"""Contained, bounded transport for model-backed CVEHunt stages.

Pi receives only the tools in ``scripts/pi_cvehunt_stage_tools.ts`` and all
provider output is consumed incrementally.  Codex remains fail-closed unless an
outer OS boundary addresses its documented residual host-read risk.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Callable, Mapping, Protocol, Sequence


class StageHarnessError(RuntimeError):
    """A stage could not be prepared, safely launched, or validated."""


class StageStatus(str, Enum):
    SUCCESS = "success"
    REFUSAL = "refusal"
    TIMEOUT = "timeout"
    PROVIDER_ERROR = "provider_error"
    ERROR = "error"


@dataclass(frozen=True)
class DeclaredInput:
    source: Path
    destination: str


@dataclass(frozen=True)
class StagePaths:
    root: Path
    input: Path
    workspace: Path
    output: Path
    log: Path
    home: Path
    config: Path


@dataclass(frozen=True)
class StageMetrics:
    elapsed_seconds: float
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    tool_calls: int = 0
    network_requests: int = 0


@dataclass(frozen=True)
class StageResult:
    status: StageStatus
    provider: str
    model: str
    stage: str
    exit_code: int | None
    response: str
    paths: StagePaths
    metrics: StageMetrics
    output_hashes: Mapping[str, str] = field(default_factory=dict)
    native_output_hashes: Mapping[str, str] = field(default_factory=dict)
    native_output_bytes: Mapping[str, int] = field(default_factory=dict)
    error: str | None = None


class CandidateExecutor(Protocol):
    def execute(self, *, operation: str, artifact: Path, timeout_seconds: float) -> Mapping[str, object]: ...


StageContract = Callable[[str, StagePaths], StageStatus]


@dataclass(frozen=True)
class StageRequest:
    stage: str
    provider: str
    model: str
    prompt: str
    inputs: Sequence[DeclaredInput] = ()
    authoring: bool = False
    research: bool = False
    timeout_seconds: float = 600.0
    thinking: str | None = "minimal"
    allow_codex_residual_read_risk: bool = False
    # Transport success says nothing about semantic refusal.  A host-owned,
    # stage-specific validator may explicitly return SUCCESS or REFUSAL.
    contract: StageContract | None = None


_SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_PROVIDER_ERROR = re.compile(
    r"(?:authentication|unauthori[sz]ed|invalid api key|rate.?limit|quota|provider|overloaded|model not found)",
    re.IGNORECASE,
)
_SECRET_NAME = re.compile(
    r"(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|APIKEY|CREDENTIAL|AUTH|COOKIE|SESSION|AWS_|AZURE_|GOOGLE_|OPENAI_|ANTHROPIC_)",
    re.IGNORECASE,
)
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")


@dataclass
class _CopyBudget:
    total: int = 0


class _EventAccumulator:
    """Parse bounded NDJSON one line at a time without retaining the stream."""

    def __init__(self, max_line: int, max_response: int, max_events: int) -> None:
        self.max_line = max_line
        self.max_response = max_response
        self.max_events = max_events
        self.pending = bytearray()
        self.answer = ""
        self.input_tokens = 0
        self.output_tokens = 0
        self.total_tokens = 0
        self.tool_calls = 0
        self.normalized: list[dict[str, object]] = []
        self.normalized_bytes = 0
        self.error: str | None = None

    def feed(self, chunk: bytes) -> None:
        if self.error:
            return
        self.pending.extend(chunk)
        while True:
            newline = self.pending.find(b"\n")
            if newline < 0:
                if len(self.pending) > self.max_line:
                    self.error = "native event exceeds configured per-event limit"
                return
            line = bytes(self.pending[:newline])
            del self.pending[: newline + 1]
            if len(line) > self.max_line:
                self.error = "native event exceeds configured per-event limit"
                return
            self._line(line)

    def finish(self) -> None:
        if self.pending and not self.error:
            if len(self.pending) > self.max_line:
                self.error = "native event exceeds configured per-event limit"
            else:
                self._line(bytes(self.pending))
        self.pending.clear()

    def _line(self, line: bytes) -> None:
        try:
            event = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return
        summary: dict[str, object] = {}
        if not isinstance(event, dict):
            return
        event_type = event.get("type")
        if isinstance(event_type, str):
            summary["type"] = event_type
            if event_type.lower() in {"tool_call", "tool_use", "function_call"}:
                self.tool_calls += 1
        candidates = [event]
        for key in ("message", "response"):
            child = event.get(key)
            if isinstance(child, dict):
                candidates.append(child)
        for value in candidates:
            usage = value.get("usage")
            if isinstance(usage, dict):
                self.input_tokens = max(self.input_tokens, _int(usage.get("input_tokens", usage.get("input", 0))))
                self.output_tokens = max(self.output_tokens, _int(usage.get("output_tokens", usage.get("output", 0))))
                self.total_tokens = max(self.total_tokens, _int(usage.get("total_tokens", usage.get("total", 0))))
                summary["usage"] = {
                    "input_tokens": self.input_tokens,
                    "output_tokens": self.output_tokens,
                    "total_tokens": self.total_tokens,
                }
            if value.get("role") == "assistant":
                content = value.get("content")
                answer: str | None = None
                if isinstance(content, str):
                    answer = content
                elif isinstance(content, list):
                    texts = [
                        part.get("text", "") for part in content
                        if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str)
                    ]
                    if texts:
                        answer = "".join(texts)
                if answer is not None:
                    if len(answer.encode("utf-8")) > self.max_response:
                        self.error = "assistant response exceeds configured limit"
                        return
                    self.answer = answer
                    summary["assistant_response_bytes"] = len(answer.encode("utf-8"))
        if summary:
            encoded_size = len(json.dumps(summary, separators=(",", ":")).encode("utf-8")) + 1
            if self.normalized_bytes + encoded_size <= self.max_events:
                self.normalized.append(summary)
                self.normalized_bytes += encoded_size


class _Capture:
    def __init__(self, tail_limit: int, events: _EventAccumulator | None = None) -> None:
        self.tail_limit = tail_limit
        self.events = events
        self.digest = hashlib.sha256()
        self.count = 0
        self.tail = bytearray()

    def feed(self, chunk: bytes) -> None:
        self.digest.update(chunk)
        self.count += len(chunk)
        self.tail.extend(chunk)
        if len(self.tail) > self.tail_limit:
            del self.tail[: len(self.tail) - self.tail_limit]
        if self.events is not None:
            self.events.feed(chunk)


class StageHarness:
    def __init__(
        self,
        run_root: Path,
        *,
        pi_binary: Path | str = "pi",
        codex_binary: Path | str = "codex",
        pi_extension: Path | None = None,
        provider_environment: Mapping[str, str] | None = None,
        pi_models_source: Path | None = None,
        research_policy_file: Path | None = None,
        terminate_grace_seconds: float = 0.5,
        max_prompt_bytes: int = 2 * 1024 * 1024,
        max_input_file_bytes: int = 16 * 1024 * 1024,
        max_input_total_bytes: int = 64 * 1024 * 1024,
        max_output_file_bytes: int = 32 * 1024 * 1024,
        max_output_total_bytes: int = 128 * 1024 * 1024,
        max_stage_disk_bytes: int = 256 * 1024 * 1024,
        max_native_output_bytes: int = 64 * 1024 * 1024,
        max_native_tail_bytes: int = 512 * 1024,
        max_native_event_bytes: int = 2 * 1024 * 1024,
        max_normalized_events_bytes: int = 2 * 1024 * 1024,
        max_response_bytes: int = 4 * 1024 * 1024,
        max_stage_write_bytes: int = 8 * 1024 * 1024,
    ) -> None:
        self.run_root = Path(run_root).resolve()
        self.pi_binary = str(pi_binary)
        self.codex_binary = str(codex_binary)
        self.pi_extension = (pi_extension or Path(__file__).parents[2] / "scripts" / "pi_cvehunt_stage_tools.ts").resolve()
        self.provider_environment = dict(provider_environment or {})
        self.pi_models_source = Path(pi_models_source).resolve() if pi_models_source else None
        self.research_policy_file = Path(research_policy_file).resolve() if research_policy_file else None
        self.terminate_grace_seconds = terminate_grace_seconds
        self.max_prompt_bytes = _positive("max_prompt_bytes", max_prompt_bytes)
        self.max_input_file_bytes = _positive("max_input_file_bytes", max_input_file_bytes)
        self.max_input_total_bytes = _positive("max_input_total_bytes", max_input_total_bytes)
        self.max_output_file_bytes = _positive("max_output_file_bytes", max_output_file_bytes)
        self.max_output_total_bytes = _positive("max_output_total_bytes", max_output_total_bytes)
        self.max_stage_disk_bytes = _positive("max_stage_disk_bytes", max_stage_disk_bytes)
        self.max_native_output_bytes = _positive("max_native_output_bytes", max_native_output_bytes)
        self.max_native_tail_bytes = _positive("max_native_tail_bytes", max_native_tail_bytes)
        self.max_native_event_bytes = _positive("max_native_event_bytes", max_native_event_bytes)
        self.max_normalized_events_bytes = _positive("max_normalized_events_bytes", max_normalized_events_bytes)
        self.max_response_bytes = _positive("max_response_bytes", max_response_bytes)
        self.max_stage_write_bytes = _positive("max_stage_write_bytes", max_stage_write_bytes)
        self._validate_provider_environment()

    def preflight(self, *, provider: str, model: str, research: bool = False) -> Mapping[str, str]:
        """Validate launch prerequisites without creating a stage or contacting a provider."""
        normalized_provider = provider.lower()
        if normalized_provider == "codex":
            raise StageHarnessError(
                "Codex is unavailable without a configured outer OS sandbox adapter; residual host-read opt-in is not accepted"
            )
        if normalized_provider != "pi":
            raise StageHarnessError(f"unsupported provider: {provider!r}")
        executable = _resolve_executable(self.pi_binary, "Pi")
        extension = _read_regular_limited(self.pi_extension, 4 * 1024 * 1024, reject_hardlink=True)
        if self.pi_models_source is None:
            raise StageHarnessError("Pi requires an explicit sanitized models.json source")
        models_raw = _read_regular_limited(self.pi_models_source, self.max_input_file_bytes, reject_hardlink=True)
        try:
            models = json.loads(models_raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise StageHarnessError(f"invalid Pi models.json: {exc}") from exc
        _validate_models_config(models, self.provider_environment)
        provider_name, separator, model_name = model.partition("/")
        configured = models.get("providers", {}).get(provider_name) if separator else None
        configured_models = configured.get("models") if isinstance(configured, dict) else None
        if not isinstance(configured_models, list) or not any(
            isinstance(item, dict) and item.get("id") == model_name for item in configured_models
        ):
            raise StageHarnessError("selected Pi provider/model is absent from sanitized models.json")
        summary = {
            "provider": "pi", "model": model,
            "harness_sha256": hashlib.sha256(extension).hexdigest(),
            "models_sha256": hashlib.sha256(models_raw).hexdigest(),
            "executable_sha256": hashlib.sha256(_read_regular_limited(executable, 64 * 1024 * 1024)).hexdigest(),
        }
        if research:
            policy = self._validated_research_policy()
            summary["research_policy_sha256"] = hashlib.sha256(
                _read_regular_limited(policy, 64 * 1024, reject_hardlink=True)
            ).hexdigest()
        return summary

    def prepare(self, stage: str, inputs: Sequence[DeclaredInput] = ()) -> StagePaths:
        if not _SAFE_COMPONENT.fullmatch(stage) or stage in {".", ".."}:
            raise StageHarnessError(f"unsafe stage name: {stage!r}")
        self.run_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        root = self.run_root / stage
        if root.exists() or root.is_symlink():
            raise StageHarnessError(f"stage directory already exists: {root}")
        root.mkdir(mode=0o700)
        paths = StagePaths(root, root / "input", root / "workspace", root / "output", root / "log", root / ".home", root / ".config")
        for path in (paths.input, paths.workspace, paths.output, paths.log, paths.home, paths.config):
            path.mkdir(mode=0o700)
        budget = _CopyBudget()
        try:
            for item in inputs:
                destination = _confined_destination(paths.input, item.destination)
                _copy_without_links(
                    Path(item.source), destination, budget,
                    self.max_input_file_bytes, self.max_input_total_bytes,
                )
            self._bootstrap_pi_config(paths)
        except BaseException:
            shutil.rmtree(root, ignore_errors=True)
            raise
        return paths

    def build_argv(self, request: StageRequest, paths: StagePaths) -> list[str]:
        provider = request.provider.lower()
        if provider == "pi":
            tools = ["stage_read", "stage_list"]
            if request.authoring:
                tools.append("stage_write")
            if request.research:
                tools.append("https_retrieve")
            argv = [
                self.pi_binary, "-p", "--no-builtin-tools", "--no-extensions", "--no-skills",
                "--no-prompt-templates", "--no-context-files", "--tools", ",".join(tools),
                "--no-session", "--mode", "json", "--offline", "--extension", str(self.pi_extension),
                "--model", request.model,
            ]
            if request.thinking:
                argv.extend(["--thinking", request.thinking])
            # Pi's @file syntax reads the prompt from the stdin descriptor.  The
            # prompt itself never appears in argv, argv.json, or process lists.
            argv.append("@/dev/stdin")
            return argv
        if provider == "codex":
            if not request.allow_codex_residual_read_risk:
                raise StageHarnessError(
                    "Codex workspace-write does not guarantee host read isolation; run inside an additional "
                    "stage-root OS sandbox and explicitly opt in"
                )
            return [
                self.codex_binary, "exec", "--ephemeral", "--ignore-user-config", "--model", request.model,
                "--sandbox", "workspace-write", "--skip-git-repo-check", "--cd", str(paths.workspace),
                "-c", "project_doc_max_bytes=0", "--output-last-message", str(paths.log / "response.md"), "-",
            ]
        raise StageHarnessError(f"unsupported provider: {request.provider!r}")

    def run(self, request: StageRequest) -> StageResult:
        prompt = request.prompt.encode("utf-8")
        if len(prompt) > self.max_prompt_bytes:
            raise StageHarnessError("prompt exceeds configured input limit")
        if request.research:
            self._validated_research_policy()
        paths = self.prepare(request.stage, request.inputs)
        secrets = tuple(value.encode("utf-8") for value in self.provider_environment.values() if value)
        (paths.log / "prompt.md").write_bytes(_redact(prompt, secrets))
        argv = self.build_argv(request, paths)
        (paths.log / "argv.json").write_text(json.dumps(argv, indent=2) + "\n", encoding="utf-8")
        env = self._environment(request, paths)
        self._assert_secret_absence(paths.root, secrets)

        started = time.monotonic()
        process: subprocess.Popen[bytes] | None = None
        timed_out = False
        launch_error: str | None = None
        limit_error: str | None = None
        exit_code: int | None = None
        events = _EventAccumulator(self.max_native_event_bytes, self.max_response_bytes, self.max_normalized_events_bytes)
        stdout_capture = _Capture(self.max_native_tail_bytes, events)
        stderr_capture = _Capture(self.max_native_tail_bytes)
        try:
            process = subprocess.Popen(
                argv, cwd=paths.workspace, env=env, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
            )
            timed_out, limit_error = self._stream_process(process, prompt, paths, stdout_capture, stderr_capture, request.timeout_seconds)
            exit_code = process.returncode
        except OSError as exc:
            launch_error = f"{type(exc).__name__}: {exc}"
        events.finish()
        if events.error and limit_error is None:
            limit_error = events.error
        elapsed = time.monotonic() - started

        stdout_tail = _redact(bytes(stdout_capture.tail), secrets)
        stderr_tail = _redact(bytes(stderr_capture.tail), secrets)
        normalized = b"".join(
            json.dumps(item, separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n"
            for item in events.normalized
        )
        (paths.log / "events.ndjson").write_bytes(_redact(normalized or stdout_tail, secrets))
        (paths.log / "stderr.log").write_bytes(stderr_tail)
        response, response_error = self._response(request.provider, paths, events.answer, stdout_tail)
        if response_error and limit_error is None:
            limit_error = response_error
        response = _redact(response.encode("utf-8"), secrets).decode("utf-8", "replace")
        (paths.log / "response.md").write_text(response, encoding="utf-8")

        try:
            hashes = _hash_output_tree(paths.output, self.max_output_file_bytes, self.max_output_total_bytes)
            if _tree_size(paths.root, self.max_stage_disk_bytes) > self.max_stage_disk_bytes:
                raise StageHarnessError("stage disk usage exceeds configured limit")
        except StageHarnessError as exc:
            hashes = {}
            if limit_error is None:
                limit_error = str(exc)

        contamination = _remove_secret_contamination(paths, secrets)
        if contamination and limit_error is None:
            limit_error = f"provider credential appeared in stage file(s): {', '.join(contamination)}"
        if contamination:
            hashes = {}
        self._assert_secret_absence(paths.root, secrets)

        metrics = _collect_metrics(paths, events, elapsed)
        status, error = _classify(timed_out, exit_code, stderr_tail.decode("utf-8", "replace"), launch_error, limit_error)
        if status is StageStatus.SUCCESS and request.contract is not None:
            try:
                contract_status = request.contract(response, paths)
                if contract_status not in {StageStatus.SUCCESS, StageStatus.REFUSAL}:
                    raise ValueError("contract must return StageStatus.SUCCESS or StageStatus.REFUSAL")
                status = contract_status
            except Exception as exc:
                status, error = StageStatus.ERROR, f"stage result contract rejected response: {type(exc).__name__}: {exc}"

        result = StageResult(
            status, request.provider.lower(), request.model, request.stage, exit_code, response, paths, metrics,
            hashes,
            {"stdout": stdout_capture.digest.hexdigest(), "stderr": stderr_capture.digest.hexdigest()},
            {"stdout": stdout_capture.count, "stderr": stderr_capture.count},
            error,
        )
        public = asdict(result)
        public["status"] = result.status.value
        public["paths"] = {
            key: str(value.relative_to(paths.root)) if value != paths.root else "."
            for key, value in asdict(paths).items()
        }
        (paths.log / "result.json").write_text(json.dumps(public, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self._assert_secret_absence(paths.root, secrets)
        return result

    def _stream_process(
        self,
        process: subprocess.Popen[bytes],
        prompt: bytes,
        paths: StagePaths,
        stdout_capture: _Capture,
        stderr_capture: _Capture,
        timeout: float,
    ) -> tuple[bool, str | None]:
        assert process.stdin is not None and process.stdout is not None and process.stderr is not None
        selector = selectors.DefaultSelector()
        for stream in (process.stdin, process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ, stdout_capture)
        selector.register(process.stderr, selectors.EVENT_READ, stderr_capture)
        selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
        sent = 0
        deadline = time.monotonic() + timeout
        timed_out = False
        limit_error: str | None = None
        last_disk_check = 0.0
        stopped = False

        while selector.get_map():
            now = time.monotonic()
            if not stopped and now >= deadline:
                timed_out = True
                stopped = True
                _terminate_process_group(process, self.terminate_grace_seconds)
            if not stopped and now - last_disk_check >= 0.05:
                last_disk_check = now
                try:
                    _validate_output_tree_size(
                        paths.output, self.max_output_file_bytes, self.max_output_total_bytes
                    )
                    if _tree_size(paths.root, self.max_stage_disk_bytes) > self.max_stage_disk_bytes:
                        limit_error = "stage disk usage exceeds configured limit"
                except StageHarnessError as exc:
                    limit_error = str(exc)
                if limit_error:
                    stopped = True
                    _terminate_process_group(process, self.terminate_grace_seconds)
            for key, _mask in selector.select(0.05):
                if key.data == "stdin":
                    try:
                        if sent < len(prompt):
                            sent += os.write(key.fd, prompt[sent : sent + 65536])
                        if sent >= len(prompt):
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                    except BrokenPipeError:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                    continue
                capture: _Capture = key.data
                try:
                    chunk = os.read(key.fd, 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                capture.feed(chunk)
                if not stopped and stdout_capture.count + stderr_capture.count > self.max_native_output_bytes:
                    limit_error = "native provider output exceeds configured limit"
                if not stopped and stdout_capture.events and stdout_capture.events.error:
                    limit_error = stdout_capture.events.error
                if limit_error and not stopped:
                    stopped = True
                    _terminate_process_group(process, self.terminate_grace_seconds)
            if process.poll() is not None and process.stdin in [key.fileobj for key in selector.get_map().values()]:
                try:
                    selector.unregister(process.stdin)
                    process.stdin.close()
                except (KeyError, OSError):
                    pass
        selector.close()
        process.wait()
        return timed_out, limit_error

    def _environment(self, request: StageRequest, paths: StagePaths) -> dict[str, str]:
        env: dict[str, str] = {
            "PATH": os.defpath, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            "HOME": str(paths.home), "XDG_CONFIG_HOME": str(paths.config),
            "CODEX_HOME": str(paths.config / "codex"),
            "PI_CODING_AGENT_DIR": str(paths.config / "pi"),
            "PI_CODING_AGENT_SESSION_DIR": str(paths.config / "pi-sessions"),
            "PI_OFFLINE": "1", "PI_TELEMETRY": "0",
            "CVEHUNT_STAGE_INPUT": str(paths.input), "CVEHUNT_STAGE_WORKSPACE": str(paths.workspace),
            "CVEHUNT_STAGE_OUTPUT": str(paths.output), "CVEHUNT_STAGE_LOG": str(paths.log),
            "CVEHUNT_STAGE_AUTHORING": "1" if request.authoring else "0",
            "CVEHUNT_STAGE_RESEARCH": "1" if request.research else "0",
            "CVEHUNT_STAGE_MAX_WRITE_BYTES": str(self.max_stage_write_bytes),
        }
        (paths.config / "codex").mkdir(mode=0o700, exist_ok=True)
        if request.research:
            env["CVEHUNT_STAGE_POLICY"] = str(self._validated_research_policy())
        if request.provider.lower() == "codex" and self.provider_environment:
            raise StageHarnessError(
                "Codex model tools can inspect process environment; use an outer credential broker, not provider_environment"
            )
        env.update(self.provider_environment)
        return env

    def _validate_provider_environment(self) -> None:
        for key, value in self.provider_environment.items():
            if (
                not _ENV_NAME.fullmatch(key) or not value or "\0" in value
                or len(value.encode("utf-8")) > 64 * 1024 or not _SECRET_NAME.search(key)
            ):
                raise StageHarnessError("invalid provider environment")

    def _bootstrap_pi_config(self, paths: StagePaths) -> None:
        pi_dir = paths.config / "pi"
        pi_dir.mkdir(mode=0o700)
        if self.pi_models_source is None:
            return
        data = _read_regular_limited(self.pi_models_source, self.max_input_file_bytes, reject_hardlink=True)
        try:
            model_config = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise StageHarnessError(f"invalid Pi models.json: {exc}") from exc
        _validate_models_config(model_config, self.provider_environment)
        encoded = (json.dumps(model_config, indent=2, sort_keys=True) + "\n").encode("utf-8")
        if len(encoded) > self.max_input_file_bytes:
            raise StageHarnessError("sanitized Pi models.json exceeds configured limit")
        destination = pi_dir / "models.json"
        destination.write_bytes(encoded)
        destination.chmod(0o600)

    def _validated_research_policy(self) -> Path:
        if self.research_policy_file is None:
            raise StageHarnessError("research requires a root-owned stage policy file")
        try:
            info = self.research_policy_file.lstat()
        except OSError as exc:
            raise StageHarnessError(f"cannot inspect research policy: {exc}") from exc
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o022:
            raise StageHarnessError("research policy must be a root-owned, non-writable, single-link regular file")
        try:
            policy = json.loads(_read_regular_limited(self.research_policy_file, 64 * 1024, reject_hardlink=True))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise StageHarnessError(f"invalid research policy JSON: {exc}") from exc
        hosts = policy.get("research_hosts") if isinstance(policy, dict) else None
        if not isinstance(hosts, list) or not hosts or any(not _valid_hostname(item) for item in hosts):
            raise StageHarnessError("research policy requires a non-empty research_hosts hostname list")
        return self.research_policy_file

    def _response(self, provider: str, paths: StagePaths, pi_answer: str, stdout_tail: bytes) -> tuple[str, str | None]:
        if provider.lower() == "codex":
            response_file = paths.log / "response.md"
            if response_file.is_file():
                try:
                    return _read_regular_limited(response_file, self.max_response_bytes).decode("utf-8", "replace"), None
                except StageHarnessError as exc:
                    return "", str(exc)
        if provider.lower() == "pi" and pi_answer:
            return pi_answer, None
        return stdout_tail.decode("utf-8", "replace"), None

    @staticmethod
    def _assert_secret_absence(root: Path, secrets: Sequence[bytes]) -> None:
        contaminated = _find_secret_contamination(root, secrets)
        if contaminated:
            raise StageHarnessError(f"provider credential persisted in stage: {', '.join(contaminated)}")


def _positive(name: str, value: int) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _resolve_executable(value: str, label: str) -> Path:
    candidate = Path(value)
    discovered = str(candidate) if candidate.is_absolute() or "/" in value else shutil.which(value)
    if not discovered:
        raise StageHarnessError(f"{label} executable is not installed")
    try:
        resolved = Path(discovered).resolve(strict=True)
        info = resolved.lstat()
    except OSError as exc:
        raise StageHarnessError(f"cannot inspect {label} executable: {exc}") from exc
    if not stat.S_ISREG(info.st_mode) or not os.access(resolved, os.X_OK):
        raise StageHarnessError(f"{label} executable is not an executable regular file")
    return resolved


def _valid_hostname(value: object) -> bool:
    if not isinstance(value, str) or value != value.lower() or value.endswith(".") or len(value) > 253:
        return False
    labels = value.split(".")
    return len(labels) >= 2 and all(
        0 < len(label) <= 63 and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) is not None
        for label in labels
    )


def _validate_models_config(value: object, provider_environment: Mapping[str, str]) -> None:
    if not isinstance(value, dict) or not isinstance(value.get("providers"), dict):
        raise StageHarnessError("Pi models.json must contain a providers object")
    secrets = tuple(secret for secret in provider_environment.values() if secret)

    def visit(item: object, parent: str = "") -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise StageHarnessError("Pi models.json contains a non-string key")
                if key.lower() in {"auth", "authorization", "password", "token", "secret"}:
                    raise StageHarnessError("Pi models.json contains a forbidden credential field")
                if key == "apiKey":
                    if not isinstance(child, str) or child not in provider_environment or not _ENV_NAME.fullmatch(child):
                        raise StageHarnessError("Pi models.json apiKey must reference a supplied credential environment name")
                if parent == "headers" and (
                    not isinstance(child, str) or child not in provider_environment or not _ENV_NAME.fullmatch(child)
                ):
                    raise StageHarnessError("Pi models.json headers must reference supplied credential environment names")
                visit(child, key)
        elif isinstance(item, list):
            for child in item:
                visit(child, parent)
        elif isinstance(item, str):
            if item.startswith("!") or any(secret in item for secret in secrets):
                raise StageHarnessError("Pi models.json contains a command or literal provider credential")
        elif item is not None and not isinstance(item, (bool, int, float)):
            raise StageHarnessError("Pi models.json contains an unsupported value")

    visit(value)


def _confined_destination(root: Path, destination: str) -> Path:
    pure = PurePosixPath(destination)
    if not destination or pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise StageHarnessError(f"unsafe input destination: {destination!r}")
    result = root.joinpath(*pure.parts)
    if not result.is_relative_to(root):
        raise StageHarnessError(f"input destination escapes stage: {destination!r}")
    return result


def _copy_without_links(source: Path, destination: Path, budget: _CopyBudget, per_file: int, total: int) -> None:
    try:
        info = source.lstat()
    except OSError as exc:
        raise StageHarnessError(f"cannot inspect declared input {source}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise StageHarnessError(f"symlink input rejected: {source}")
    if stat.S_ISREG(info.st_mode):
        if info.st_nlink > 1:
            raise StageHarnessError(f"hardlink input rejected: {source}")
        if info.st_size > per_file or budget.total + info.st_size > total:
            raise StageHarnessError(f"declared input exceeds configured size limit: {source}")
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if destination.exists() or destination.is_symlink():
            raise StageHarnessError(f"duplicate input destination: {destination}")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(source, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or opened.st_nlink > 1 or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise StageHarnessError(f"declared input changed or is not a single-link regular file: {source}")
            with os.fdopen(descriptor, "rb", closefd=False) as src, destination.open("xb") as dst:
                copied = 0
                while True:
                    block = src.read(min(1024 * 1024, per_file - copied + 1))
                    if not block:
                        break
                    copied += len(block)
                    if copied > per_file or budget.total + copied > total:
                        raise StageHarnessError(f"declared input exceeds configured size limit: {source}")
                    dst.write(block)
            budget.total += copied
            os.chmod(destination, info.st_mode & 0o777 & ~0o222)
        finally:
            os.close(descriptor)
        return
    if stat.S_ISDIR(info.st_mode):
        if destination.exists() or destination.is_symlink():
            raise StageHarnessError(f"duplicate input destination: {destination}")
        destination.mkdir(parents=True, mode=0o700)
        try:
            children = tuple(os.scandir(source))
        except OSError as exc:
            raise StageHarnessError(f"cannot inspect declared input directory {source}: {exc}") from exc
        for child in children:
            _copy_without_links(Path(child.path), destination / child.name, budget, per_file, total)
        return
    raise StageHarnessError(f"non-regular declared input rejected: {source}")


def _terminate_process_group(process: subprocess.Popen[bytes], grace: float) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        process.wait()
        return
    try:
        process.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def _redact(value: bytes, secrets: Sequence[bytes]) -> bytes:
    for secret in secrets:
        if secret:
            value = value.replace(secret, b"[REDACTED]")
    return value


def _int(value: object) -> int:
    return value if type(value) is int and value >= 0 else 0


def _collect_metrics(paths: StagePaths, events: _EventAccumulator, elapsed: float) -> StageMetrics:
    total = events.total_tokens or events.input_tokens + events.output_tokens
    network_requests = 0
    request_ids: set[str] = set()
    network_log = paths.log / "network.ndjson"
    if network_log.is_file():
        try:
            with network_log.open("rb") as stream:
                while True:
                    line = stream.readline(64 * 1024 + 1)
                    if not line:
                        break
                    if len(line) > 64 * 1024:
                        raise StageHarnessError("network audit entry exceeds configured limit")
                    if not line.strip():
                        continue
                    try:
                        record = json.loads(line)
                    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                        raise StageHarnessError("invalid network audit entry") from exc
                    request_id = record.get("request_id") if isinstance(record, dict) else None
                    outcome = record.get("outcome") if isinstance(record, dict) else None
                    if not isinstance(request_id, str) or not request_id or len(request_id) > 128:
                        raise StageHarnessError("invalid network audit request ID")
                    if outcome == "started":
                        if request_id in request_ids:
                            raise StageHarnessError("duplicate network audit request ID")
                        request_ids.add(request_id)
        except OSError as exc:
            raise StageHarnessError(f"cannot read network audit: {exc}") from exc
        network_requests = len(request_ids)
    return StageMetrics(elapsed, events.input_tokens, events.output_tokens, total, events.tool_calls, network_requests)


def _validate_output_tree_size(root: Path, per_file: int, total_limit: int) -> int:
    """Validate output entry types and limits without opening file contents."""
    total = 0
    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            entries = os.scandir(directory)
        except OSError as exc:
            raise StageHarnessError(f"cannot inspect stage output: {exc}") from exc
        with entries:
            for entry in entries:
                path = Path(entry.path)
                try:
                    info = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    raise StageHarnessError(f"cannot inspect stage output entry {path}: {exc}") from exc
                if stat.S_ISLNK(info.st_mode):
                    raise StageHarnessError(f"symlink appeared in stage output: {path}")
                if stat.S_ISDIR(info.st_mode):
                    stack.append(path)
                    continue
                if not stat.S_ISREG(info.st_mode):
                    raise StageHarnessError(f"non-regular entry appeared in stage output: {path}")
                if info.st_nlink > 1:
                    raise StageHarnessError(f"hardlink appeared in stage output: {path}")
                if info.st_size > per_file:
                    raise StageHarnessError(f"stage output file exceeds configured limit: {path}")
                total += info.st_size
                if total > total_limit:
                    raise StageHarnessError("stage output exceeds configured total limit")
    return total


def _hash_output_tree(root: Path, per_file: int, total_limit: int) -> dict[str, str]:
    hashes: dict[str, str] = {}
    total = 0

    def walk(directory: Path) -> None:
        nonlocal total
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            raise StageHarnessError(f"cannot inspect stage output: {exc}") from exc
        for entry in entries:
            path = Path(entry.path)
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise StageHarnessError(f"cannot inspect stage output entry {path}: {exc}") from exc
            if stat.S_ISLNK(info.st_mode):
                raise StageHarnessError(f"symlink appeared in stage output: {path}")
            if stat.S_ISDIR(info.st_mode):
                walk(path)
                continue
            if not stat.S_ISREG(info.st_mode):
                raise StageHarnessError(f"non-regular entry appeared in stage output: {path}")
            if info.st_nlink > 1:
                raise StageHarnessError(f"hardlink appeared in stage output: {path}")
            if info.st_size > per_file:
                raise StageHarnessError(f"stage output file exceeds configured limit: {path}")
            total += info.st_size
            if total > total_limit:
                raise StageHarnessError("stage output exceeds configured total limit")
            relative = path.relative_to(root).as_posix()
            digest = hashlib.sha256()
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags)
            try:
                opened = os.fstat(descriptor)
                if opened.st_nlink > 1 or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                    raise StageHarnessError(f"stage output changed during validation: {path}")
                with os.fdopen(descriptor, "rb", closefd=False) as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(block)
            finally:
                os.close(descriptor)
            hashes[relative] = digest.hexdigest()

    walk(root)
    return hashes


def _tree_size(root: Path, stop_after: int) -> int:
    total = 0
    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            entries = os.scandir(directory)
        except OSError as exc:
            raise StageHarnessError(f"cannot inspect stage disk usage: {exc}") from exc
        with entries:
            for entry in entries:
                try:
                    info = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    raise StageHarnessError(f"cannot inspect stage entry {entry.path}: {exc}") from exc
                if stat.S_ISLNK(info.st_mode):
                    raise StageHarnessError(f"symlink appeared in stage directory: {entry.path}")
                if stat.S_ISDIR(info.st_mode):
                    stack.append(Path(entry.path))
                elif stat.S_ISREG(info.st_mode):
                    total += info.st_size
                    if total > stop_after:
                        return total
                else:
                    raise StageHarnessError(f"special file appeared in stage directory: {entry.path}")
    return total


def _read_regular_limited(path: Path, limit: int, reject_hardlink: bool = False) -> bytes:
    try:
        info = path.lstat()
    except OSError as exc:
        raise StageHarnessError(f"cannot inspect file {path}: {exc}") from exc
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or (reject_hardlink and info.st_nlink > 1):
        raise StageHarnessError(f"not a safe regular file: {path}")
    if info.st_size > limit:
        raise StageHarnessError(f"file exceeds configured limit: {path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise StageHarnessError(f"file changed during validation: {path}")
        data = bytearray()
        while True:
            block = os.read(descriptor, min(1024 * 1024, limit - len(data) + 1))
            if not block:
                break
            data.extend(block)
            if len(data) > limit:
                raise StageHarnessError(f"file exceeds configured limit: {path}")
        return bytes(data)
    finally:
        os.close(descriptor)


def _find_secret_contamination(root: Path, secrets: Sequence[bytes]) -> list[str]:
    if not secrets:
        return []
    found: list[str] = []
    for directory, names, files in os.walk(root, followlinks=False):
        names[:] = [name for name in names if not (Path(directory) / name).is_symlink()]
        for name in files:
            path = Path(directory) / name
            try:
                info = path.lstat()
            except OSError:
                continue
            if not stat.S_ISREG(info.st_mode):
                continue
            overlap = max((len(secret) for secret in secrets), default=1) - 1
            prior = b""
            try:
                with path.open("rb") as stream:
                    while block := stream.read(1024 * 1024):
                        sample = prior + block
                        if any(secret in sample for secret in secrets):
                            found.append(path.relative_to(root).as_posix())
                            break
                        prior = sample[-overlap:] if overlap else b""
            except OSError:
                continue
    return found


def _remove_secret_contamination(paths: StagePaths, secrets: Sequence[bytes]) -> list[str]:
    contaminated = _find_secret_contamination(paths.root, secrets)
    for relative in contaminated:
        path = paths.root / relative
        if path.is_relative_to(paths.log):
            try:
                data = _read_regular_limited(path, 16 * 1024 * 1024)
                path.write_bytes(_redact(data, secrets))
            except (OSError, StageHarnessError):
                path.unlink(missing_ok=True)
        else:
            path.unlink(missing_ok=True)
    return contaminated


def _classify(
    timed_out: bool,
    exit_code: int | None,
    stderr: str,
    launch_error: str | None,
    limit_error: str | None,
) -> tuple[StageStatus, str | None]:
    if timed_out:
        return StageStatus.TIMEOUT, "stage exceeded its timeout; process group terminated"
    if limit_error:
        return StageStatus.ERROR, limit_error
    if launch_error:
        return StageStatus.ERROR, launch_error
    if exit_code != 0:
        message = stderr.strip() or f"provider exited with status {exit_code}"
        return (StageStatus.PROVIDER_ERROR if _PROVIDER_ERROR.search(message) else StageStatus.ERROR), message
    return StageStatus.SUCCESS, None


__all__ = [
    "CandidateExecutor", "DeclaredInput", "StageContract", "StageHarness", "StageHarnessError",
    "StageMetrics", "StagePaths", "StageRequest", "StageResult", "StageStatus",
]
