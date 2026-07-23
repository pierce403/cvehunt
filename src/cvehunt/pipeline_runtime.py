"""Trusted, fail-closed runtime adapters for the agent pipeline.

This module is deliberately not a general command execution API.  Model output is
accepted only as two small declarative schemas and is translated to fixed Docker
argv by :class:`ContainerExecutor`.  Hidden scoring is similarly limited to a
small rule language over the pipeline's safe public stage records.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import secrets
import signal
import stat
import subprocess
import tempfile
import threading
import time

from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

from .agent_pipeline import (
    TrustedArtifact,
    TrustedCallbackContext,
    TrustedInput,
    TrustedStageOutput,
)
from .stage_contracts import StageContractError, canonical_json, sha256_bytes

CONTAINER_PLAN_SCHEMA = "cvehunt.container-plan/v1"
CANDIDATE_PLAN_SCHEMA = "cvehunt.candidate-plan/v1"
ADVERSARIAL_PLAN_SCHEMA = "cvehunt.adversarial-plan/v1"
FIX_PLAN_SCHEMA = "cvehunt.fix-plan/v1"
HIDDEN_SCORE_SCHEMA = "cvehunt.hidden-score/v1"
CAPABILITY_RECEIPT_SCHEMA = "cvehunt.capability-receipt/v1"
_DOCKER_DIGEST = re.compile(r"^[a-z0-9][a-z0-9._/-]*(?::[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}$")
_SAFE_NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$")
_ACTIVE_RUN_DEADLINE: ContextVar[float | None] = ContextVar(
    "cvehunt_active_run_deadline", default=None
)
_ACTIVE_CLEANUP_RESERVE: ContextVar[float] = ContextVar(
    "cvehunt_active_cleanup_reserve", default=0.0
)
_ENV_SAFE = re.compile(r"^[\x20-\x7e]{0,1024}$")
_MAX_PLAN_BYTES = 64 * 1024
_MAX_RESULT_BYTES = 16 * 1024


class RuntimeValidationError(StageContractError):
    """A declarative runtime input violated the trusted boundary."""


class CommandExecutionError(RuntimeError):
    """A fixed trusted command failed or timed out."""


class RuntimeExecutionError(RuntimeError):
    """Execution failed; cleanup details remain available without masking it."""

    def __init__(self, primary: BaseException, cleanup: Mapping[str, object]) -> None:
        super().__init__(f"container execution failed: {type(primary).__name__}; cleanup_ok={cleanup.get('ok')}")
        self.primary = primary
        self.cleanup = dict(cleanup)


@contextmanager
def _runtime_deadline(remaining_seconds: float):
    if (
        not isinstance(remaining_seconds, (int, float))
        or isinstance(remaining_seconds, bool)
        or not math.isfinite(float(remaining_seconds))
        or not 0 < float(remaining_seconds)
    ):
        raise RuntimeValidationError("run deadline is exhausted or invalid")
    seconds = float(remaining_seconds)
    token = _ACTIVE_RUN_DEADLINE.set(time.monotonic() + seconds)
    reserve_token = _ACTIVE_CLEANUP_RESERVE.set(min(30.0, seconds * 0.2))
    try:
        yield
    finally:
        _ACTIVE_CLEANUP_RESERVE.reset(reserve_token)
        _ACTIVE_RUN_DEADLINE.reset(token)


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool = False
    stdout_truncated: bool = False
    stderr_truncated: bool = False


class CommandRunner(Protocol):
    """Narrow injectable runner. Implementations must never invoke a shell."""

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
        input_data: bytes | None = None,
    ) -> CommandResult: ...


@dataclass(frozen=True)
class CapabilityOracleArmRequest:
    """Pre-execution challenge used to arm independent host instrumentation."""

    cve_id: str
    nonce: bytes
    variant: str
    target_digest: str
    candidate_commitment: str


@dataclass(frozen=True)
class CapabilityOracleRequest:
    """Private host observation request; never persisted or shown to the model."""

    cve_id: str
    nonce: bytes
    variant: str
    target_digest: str
    candidate_commitment: str
    execution_result_commitment: str
    candidate_stdout: bytes
    candidate_stderr: bytes
    host_observation: bytes


@dataclass(frozen=True)
class CapabilityOracleObservation:
    """CVE-specific host decision plus bytes committing the observed interaction."""

    capability_proved: bool
    observed_interaction: bytes


class CapabilityOracle(Protocol):
    """A pinned, CVE-specific host observer independent of candidate self-report."""

    cve_id: str
    oracle_sha256: str

    def arm(self, request: CapabilityOracleArmRequest) -> None: ...

    def observe(self, request: CapabilityOracleRequest) -> CapabilityOracleObservation: ...


class TargetIdentityValidator(Protocol):
    """CVE-specific validator for model-acquired realistic target bytes."""

    cve_id: str

    def validate(
        self, *, cve_id: str, harness_payload: Mapping[str, object],
        artifacts: Mapping[str, bytes],
    ) -> Mapping[str, str]: ...


class SubprocessCommandRunner:
    """Run argv directly in a new process group with bounded captured output."""

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
        input_data: bytes | None = None,
    ) -> CommandResult:
        args = _trusted_argv(argv)
        if not isinstance(timeout_seconds, (int, float)) or isinstance(timeout_seconds, bool) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if not isinstance(max_output_bytes, int) or isinstance(max_output_bytes, bool) or max_output_bytes <= 0:
            raise ValueError("max_output_bytes must be positive")
        if input_data is not None and len(input_data) > max_output_bytes:
            raise ValueError("input_data exceeds runner limit")
        process = subprocess.Popen(
            args,
            stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=True,
            close_fds=True,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        )
        captured = [bytearray(), bytearray()]
        truncated = [False, False]

        def drain(stream: Any, index: int) -> None:
            while block := stream.read(64 * 1024):
                remaining = max_output_bytes - len(captured[index])
                if remaining > 0:
                    captured[index].extend(block[:remaining])
                if len(block) > remaining:
                    truncated[index] = True

        assert process.stdout is not None and process.stderr is not None
        readers = [
            threading.Thread(target=drain, args=(process.stdout, 0), daemon=True),
            threading.Thread(target=drain, args=(process.stderr, 1), daemon=True),
        ]
        for reader in readers:
            reader.start()
        writer: threading.Thread | None = None
        if input_data is not None:
            stdin = process.stdin
            assert stdin is not None

            def write_input() -> None:
                try:
                    stdin.write(input_data)
                    stdin.close()
                except (BrokenPipeError, ValueError):
                    pass

            writer = threading.Thread(target=write_input, daemon=True)
            writer.start()
        timed_out = False
        try:
            process.wait(timeout=float(timeout_seconds))
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        for reader in readers:
            reader.join()
        if writer is not None:
            writer.join()
        return CommandResult(
            tuple(args), process.returncode, bytes(captured[0]), bytes(captured[1]),
            timed_out, truncated[0], truncated[1],
        )


@dataclass(frozen=True)
class _File:
    artifact_id: str
    source: Path
    data: bytes


@dataclass(frozen=True)
class _Variant:
    name: str
    dockerfile_artifact_id: str


@dataclass(frozen=True)
class _ContainerPlan:
    files: tuple[tuple[str, str], ...]
    variants: tuple[_Variant, ...]
    container_port: int
    readiness_path: str


@dataclass(frozen=True)
class _CandidatePlan:
    artifact_id: str
    runtime: str
    timeout_seconds: float
    args: tuple[str, ...]
    data: object


@dataclass(frozen=True)
class _AdversarialRound:
    id: str
    candidate: _CandidatePlan


@dataclass(frozen=True)
class _FixPlan:
    replacements: tuple[tuple[str, str], ...]


class ContainerExecutor:
    """Translate validated plans into fixed, rootless Docker invocations.

    ``allowed_base_images`` and ``python_runner_image`` must be exact digest-pinned
    image references.  Non-rootless operation requires an explicit opt-out and is
    intended only for administrator-controlled test environments.
    """

    def __init__(
        self,
        *,
        allowed_base_images: Sequence[str],
        python_runner_image: str,
        runner: CommandRunner | None = None,
        docker_binary: str = "docker",
        require_rootless: bool = True,
        administrator_allow_non_rootless: bool = False,
        max_artifact_bytes: int = 4 * 1024 * 1024,
        max_total_context_bytes: int = 16 * 1024 * 1024,
        max_output_bytes: int = _MAX_RESULT_BYTES,
        command_timeout_seconds: float = 120.0,
        capability_oracle: CapabilityOracle | None = None,
        target_identity_validator: TargetIdentityValidator | None = None,
    ) -> None:
        self.runner = runner or SubprocessCommandRunner()
        self.docker_binary = _binary_name(docker_binary)
        self.allowed_base_images = frozenset(_pinned_image(item, "allowed_base_images") for item in allowed_base_images)
        if not self.allowed_base_images:
            raise ValueError("at least one digest-pinned base image is required")
        self.python_runner_image = _pinned_image(python_runner_image, "python_runner_image")
        self.require_rootless = bool(require_rootless)
        self.administrator_allow_non_rootless = bool(administrator_allow_non_rootless)
        if not self.require_rootless and not self.administrator_allow_non_rootless:
            raise ValueError("disabling rootless requires explicit administrator_allow_non_rootless")
        self.max_artifact_bytes = _positive_int(max_artifact_bytes, "max_artifact_bytes")
        self.max_total_context_bytes = _positive_int(max_total_context_bytes, "max_total_context_bytes")
        self.max_output_bytes = _positive_int(max_output_bytes, "max_output_bytes")
        self.command_timeout_seconds = _positive_number(command_timeout_seconds, "command_timeout_seconds")
        self.capability_oracle = capability_oracle
        self.target_identity_validator = target_identity_validator

    def provision_and_execute(
        self, *, context: TrustedCallbackContext, output_dir: Path
    ) -> TrustedStageOutput:
        with _runtime_deadline(context.remaining_run_seconds):
            return self._provision_and_execute(context=context, output_dir=output_dir)

    def _provision_and_execute(
        self, *, context: TrustedCallbackContext, output_dir: Path
    ) -> TrustedStageOutput:
        output_dir = Path(output_dir)
        if output_dir.is_symlink() or not output_dir.is_dir():
            raise RuntimeValidationError("output_dir must be an existing regular directory")
        harness_record = _record(context.public_stage_records, "harness_builder")
        exploiter_record = _record(context.public_stage_records, "exploiter")
        harness_payload = _payload(harness_record, "harness_builder")
        plan = _parse_container_plan(harness_payload)
        candidate = _parse_candidate_plan(_payload(exploiter_record, "exploiter"))
        inputs = self._validate_inputs(context.inputs)
        oracle = _validated_capability_oracle(self.capability_oracle, context.cve_id)
        validated_target_digests = _validated_target_identities(
            self.target_identity_validator, context.cve_id, harness_payload,
            {key: value.data for key, value in inputs.items()}, plan,
        )
        referenced = {artifact_id for artifact_id, _ in plan.files} | {
            item.dockerfile_artifact_id for item in plan.variants
        } | {candidate.artifact_id}
        unknown = referenced - set(inputs)
        if unknown:
            raise RuntimeValidationError("plan references unknown artifact ID")
        candidate_commitment = _candidate_commitment(candidate, inputs[candidate.artifact_id].data)
        destinations = {artifact_id: destination for artifact_id, destination in plan.files}
        if candidate.artifact_id in destinations:
            raise RuntimeValidationError("candidate artifact must not enter the target build context")
        dockerfile_ids = [item.dockerfile_artifact_id for item in plan.variants]
        if len(set(dockerfile_ids)) != len(dockerfile_ids):
            raise RuntimeValidationError("each variant requires a distinct Dockerfile artifact")
        for variant in plan.variants:
            if variant.dockerfile_artifact_id not in destinations:
                raise RuntimeValidationError("Dockerfile artifact must be declared in build-context files")
            _validate_dockerfile(inputs[variant.dockerfile_artifact_id].data, self.allowed_base_images)

        execution_id = _execution_id(context.run_id, context.predecessor_handoff_sha256)
        network = _opaque_runtime_name()
        image_names = {v.name: _opaque_runtime_name() for v in plan.variants}
        container_names = {v.name: _opaque_runtime_name() for v in plan.variants}
        created_images: list[str] = []
        created_containers: list[str] = []
        network_created = False
        audit: list[dict[str, object]] = []
        primary: BaseException | None = None
        payload: dict[str, object] | None = None
        cleanup: dict[str, object] = {"ok": True, "failures": []}

        try:
            self._check_daemon(audit)
            with tempfile.TemporaryDirectory(prefix="cvehunt-build-") as temporary, tempfile.TemporaryDirectory(prefix="cvehunt-candidate-") as candidate_temporary:
                build_root = Path(temporary)
                candidate_root = Path(candidate_temporary)
                self._materialize_context(build_root, plan, inputs)
                candidate_path = candidate_root / "candidate.py"
                candidate_path.write_bytes(inputs[candidate.artifact_id].data)
                candidate_path.chmod(0o400)
                if sha256_bytes(_safe_read(candidate_path, self.max_artifact_bytes)) != hashlib.sha256(inputs[candidate.artifact_id].data).hexdigest():
                    raise RuntimeValidationError("materialized candidate hash mismatch")
                network_created = True
                self._command((self.docker_binary, "network", "create", "--internal", network), audit)
                builds: list[dict[str, object]] = []
                for variant in plan.variants:
                    dockerfile = destinations[variant.dockerfile_artifact_id]
                    argv = (
                        self.docker_binary, "build", "--network=none", "--pull=false",
                        "--tag", image_names[variant.name], "--file", str(build_root / dockerfile),
                        str(build_root),
                    )
                    created_images.append(image_names[variant.name])
                    self._command(argv, audit)
                    builds.append({"variant": variant.name, "status": "built"})

                targets: list[dict[str, object]] = []
                runs: list[dict[str, object]] = []
                for variant in plan.variants:
                    name = container_names[variant.name]
                    created_containers.append(name)
                    self._command(self._target_create_argv(name, image_names[variant.name]), audit)
                    self._command(
                        (self.docker_binary, "network", "connect", "--alias", "target", network, name), audit,
                    )
                    self._command((self.docker_binary, "start", name), audit)
                    target_url = f"http://target:{plan.container_port}{plan.readiness_path}"
                    self._readiness_probe(
                        execution_id, variant.name, network, target_url,
                        candidate.timeout_seconds, created_containers, audit,
                    )
                    target_digest = validated_target_digests.get(
                        variant.name, _target_digest(plan, variant, inputs)
                    )
                    nonce = _arm_capability_oracle(
                        oracle,
                        cve_id=context.cve_id,
                        variant=variant.name,
                        target_digest=target_digest,
                        candidate_commitment=candidate_commitment,
                    )
                    result = self._candidate_run(
                        execution_id, variant.name, network, plan.container_port,
                        candidate, candidate_path, created_containers, audit, nonce=nonce,
                    )
                    result["_host_observation"] = self._observe_target_canary(
                        name, nonce, audit,
                    )
                    self._command((self.docker_binary, "network", "disconnect", network, name), audit)
                    targets.append({"variant": variant.name, "status": "running", "internal_url": target_url})
                    runs.append(_evidence_receipt(
                        result,
                        candidate_commitment,
                        cve_id=context.cve_id,
                        target_digest=target_digest,
                        oracle=oracle,
                        nonce=nonce,
                    ))
                payload = {
                    "execution_id": execution_id,
                    "executor": "trusted-rootless-docker/container-plan-v1",
                    "builds": builds,
                    "targets": targets,
                    "candidate_runs": runs,
                    "cleanup": cleanup,
                }
        except BaseException as exc:
            primary = exc
        finally:
            failures: list[str] = []
            for name in reversed(created_containers):
                self._cleanup((self.docker_binary, "rm", "--force", name), "container", failures, audit)
            if network_created:
                self._cleanup((self.docker_binary, "network", "rm", network), "network", failures, audit)
            for image in reversed(created_images):
                self._cleanup((self.docker_binary, "image", "rm", "--force", image), "image", failures, audit)
            cleanup = {"ok": not failures, "failures": failures}
            if payload is not None:
                payload["cleanup"] = cleanup
            try:
                self._write_outputs(output_dir, execution_id, payload, cleanup, audit, primary)
            except BaseException as output_error:
                if primary is None:
                    primary = output_error

        if primary is not None:
            raise RuntimeExecutionError(primary, cleanup) from primary
        assert payload is not None
        return TrustedStageOutput(
            payload,
            (
                TrustedArtifact("execution-summary", "execution-summary.json", "public_summary"),
                TrustedArtifact("execution-audit", "execution-audit.json", "local_audit"),
            ),
            "success" if cleanup["ok"] else "partial",
        )

    def execute_adversarial(
        self, *, context: TrustedCallbackContext, output_dir: Path
    ) -> TrustedStageOutput:
        """Fresh-build both variants and execute every declared adversarial round."""
        with _runtime_deadline(context.remaining_run_seconds):
            return self._execute_evidence(context=context, output_dir=output_dir, mode="adversarial")

    def execute_fix(
        self, *, context: TrustedCallbackContext, output_dir: Path
    ) -> TrustedStageOutput:
        """Overlay declared replacements and execute all original/challenge candidates."""
        with _runtime_deadline(context.remaining_run_seconds):
            return self._execute_evidence(context=context, output_dir=output_dir, mode="fix")

    def _execute_evidence(
        self, *, context: TrustedCallbackContext, output_dir: Path, mode: str
    ) -> TrustedStageOutput:
        output_dir = Path(output_dir)
        if output_dir.is_symlink() or not output_dir.is_dir():
            raise RuntimeValidationError("output_dir must be an existing regular directory")
        if mode not in {"adversarial", "fix"}:
            raise RuntimeValidationError("unknown bounded execution mode")
        harness_record = _record(context.public_stage_records, "harness_builder")
        exploiter_record = _record(context.public_stage_records, "exploiter")
        adversarial_record = _record(context.public_stage_records, "adversarial_loop")
        _record(context.public_stage_records, "provision_execution" if mode == "adversarial" else "adversarial_execution")
        harness_payload = _payload(harness_record, "harness_builder")
        plan = _parse_container_plan(harness_payload)
        original = _parse_candidate_plan(_payload(exploiter_record, "exploiter"))
        rounds = _parse_adversarial_plan(_payload(adversarial_record, "adversarial_loop"))
        fix_plan = None
        if mode == "fix":
            fix_record = _record(context.public_stage_records, "fix_developer")
            fix_plan = _parse_fix_plan(_payload(fix_record, "fix_developer"))

        inputs = self._validate_inputs(context.inputs)
        oracle = _validated_capability_oracle(self.capability_oracle, context.cve_id)
        validated_target_digests = _validated_target_identities(
            self.target_identity_validator, context.cve_id, harness_payload,
            {key: value.data for key, value in inputs.items()}, plan,
        )
        destinations = {artifact_id: destination for artifact_id, destination in plan.files}
        destination_ids = {destination: artifact_id for artifact_id, destination in plan.files}
        candidates = [("original", original)] if mode == "fix" else []
        candidates.extend((item.id, item.candidate) for item in rounds)
        referenced = {artifact_id for artifact_id, _ in plan.files}
        referenced.update(item.dockerfile_artifact_id for item in plan.variants)
        referenced.update(candidate.artifact_id for _, candidate in candidates)
        if fix_plan is not None:
            referenced.update(artifact_id for artifact_id, _ in fix_plan.replacements)
        if referenced - set(inputs):
            raise RuntimeValidationError("execution plan references unknown artifact ID")
        candidate_commitments = {
            candidate_id: _candidate_commitment(candidate, inputs[candidate.artifact_id].data)
            for candidate_id, candidate in candidates
        }
        build_ids = set(destinations)
        if any(candidate.artifact_id in build_ids for _, candidate in candidates):
            raise RuntimeValidationError("candidate artifact must not enter the target build context")
        dockerfile_ids = {item.dockerfile_artifact_id for item in plan.variants}
        if len(dockerfile_ids) != len(plan.variants) or not dockerfile_ids <= build_ids:
            raise RuntimeValidationError("variants require distinct declared Dockerfiles")
        for variant in plan.variants:
            _validate_dockerfile(inputs[variant.dockerfile_artifact_id].data, self.allowed_base_images)
        fix_commitment: str | None = None
        if fix_plan is not None:
            commitment_records = []
            for artifact_id, destination in fix_plan.replacements:
                if destination not in destination_ids:
                    raise RuntimeValidationError("replacement destination is not an existing build-context destination")
                if destination_ids[destination] in dockerfile_ids:
                    raise RuntimeValidationError("replacement may not replace a variant Dockerfile")
                if artifact_id in build_ids or any(artifact_id == candidate.artifact_id for _, candidate in candidates):
                    raise RuntimeValidationError("replacement artifact must be a unique model_input file")
                commitment_records.append({
                    "destination_sha256": sha256_bytes(destination.encode("utf-8")),
                    "replacement_sha256": sha256_bytes(inputs[artifact_id].data),
                })
            fix_commitment = sha256_bytes(canonical_json(sorted(
                commitment_records, key=lambda item: (item["destination_sha256"], item["replacement_sha256"]),
            )))

        execution_id = _execution_id(context.run_id, context.predecessor_handoff_sha256 + f":{mode}")
        network = _opaque_runtime_name()
        variants = list(plan.variants) if mode == "adversarial" else [next(item for item in plan.variants if item.name == "vulnerable")]
        image_names = {
            item.name: _opaque_runtime_name()
            for item in variants
        }
        created_images: list[str] = []
        created_containers: list[str] = []
        network_created = False
        audit: list[dict[str, object]] = []
        primary: BaseException | None = None
        cleanup: dict[str, object] = {"ok": True, "failures": []}
        payload: dict[str, object] | None = None
        try:
            self._check_daemon(audit)
            with tempfile.TemporaryDirectory(prefix=f"cvehunt-{mode}-build-") as temporary, tempfile.TemporaryDirectory(prefix=f"cvehunt-{mode}-candidate-") as candidate_temporary:
                build_root = Path(temporary)
                candidate_root = Path(candidate_temporary)
                self._materialize_context(build_root, plan, inputs)
                if fix_plan is not None:
                    for artifact_id, destination in fix_plan.replacements:
                        target = build_root.joinpath(*PurePosixPath(destination).parts)
                        if not target.is_file() or target.is_symlink():
                            raise RuntimeValidationError("replacement target is not an existing regular context file")
                        target.write_bytes(inputs[artifact_id].data)
                        target.chmod(0o600)
                candidate_paths: dict[str, Path] = {}
                for candidate_id, candidate in candidates:
                    path = candidate_root / f"{candidate_id}.py"
                    path.write_bytes(inputs[candidate.artifact_id].data)
                    path.chmod(0o400)
                    if sha256_bytes(_safe_read(path, self.max_artifact_bytes)) != sha256_bytes(inputs[candidate.artifact_id].data):
                        raise RuntimeValidationError("materialized candidate hash mismatch")
                    candidate_paths[candidate_id] = path
                network_created = True
                self._command((self.docker_binary, "network", "create", "--internal", network), audit)
                builds: list[dict[str, object]] = []
                targets: list[dict[str, object]] = []
                receipts: list[dict[str, object]] = []
                for variant in variants:
                    dockerfile = destinations[variant.dockerfile_artifact_id]
                    created_images.append(image_names[variant.name])
                    self._command((
                        self.docker_binary, "build", "--network=none", "--pull=false", "--tag",
                        image_names[variant.name], "--file", str(build_root / dockerfile), str(build_root),
                    ), audit)
                    public_variant = "fixed" if mode == "fix" else variant.name
                    builds.append({"variant": public_variant, "status": "built"})
                    target_name = _opaque_runtime_name()
                    created_containers.append(target_name)
                    self._command(self._target_create_argv(target_name, image_names[variant.name]), audit)
                    self._command(
                        (self.docker_binary, "network", "connect", "--alias", "target", network, target_name), audit,
                    )
                    self._command((self.docker_binary, "start", target_name), audit)
                    readiness_url = f"http://target:{plan.container_port}{plan.readiness_path}"
                    self._readiness_probe(execution_id, public_variant, network, readiness_url, 25, created_containers, audit)
                    targets.append({"variant": public_variant, "status": "running"})
                    for candidate_id, candidate in candidates:
                        target_digest = validated_target_digests.get(
                            variant.name, _target_digest(plan, variant, inputs)
                        )
                        if mode == "fix":
                            if fix_commitment is None:
                                raise RuntimeValidationError("fixed target lacks fix commitment")
                            target_digest = sha256_bytes(canonical_json({
                                "schema": "cvehunt.fixed-target-identity/v1",
                                "base_target_digest": target_digest,
                                "fix_commitment": fix_commitment,
                            }))
                        nonce = _arm_capability_oracle(
                            oracle,
                            cve_id=context.cve_id,
                            variant=public_variant,
                            target_digest=target_digest,
                            candidate_commitment=candidate_commitments[candidate_id],
                        )
                        raw_run = self._candidate_run(
                            execution_id, public_variant, network, plan.container_port,
                            candidate, candidate_paths[candidate_id], created_containers, audit,
                            run_id=candidate_id, nonce=nonce,
                        )
                        raw_run["_host_observation"] = self._observe_target_canary(
                            target_name, nonce, audit,
                        )
                        receipts.append(_evidence_receipt(
                            raw_run,
                            candidate_commitments[candidate_id],
                            cve_id=context.cve_id,
                            target_digest=target_digest,
                            oracle=oracle,
                            nonce=nonce,
                        ))
                    self._command((self.docker_binary, "network", "disconnect", network, target_name), audit)
                if mode == "adversarial":
                    payload = {
                        "execution_id": execution_id,
                        "executor": "trusted-rootless-docker/adversarial-plan-v1",
                        "builds": builds,
                        "targets": targets,
                        "adversarial_runs": receipts,
                        "cleanup": cleanup,
                    }
                else:
                    payload = {
                        "execution_id": execution_id,
                        "executor": "trusted-rootless-docker/fix-plan-v1",
                        "build": builds[0],
                        "target": targets[0],
                        "candidate_runs": receipts,
                        "fix_commitment": fix_commitment,
                        "cleanup": cleanup,
                    }
        except BaseException as exc:
            primary = exc
        finally:
            failures: list[str] = []
            for name in reversed(created_containers):
                self._cleanup((self.docker_binary, "rm", "--force", name), "container", failures, audit)
            if network_created:
                self._cleanup((self.docker_binary, "network", "rm", network), "network", failures, audit)
            for image in reversed(created_images):
                self._cleanup((self.docker_binary, "image", "rm", "--force", image), "image", failures, audit)
            cleanup = {"ok": not failures, "failures": failures}
            if payload is not None:
                payload["cleanup"] = cleanup
            try:
                self._write_evidence_outputs(output_dir, execution_id, mode, payload, cleanup, audit, primary)
            except BaseException as output_error:
                if primary is None:
                    primary = output_error
        if primary is not None:
            raise RuntimeExecutionError(primary, cleanup) from primary
        assert payload is not None
        return TrustedStageOutput(
            payload,
            (
                TrustedArtifact(f"{mode}-execution-summary", f"{mode}-execution-summary.json", "public_summary"),
                TrustedArtifact(f"{mode}-execution-audit", f"{mode}-execution-audit.json", "local_audit"),
            ),
            "success" if cleanup["ok"] else "partial",
        )

    @staticmethod
    def _write_evidence_outputs(
        output_dir: Path, execution_id: str, mode: str, payload: Mapping[str, object] | None,
        cleanup: Mapping[str, object], audit: Sequence[Mapping[str, object]], primary: BaseException | None,
    ) -> None:
        runs_key = "adversarial_runs" if mode == "adversarial" else "candidate_runs"
        public_runs = []
        for raw in _payload_list(payload, runs_key):
            receipt = _mapping(raw, "evidence receipt")
            public_runs.append({
                key: receipt[key]
                for key in (
                    "schema", "cve_id", "variant", "trusted_result",
                    "candidate_commitment", "target_digest", "oracle_digest",
                    "nonce_commitment", "observed_interaction_commitment",
                    "execution_result", "infrastructure_disposition",
                    "evidence_sha256", "evidence_bytes",
                )
            })
        public = {
            "schema": f"cvehunt.{mode}-execution-summary/v1",
            "execution_id": execution_id,
            "status": "failed" if primary else "completed",
            "runs": public_runs,
            "cleanup": dict(cleanup),
        }
        if mode == "fix" and payload is not None:
            public["fix_commitment"] = payload.get("fix_commitment")
        local = {
            "schema": f"cvehunt.{mode}-execution-audit/v1",
            "execution_id": execution_id,
            "primary_error": type(primary).__name__ if primary else None,
            "commands": list(audit)[-256:],
            "cleanup": dict(cleanup),
        }
        _bounded_json(output_dir / f"{mode}-execution-summary.json", public, 64 * 1024)
        _bounded_json(output_dir / f"{mode}-execution-audit.json", local, 256 * 1024)

    def _validate_inputs(self, raw_inputs: Sequence[TrustedInput]) -> dict[str, _File]:
        result: dict[str, _File] = {}
        file_identities: set[tuple[int, int]] = set()
        total = 0
        for item in raw_inputs:
            if not isinstance(item, TrustedInput):
                raise RuntimeValidationError("context input has invalid type")
            artifact_id = _identifier(item.artifact_id, "artifact_id")
            if artifact_id in result:
                raise RuntimeValidationError("duplicate context input artifact ID")
            if item.classification != "model_input":
                raise RuntimeValidationError("runtime context inputs must be model_input-classified")
            info = Path(item.path).lstat()
            identity = (info.st_dev, info.st_ino)
            if identity in file_identities:
                raise RuntimeValidationError("distinct input artifact IDs must identify unique files")
            file_identities.add(identity)
            data = _safe_read(item.path, self.max_artifact_bytes)
            if hashlib.sha256(data).hexdigest() != item.sha256:
                raise RuntimeValidationError("context input hash mismatch")
            total += len(data)
            if total > self.max_total_context_bytes:
                raise RuntimeValidationError("context inputs exceed total size limit")
            result[artifact_id] = _File(artifact_id, Path(item.path), data)
        return result

    @staticmethod
    def _materialize_context(root: Path, plan: _ContainerPlan, inputs: Mapping[str, _File]) -> None:
        for artifact_id, destination in plan.files:
            target = root.joinpath(*PurePosixPath(destination).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists() or target.is_symlink():
                raise RuntimeValidationError("duplicate build-context destination")
            target.write_bytes(inputs[artifact_id].data)
            target.chmod(0o600)

    def _check_daemon(self, audit: list[dict[str, object]]) -> None:
        result = self._command(
            (self.docker_binary, "info", "--format", "{{json .SecurityOptions}}"), audit
        )
        try:
            options = json.loads(result.stdout)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise CommandExecutionError("docker info returned invalid security options") from exc
        rootless = isinstance(options, list) and any(
            isinstance(item, str) and (item == "rootless" or "name=rootless" in item)
            for item in options
        )
        if self.require_rootless and not rootless:
            raise CommandExecutionError("rootless Docker daemon is required")
        for image in sorted(self.allowed_base_images | {self.python_runner_image}):
            self._command(
                (self.docker_binary, "image", "inspect", "--format", "{{.Id}}", image), audit
            )

    def _target_create_argv(self, name: str, image: str) -> tuple[str, ...]:
        return (
            self.docker_binary, "create", "--name", name, "--network", "none",
            "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--pids-limit", "128", "--memory", "512m", "--cpus", "1.0",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m", image,
        )

    def _readiness_probe(
        self, execution_id: str, variant: str, network: str, url: str,
        timeout_seconds: float, created_containers: list[str],
        audit: list[dict[str, object]],
    ) -> None:
        # Fixed trusted source: no plan text is interpolated into Python code.
        code = (
            "import os,time,urllib.request;u=os.environ['CVEHUNT_TARGET'];end=time.monotonic()+20;"
            "\nwhile True:\n"
            " try:\n  urllib.request.urlopen(u,timeout=2).read(1);break\n"
            " except Exception:\n  \n  if time.monotonic()>=end:raise\n  time.sleep(.2)"
        )
        probe_name = _opaque_runtime_name()
        created_containers.append(probe_name)
        argv = self._restricted_run_prefix(network) + (
            "--name", probe_name, "--env", f"CVEHUNT_TARGET={url}", self.python_runner_image,
            "python", "-I", "-c", code,
        )
        self._command(argv, audit, timeout_seconds=min(timeout_seconds, 25.0))

    def _candidate_run(
        self, execution_id: str, variant: str, network: str,
        port: int, plan: _CandidatePlan, candidate_path: Path,
        created_containers: list[str], audit: list[dict[str, object]],
        *, run_id: str = "candidate", nonce: bytes,
    ) -> dict[str, object]:
        _identifier(run_id, "candidate run ID")
        runner_name = _opaque_runtime_name()
        target_url = f"http://target:{port}"
        created_containers.append(runner_name)
        argv = self._restricted_run_prefix(network) + (
            "--name", runner_name, "--mount", f"type=bind,src={candidate_path.resolve()},dst=/candidate/candidate.py,readonly",
            "--env", f"CVEHUNT_TARGET={target_url}",
            "--env", f"CVEHUNT_CHALLENGE={nonce.hex()}", self.python_runner_image,
            "python", "-I", "/candidate/candidate.py", *plan.args,
        )
        if argv.count("--mount") != 1:
            raise RuntimeValidationError("candidate mount invariant failed")
        stdin = canonical_json(plan.data)
        result = self._command(argv, audit, timeout_seconds=plan.timeout_seconds, input_data=stdin)
        parsed = _candidate_result(result.stdout)
        execution_result = {
            "returncode": result.returncode,
            "stdout_sha256": sha256_bytes(result.stdout),
            "stderr_sha256": sha256_bytes(result.stderr),
            "timed_out": result.timed_out,
            "stdout_truncated": result.stdout_truncated,
            "stderr_truncated": result.stderr_truncated,
        }
        return {
            "variant": variant,
            **parsed,
            "_stdout": result.stdout,
            "_stderr": result.stderr,
            "_execution_result_commitment": sha256_bytes(canonical_json(execution_result)),
        }

    def _observe_target_canary(
        self, target_name: str, nonce: bytes, audit: list[dict[str, object]],
    ) -> bytes:
        """Observe a nonce-bound target-side effect without trusting candidate output."""
        path = f"/tmp/cvehunt-capability-{nonce.hex()}"
        deadline = _ACTIVE_RUN_DEADLINE.get()
        timeout = min(self.command_timeout_seconds, 10.0)
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CommandExecutionError("run deadline exhausted before host observation")
            timeout = min(timeout, remaining)
        argv = (self.docker_binary, "exec", target_name, "cat", path)
        result = self.runner.run(
            argv, timeout_seconds=timeout, max_output_bytes=4096,
        )
        audit.append({
            "operation": "docker:exec-canary", "returncode": result.returncode,
            "timed_out": result.timed_out,
            "stdout_sha256": sha256_bytes(result.stdout),
            "stderr_sha256": sha256_bytes(result.stderr),
            "stdout_truncated": result.stdout_truncated,
            "stderr_truncated": result.stderr_truncated,
        })
        if result.timed_out or result.stdout_truncated or result.stderr_truncated:
            raise CommandExecutionError("host capability observation failed")
        return canonical_json({
            "schema": "cvehunt.target-canary-observation/v1",
            "present": result.returncode == 0,
            "content_sha256": sha256_bytes(result.stdout),
            "content_bytes": len(result.stdout),
        })

    def _restricted_run_prefix(self, network: str) -> tuple[str, ...]:
        return (
            self.docker_binary, "run", "--network", network, "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--pids-limit", "64", "--memory", "256m", "--cpus", "0.5",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=32m",
        )

    def _command(
        self, argv: Sequence[str], audit: list[dict[str, object]], *,
        timeout_seconds: float | None = None, input_data: bytes | None = None,
        cleanup: bool = False,
    ) -> CommandResult:
        requested_timeout = timeout_seconds or self.command_timeout_seconds
        deadline = _ACTIVE_RUN_DEADLINE.get()
        if deadline is not None:
            remaining = deadline - time.monotonic()
            available = remaining if cleanup else remaining - _ACTIVE_CLEANUP_RESERVE.get()
            if available <= 0:
                raise CommandExecutionError("run deadline exhausted before command")
            requested_timeout = min(requested_timeout, available)
        result = self.runner.run(
            argv,
            timeout_seconds=requested_timeout,
            max_output_bytes=self.max_output_bytes,
            input_data=input_data,
        )
        audit.append({
            "operation": _operation(argv), "returncode": result.returncode,
            "timed_out": result.timed_out,
            "stdout_sha256": sha256_bytes(result.stdout), "stderr_sha256": sha256_bytes(result.stderr),
            "stdout_truncated": result.stdout_truncated, "stderr_truncated": result.stderr_truncated,
        })
        if result.timed_out:
            raise CommandExecutionError(f"{_operation(argv)} timed out")
        if result.stdout_truncated or result.stderr_truncated:
            raise CommandExecutionError(f"{_operation(argv)} exceeded output limit")
        if result.returncode != 0:
            raise CommandExecutionError(f"{_operation(argv)} failed with exit code {result.returncode}")
        return result

    def _cleanup(
        self, argv: Sequence[str], kind: str, failures: list[str], audit: list[dict[str, object]]
    ) -> None:
        try:
            self._command(
                argv, audit, timeout_seconds=min(self.command_timeout_seconds, 30.0),
                cleanup=True,
            )
        except BaseException:
            failures.append(kind)

    @staticmethod
    def _write_outputs(
        output_dir: Path, execution_id: str, payload: Mapping[str, object] | None,
        cleanup: Mapping[str, object], audit: Sequence[Mapping[str, object]],
        primary: BaseException | None,
    ) -> None:
        public_runs = []
        for raw_run in _payload_list(payload, "candidate_runs"):
            run = _mapping(raw_run, "candidate run")
            public_runs.append({
                key: run[key]
                for key in (
                    "schema", "cve_id", "variant", "trusted_result",
                    "candidate_commitment", "target_digest", "oracle_digest",
                    "nonce_commitment", "observed_interaction_commitment",
                    "execution_result", "infrastructure_disposition",
                    "evidence_bytes", "evidence_sha256",
                )
            })
        public_targets = []
        for raw_target in _payload_list(payload, "targets"):
            target = _mapping(raw_target, "target result")
            public_targets.append({"variant": target.get("variant"), "status": target.get("status")})
        public = {
            "schema": "cvehunt.execution-summary/v1", "execution_id": execution_id,
            "status": "failed" if primary else "completed",
            "builds": _payload_list(payload, "builds"),
            "targets": public_targets,
            "candidate_runs": public_runs,
            "cleanup": dict(cleanup),
        }
        local = {
            "schema": "cvehunt.execution-audit/v1", "execution_id": execution_id,
            "primary_error": type(primary).__name__ if primary else None,
            "commands": list(audit)[-128:], "cleanup": dict(cleanup),
        }
        _bounded_json(output_dir / "execution-summary.json", public, 64 * 1024)
        _bounded_json(output_dir / "execution-audit.json", local, 128 * 1024)


class HiddenOracleScorer:
    """Evaluate a bounded hidden oracle without copying or disclosing it."""

    def __init__(self, oracle_path: Path, *, max_oracle_bytes: int = 64 * 1024) -> None:
        self.oracle_path = Path(oracle_path)
        self.max_oracle_bytes = _positive_int(max_oracle_bytes, "max_oracle_bytes")
        try:
            info = self.oracle_path.lstat()
            raw = _safe_read(self.oracle_path, self.max_oracle_bytes)
        except OSError as exc:
            raise RuntimeValidationError("hidden oracle unavailable during preflight") from exc
        self._pinned_identity = (info.st_dev, info.st_ino, info.st_size)
        self._pinned_raw = raw
        self._pinned_sha256 = sha256_bytes(raw)

    def official_score(
        self, *, context: TrustedCallbackContext, output_dir: Path
    ) -> TrustedStageOutput:
        output_dir = Path(output_dir)
        run_dir = output_dir.parent.parent if output_dir.parent.name == "callbacks" else output_dir
        if self.oracle_path.resolve().is_relative_to(run_dir.resolve()):
            raise RuntimeValidationError("hidden oracle must be outside pipeline run directory")
        try:
            current = self.oracle_path.lstat()
            current_raw = _safe_read(self.oracle_path, self.max_oracle_bytes)
        except (OSError, RuntimeValidationError) as exc:
            raise RuntimeValidationError("hidden oracle changed after preflight") from exc
        if (
            (current.st_dev, current.st_ino, current.st_size) != self._pinned_identity
            or sha256_bytes(current_raw) != self._pinned_sha256
        ):
            raise RuntimeValidationError("hidden oracle changed after preflight")
        oracle = _parse_json(self._pinned_raw, "hidden oracle")
        normalized = _validate_oracle(oracle, context.cve_id)
        commitment = sha256_bytes(canonical_json(normalized))
        score = 0.0
        for rule in normalized["rules"]:
            actual_present, actual = _lookup_public(context.public_stage_records, rule["stage"], rule["path"])
            matched = _evaluate(rule, actual_present, actual)
            awarded = rule["weight"] if matched else 0
            score += awarded
        score = min(score, normalized["max_score"])
        scoring_input = {
            key: dict(value)
            for key, value in sorted(context.public_stage_records.items())
        }
        payload = {
            "score": score, "max_score": normalized["max_score"],
            "eligible": True,
            "oracle_commitment": commitment,
            "scoring_input_commitment": sha256_bytes(canonical_json(scoring_input)),
        }
        # Scoring intentionally emits no artifact: the hidden file and expected
        # values never enter the callback directory, envelope, or public packet.
        return TrustedStageOutput(payload)


def _parse_container_plan(payload: Mapping[str, Any]) -> _ContainerPlan:
    if set(payload) != {
        "target_class", "backend", "variants", "services", "commands", "safety", "container_plan"
    }:
        raise RuntimeValidationError("harness_builder payload has unknown or missing keys")
    raw = _mapping(payload["container_plan"], "container_plan")
    if len(canonical_json(raw)) > _MAX_PLAN_BYTES:
        raise RuntimeValidationError("container plan exceeds size limit")
    if set(raw) != {"schema", "files", "variants", "container_port", "readiness_path"}:
        raise RuntimeValidationError("container plan has unknown or missing keys")
    if raw["schema"] != CONTAINER_PLAN_SCHEMA:
        raise RuntimeValidationError("invalid container plan schema")
    files_raw = _array(raw["files"], "container_plan.files")
    files: list[tuple[str, str]] = []
    ids: set[str] = set()
    destinations: set[str] = set()
    for item in files_raw:
        entry = _exact_mapping(item, {"artifact_id", "destination"}, "container_plan.files entry")
        artifact_id = _identifier(entry["artifact_id"], "artifact_id")
        destination = _relative_path(entry["destination"], "destination")
        if artifact_id in ids or destination in destinations:
            raise RuntimeValidationError("duplicate build-context artifact or destination")
        ids.add(artifact_id)
        destinations.add(destination)
        files.append((artifact_id, destination))
    if not files:
        raise RuntimeValidationError("build-context files must not be empty")
    variants_raw = _array(raw["variants"], "container_plan.variants")
    variants: list[_Variant] = []
    names: set[str] = set()
    for item in variants_raw:
        entry = _exact_mapping(item, {"name", "dockerfile_artifact_id"}, "variant")
        name = _identifier(entry["name"], "variant.name")
        if name not in {"vulnerable", "patched"} or name in names:
            raise RuntimeValidationError("variants must contain vulnerable and patched exactly once")
        names.add(name)
        variants.append(_Variant(name, _identifier(entry["dockerfile_artifact_id"], "dockerfile_artifact_id")))
    if names != {"vulnerable", "patched"}:
        raise RuntimeValidationError("variants must contain vulnerable and patched")
    port = _positive_int(raw["container_port"], "container_port")
    if port > 65535:
        raise RuntimeValidationError("container_port is out of range")
    readiness = _readiness_path(raw["readiness_path"])
    return _ContainerPlan(tuple(files), tuple(variants), port, readiness)


def _parse_candidate_plan(payload: Mapping[str, Any]) -> _CandidatePlan:
    if set(payload) != {"hypothesis_ids", "candidate", "derivation", "runtime_requirements"}:
        raise RuntimeValidationError("exploiter payload has unknown or missing keys")
    raw = _mapping(payload["candidate"], "candidate")
    if len(canonical_json(raw)) > _MAX_PLAN_BYTES:
        raise RuntimeValidationError("candidate plan exceeds size limit")
    if set(raw) != {"schema", "artifact_id", "runtime", "timeout_seconds", "args", "data"}:
        raise RuntimeValidationError("candidate plan has unknown or missing keys")
    if raw["schema"] != CANDIDATE_PLAN_SCHEMA or raw["runtime"] != "python":
        raise RuntimeValidationError("candidate schema or runtime is not allowlisted")
    timeout = _positive_number(raw["timeout_seconds"], "timeout_seconds")
    if timeout > 60:
        raise RuntimeValidationError("candidate timeout exceeds limit")
    args_raw = _array(raw["args"], "candidate.args")
    if len(args_raw) > 16:
        raise RuntimeValidationError("too many candidate arguments")
    args: list[str] = []
    for value in args_raw:
        if not isinstance(value, str) or not _ENV_SAFE.fullmatch(value) or len(value) > 256:
            raise RuntimeValidationError("candidate argument is invalid")
        args.append(value)
    encoded_data = canonical_json(raw["data"])
    if len(encoded_data) > 8192:
        raise RuntimeValidationError("candidate data exceeds limit")
    return _CandidatePlan(_identifier(raw["artifact_id"], "candidate.artifact_id"), "python", timeout, tuple(args), raw["data"])


def _parse_adversarial_plan(payload: Mapping[str, Any]) -> tuple[_AdversarialRound, ...]:
    if set(payload) != {"round_budget", "rounds", "rounds_executed", "stop_reason", "adversarial_plan"}:
        raise RuntimeValidationError("adversarial_loop payload has unknown or missing keys")
    raw = _exact_mapping(payload["adversarial_plan"], {"schema", "rounds"}, "adversarial_plan")
    if raw["schema"] != ADVERSARIAL_PLAN_SCHEMA or len(canonical_json(raw)) > _MAX_PLAN_BYTES:
        raise RuntimeValidationError("invalid or oversized adversarial plan")
    rounds_raw = _array(raw["rounds"], "adversarial_plan.rounds")
    if not 1 <= len(rounds_raw) <= 3:
        raise RuntimeValidationError("adversarial plan requires 1..3 rounds")
    result: list[_AdversarialRound] = []
    ids: set[str] = set()
    artifact_ids: set[str] = set()
    for raw_round in rounds_raw:
        entry = _exact_mapping(
            raw_round, {"id", "artifact_id", "runtime", "timeout_seconds", "args", "data"},
            "adversarial round",
        )
        round_id = _identifier(entry["id"], "round.id")
        candidate_payload = {
            "hypothesis_ids": [], "derivation": {}, "runtime_requirements": {},
            "candidate": {"schema": CANDIDATE_PLAN_SCHEMA, **{key: entry[key] for key in (
                "artifact_id", "runtime", "timeout_seconds", "args", "data"
            )}},
        }
        candidate = _parse_candidate_plan(candidate_payload)
        if round_id in ids or candidate.artifact_id in artifact_ids:
            raise RuntimeValidationError("adversarial round IDs and artifact IDs must be unique")
        ids.add(round_id)
        artifact_ids.add(candidate.artifact_id)
        result.append(_AdversarialRound(round_id, candidate))
    return tuple(result)


def _parse_fix_plan(payload: Mapping[str, Any]) -> _FixPlan:
    if set(payload) != {"root_cause", "patch", "security_invariant", "expected_behavior", "limitations", "fix_plan"}:
        raise RuntimeValidationError("fix_developer payload has unknown or missing keys")
    raw = _exact_mapping(payload["fix_plan"], {"schema", "replacements"}, "fix_plan")
    if raw["schema"] != FIX_PLAN_SCHEMA or len(canonical_json(raw)) > _MAX_PLAN_BYTES:
        raise RuntimeValidationError("invalid or oversized fix plan")
    replacements_raw = _array(raw["replacements"], "fix_plan.replacements")
    if not 1 <= len(replacements_raw) <= 16:
        raise RuntimeValidationError("fix plan requires 1..16 replacements")
    replacements: list[tuple[str, str]] = []
    ids: set[str] = set()
    destinations: set[str] = set()
    for item in replacements_raw:
        entry = _exact_mapping(item, {"artifact_id", "destination"}, "fix replacement")
        artifact_id = _identifier(entry["artifact_id"], "replacement.artifact_id")
        destination = _relative_path(entry["destination"], "replacement.destination")
        if artifact_id in ids or destination in destinations:
            raise RuntimeValidationError("duplicate fix replacement artifact or destination")
        ids.add(artifact_id)
        destinations.add(destination)
        replacements.append((artifact_id, destination))
    return _FixPlan(tuple(replacements))


def _candidate_commitment(plan: _CandidatePlan, source: bytes) -> str:
    """Bind the executable bytes and complete fixed runner inputs without publishing them."""
    return sha256_bytes(canonical_json({
        "source_sha256": sha256_bytes(source),
        "runtime": plan.runtime,
        "timeout_seconds": plan.timeout_seconds,
        "args": list(plan.args),
        "data": plan.data,
    }))


def _opaque_runtime_name() -> str:
    """Return a fresh Docker-safe name with no target/control semantics."""
    return f"cvehunt-{secrets.token_hex(12)}"


def _evidence_receipt(
    run: Mapping[str, object],
    candidate_commitment: str,
    *,
    cve_id: str,
    target_digest: str,
    oracle: CapabilityOracle | None,
    nonce: bytes,
) -> dict[str, object]:
    """Bind execution to the challenge armed before candidate side effects."""
    evidence = run.get("evidence")
    if not isinstance(evidence, str):
        raise RuntimeValidationError("candidate evidence must be text")
    encoded = evidence.encode("utf-8")
    claimed = run.get("triggered")
    if not isinstance(claimed, bool):
        raise RuntimeValidationError("candidate triggered claim must be boolean")
    if not re.fullmatch(r"[0-9a-f]{64}", candidate_commitment):
        raise RuntimeValidationError("candidate commitment is invalid")
    execution_result_commitment = run.get("_execution_result_commitment")
    stdout = run.get("_stdout")
    stderr = run.get("_stderr")
    host_observation = run.get("_host_observation")
    if (
        not isinstance(execution_result_commitment, str)
        or not re.fullmatch(r"[0-9a-f]{64}", execution_result_commitment)
        or not isinstance(stdout, bytes)
        or not isinstance(stderr, bytes)
        or not isinstance(host_observation, bytes)
    ):
        raise RuntimeValidationError("candidate execution result is incomplete")
    if not isinstance(nonce, bytes) or len(nonce) != 32:
        raise RuntimeValidationError("capability challenge nonce is invalid")
    observation = CapabilityOracleObservation(False, b"")
    if oracle is not None:
        observation = oracle.observe(CapabilityOracleRequest(
            cve_id=cve_id,
            nonce=nonce,
            variant=str(run.get("variant")),
            target_digest=target_digest,
            candidate_commitment=candidate_commitment,
            execution_result_commitment=execution_result_commitment,
            candidate_stdout=stdout,
            candidate_stderr=stderr,
            host_observation=host_observation,
        ))
        if not isinstance(observation, CapabilityOracleObservation):
            raise RuntimeValidationError("capability oracle returned the wrong type")
        if not isinstance(observation.capability_proved, bool):
            raise RuntimeValidationError("capability oracle result must be boolean")
        if not isinstance(observation.observed_interaction, bytes):
            raise RuntimeValidationError("capability oracle interaction must be bytes")
        if observation.capability_proved and not observation.observed_interaction:
            raise RuntimeValidationError("positive capability observation requires interaction evidence")
    return {
        "schema": CAPABILITY_RECEIPT_SCHEMA,
        "cve_id": cve_id,
        "variant": run.get("variant"),
        "trusted_result": observation.capability_proved,
        "candidate_commitment": candidate_commitment,
        "target_digest": target_digest,
        "oracle_digest": oracle.oracle_sha256 if oracle is not None else None,
        "nonce_commitment": sha256_bytes(nonce),
        "observed_interaction_commitment": sha256_bytes(canonical_json({
            "nonce_sha256": sha256_bytes(nonce),
            "observation_sha256": sha256_bytes(observation.observed_interaction),
        })),
        "execution_result": {
            "status": "completed",
            "commitment": execution_result_commitment,
        },
        "infrastructure_disposition": "completed",
        "evidence_sha256": sha256_bytes(encoded),
        "evidence_bytes": len(encoded),
    }


def _validated_capability_oracle(
    oracle: CapabilityOracle | None, cve_id: str,
) -> CapabilityOracle | None:
    if oracle is None:
        return None
    if getattr(oracle, "cve_id", None) != cve_id:
        raise RuntimeValidationError("capability oracle CVE identity mismatch")
    digest = getattr(oracle, "oracle_sha256", None)
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise RuntimeValidationError("capability oracle digest is invalid")
    if not callable(getattr(oracle, "arm", None)) or not callable(getattr(oracle, "observe", None)):
        raise RuntimeValidationError("capability oracle observer is unavailable")
    return oracle


def _validated_target_identities(
    validator: TargetIdentityValidator | None,
    cve_id: str,
    harness_payload: Mapping[str, object],
    artifacts: Mapping[str, bytes],
    plan: _ContainerPlan,
) -> dict[str, str]:
    if validator is None:
        return {}
    if getattr(validator, "cve_id", None) != cve_id or not callable(
        getattr(validator, "validate", None)
    ):
        raise RuntimeValidationError("target identity validator is unavailable")
    try:
        raw = validator.validate(
            cve_id=cve_id, harness_payload=harness_payload, artifacts=artifacts,
        )
    except RuntimeValidationError:
        raise
    except Exception:
        raise RuntimeValidationError("target identity validation failed") from None
    expected = {item.name for item in plan.variants}
    if not isinstance(raw, Mapping) or set(raw) != expected:
        raise RuntimeValidationError("target identity validation is incomplete")
    result: dict[str, str] = {}
    for variant, digest in raw.items():
        if not isinstance(variant, str) or not isinstance(digest, str) or re.fullmatch(
            r"[0-9a-f]{64}", digest,
        ) is None:
            raise RuntimeValidationError("target identity digest is invalid")
        result[variant] = digest
    return result


def _arm_capability_oracle(
    oracle: CapabilityOracle | None,
    *,
    cve_id: str,
    variant: str,
    target_digest: str,
    candidate_commitment: str,
) -> bytes:
    """Create and arm a fresh host challenge before candidate execution."""
    nonce = secrets.token_bytes(32)
    if oracle is not None:
        oracle.arm(CapabilityOracleArmRequest(
            cve_id=cve_id,
            nonce=nonce,
            variant=variant,
            target_digest=target_digest,
            candidate_commitment=candidate_commitment,
        ))
    return nonce


def _target_digest(
    plan: _ContainerPlan, variant: _Variant, inputs: Mapping[str, _File],
) -> str:
    """Commit the selected control and every byte entering its target build context."""
    files = [
        {
            "destination": destination,
            "sha256": sha256_bytes(inputs[artifact_id].data),
        }
        for artifact_id, destination in plan.files
    ]
    return sha256_bytes(canonical_json({
        "variant": variant.name,
        "dockerfile_artifact_id": variant.dockerfile_artifact_id,
        "container_port": plan.container_port,
        "readiness_path": plan.readiness_path,
        "files": sorted(files, key=lambda item: item["destination"]),
    }))


def _validate_dockerfile(raw: bytes, allowed_images: frozenset[str]) -> None:
    if len(raw) > 256 * 1024 or b"\x00" in raw:
        raise RuntimeValidationError("Dockerfile is oversized or binary")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeValidationError("Dockerfile must be UTF-8") from exc
    logical: list[str] = []
    pending = ""
    for source in text.splitlines():
        stripped = source.strip()
        if not stripped or stripped.startswith("#"):
            if stripped.lower().startswith("# syntax="):
                raise RuntimeValidationError("Dockerfile syntax frontend is forbidden")
            continue
        pending += (" " if pending else "") + stripped
        if pending.endswith("\\"):
            pending = pending[:-1].rstrip()
            continue
        logical.append(pending)
        pending = ""
    if pending:
        logical.append(pending)
    if not logical:
        raise RuntimeValidationError("Dockerfile is empty")
    from_count = 0
    allowed_instructions = {
        "ARG", "CMD", "COPY", "ENTRYPOINT", "ENV", "EXPOSE", "FROM", "LABEL", "USER", "WORKDIR",
    }
    dangerous = re.compile(r"(?i)(--privileged|--security-opt|--device(?:=|\s)|--mount(?:=|\s)|\bmount\s|/dev/)")
    for line in logical:
        parts = line.split(None, 1)
        instruction = parts[0].upper()
        body = parts[1].strip() if len(parts) == 2 else ""
        if instruction not in allowed_instructions:
            raise RuntimeValidationError(f"Dockerfile {instruction} is forbidden")
        if dangerous.search(body):
            raise RuntimeValidationError("Dockerfile contains forbidden privileged/security/device/mount construct")
        if instruction == "COPY" and any(token.startswith("--") for token in body.split()):
            raise RuntimeValidationError("Dockerfile COPY flags are forbidden")
        if instruction == "FROM":
            from_count += 1
            tokens = body.split()
            if len(tokens) not in {1, 3} or (len(tokens) == 3 and tokens[1].upper() != "AS"):
                raise RuntimeValidationError("Dockerfile FROM is invalid")
            if tokens[0] not in allowed_images:
                raise RuntimeValidationError("Dockerfile FROM image is not exactly allowlisted and pinned")
    if from_count != 1:
        raise RuntimeValidationError("Dockerfile requires exactly one allowlisted FROM")


def _validate_oracle(raw: object, cve_id: str) -> dict[str, Any]:
    oracle = _exact_mapping(raw, {"schema", "cve_id", "max_score", "rules"}, "hidden oracle")
    if oracle["schema"] != HIDDEN_SCORE_SCHEMA or oracle["cve_id"] != cve_id:
        raise RuntimeValidationError("hidden oracle schema or CVE mismatch")
    max_score = _positive_number(oracle["max_score"], "max_score")
    rules_raw = _array(oracle["rules"], "rules")
    if len(rules_raw) > 128:
        raise RuntimeValidationError("too many hidden scoring rules")
    rules: list[dict[str, Any]] = []
    ids: set[str] = set()
    total = 0.0
    for raw_rule in rules_raw:
        rule = _mapping(raw_rule, "rule")
        op = rule.get("operator")
        expected_keys = {"id", "stage", "path", "operator", "weight"} | ({"expected"} if op == "equals" else set())
        if set(rule) != expected_keys or op not in {"equals", "truthy", "falsey", "present"}:
            raise RuntimeValidationError("hidden scoring rule has unknown keys or operator")
        identifier = _identifier(rule["id"], "rule.id")
        if identifier in ids:
            raise RuntimeValidationError("duplicate hidden scoring rule ID")
        ids.add(identifier)
        stage = _identifier(rule["stage"], "rule.stage")
        path_raw = _array(rule["path"], "rule.path")
        if not path_raw or len(path_raw) > 16:
            raise RuntimeValidationError("rule path must be a bounded non-empty array")
        path = [_identifier(part, "rule.path component") for part in path_raw]
        weight = _positive_number(rule["weight"], "rule.weight")
        total += weight
        normalized = {"id": identifier, "stage": stage, "path": path, "operator": op, "weight": weight}
        if op == "equals":
            canonical_json(rule["expected"])
            normalized["expected"] = rule["expected"]
        rules.append(normalized)
    if total > max_score:
        raise RuntimeValidationError("rule weights exceed max_score")
    return {"schema": HIDDEN_SCORE_SCHEMA, "cve_id": cve_id, "max_score": max_score, "rules": rules}


def _lookup_public(records: Mapping[str, Mapping[str, object]], stage: str, path: Sequence[str]) -> tuple[bool, object]:
    if stage not in records:
        return False, None
    value: object = records[stage]
    for component in path:
        if not isinstance(value, Mapping) or component not in value:
            return False, None
        value = value[component]
    return True, value


def _evaluate(rule: Mapping[str, Any], present: bool, actual: object) -> bool:
    op = rule["operator"]
    if op == "present":
        return present
    if op == "truthy":
        return present and bool(actual)
    if op == "falsey":
        return present and not bool(actual)
    return present and actual == rule["expected"]


def _candidate_result(raw: bytes) -> dict[str, object]:
    if len(raw) > _MAX_RESULT_BYTES:
        raise RuntimeValidationError("candidate result exceeds limit")
    value = _parse_json(raw, "candidate result")
    result = _exact_mapping(value, {"triggered", "evidence"}, "candidate result")
    if not isinstance(result["triggered"], bool):
        raise RuntimeValidationError("candidate triggered must be boolean")
    evidence = result["evidence"]
    if (
        not isinstance(evidence, str) or not evidence.strip()
        or len(evidence.encode("utf-8")) > 2048
        or any(ord(ch) < 32 and ch not in "\n\t" for ch in evidence)
    ):
        raise RuntimeValidationError("candidate evidence is empty, invalid, or oversized")
    return {"triggered": result["triggered"], "evidence": evidence}


def _safe_read(path: Path, limit: int) -> bytes:
    path = Path(path)
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise RuntimeValidationError("input must be a single-link regular file")
    if info.st_size > limit:
        raise RuntimeValidationError("input file exceeds size limit")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise RuntimeValidationError("input changed while opening")
        data = bytearray()
        while block := os.read(fd, min(1024 * 1024, limit - len(data) + 1)):
            data.extend(block)
            if len(data) > limit:
                raise RuntimeValidationError("input file exceeds size limit")
        if len(data) != info.st_size:
            raise RuntimeValidationError("input changed while reading")
        return bytes(data)
    finally:
        os.close(fd)


def _bounded_json(path: Path, value: object, limit: int) -> None:
    encoded = canonical_json(value)
    if len(encoded) > limit:
        raise RuntimeValidationError("trusted output exceeds size limit")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(encoded)


def _parse_json(raw: bytes, field: str) -> object:
    try:
        return json.loads(raw, parse_constant=lambda value: (_ for _ in ()).throw(RuntimeValidationError(f"{field} contains non-finite number")))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RuntimeValidationError(f"{field} is malformed JSON") from exc


def _record(records: Mapping[str, Mapping[str, object]], stage: str) -> Mapping[str, object]:
    value = records.get(stage)
    if not isinstance(value, Mapping) or value.get("stage") != stage or value.get("status") != "completed":
        raise RuntimeValidationError(f"missing completed {stage} public record")
    return value


def _payload(record: Mapping[str, object], stage: str) -> Mapping[str, Any]:
    return _mapping(record.get("payload"), f"{stage}.payload")


def _payload_list(payload: Mapping[str, object] | None, key: str) -> list[object]:
    if payload is None:
        return []
    value = payload.get(key, [])
    if not isinstance(value, list):
        raise RuntimeValidationError(f"trusted payload {key} must be an array")
    return list(value)


def _mapping(value: object, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RuntimeValidationError(f"{field} must be an object")
    return value


def _exact_mapping(value: object, keys: set[str], field: str) -> Mapping[str, Any]:
    result = _mapping(value, field)
    if set(result) != keys:
        raise RuntimeValidationError(f"{field} has unknown or missing keys")
    return result


def _array(value: object, field: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise RuntimeValidationError(f"{field} must be an array")
    return value


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or not _SAFE_NAME.fullmatch(value) or value in {".", ".."}:
        raise RuntimeValidationError(f"{field} is invalid")
    return value


def _relative_path(value: object, field: str) -> str:
    if not isinstance(value, str) or "\\" in value:
        raise RuntimeValidationError(f"{field} must be a POSIX relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise RuntimeValidationError(f"{field} contains traversal or is not relative")
    return path.as_posix()


def _readiness_path(value: object) -> str:
    if not isinstance(value, str) or not value.startswith("/") or len(value) > 256 or "?" in value or "#" in value or "\\" in value:
        raise RuntimeValidationError("readiness_path must be a bounded absolute URL path")
    parts = PurePosixPath(value).parts
    if any(part in {".", ".."} for part in parts):
        raise RuntimeValidationError("readiness_path contains traversal")
    return value


def _positive_int(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{field} must be a positive integer")
    return value


def _positive_number(value: object, field: str) -> float | int:
    if not isinstance(value, (int, float)) or isinstance(value, bool) or value <= 0 or value != value or value == float("inf"):
        raise ValueError(f"{field} must be a finite positive number")
    return value


def _pinned_image(value: object, field: str) -> str:
    if not isinstance(value, str) or not _DOCKER_DIGEST.fullmatch(value):
        raise ValueError(f"{field} must be an exact digest-pinned image reference")
    return value


def _binary_name(value: object) -> str:
    if not isinstance(value, str) or not value or "/" in value or "\\" in value or not _SAFE_NAME.fullmatch(value):
        raise ValueError("docker_binary must be a fixed executable name")
    return value


def _trusted_argv(argv: Sequence[str]) -> list[str]:
    if isinstance(argv, (str, bytes, bytearray)) or not argv:
        raise ValueError("argv must be a non-empty string sequence")
    result = []
    for item in argv:
        if not isinstance(item, str) or "\x00" in item:
            raise ValueError("argv entries must be NUL-free strings")
        result.append(item)
    return result


def _cap(value: bytes, limit: int) -> tuple[bytes, bool]:
    return (value[:limit], len(value) > limit)


def _operation(argv: Sequence[str]) -> str:
    # Audit only a fixed operation identifier, never attacker-controlled argv.
    return str(argv[1]) if len(argv) > 1 else "unknown"


def _execution_id(run_id: str, parent_sha: str) -> str:
    return sha256_bytes(f"{run_id}:{parent_sha}:container-plan/v1".encode())[:32]


__all__ = [
    "CANDIDATE_PLAN_SCHEMA", "CAPABILITY_RECEIPT_SCHEMA", "CONTAINER_PLAN_SCHEMA", "HIDDEN_SCORE_SCHEMA",
    "CapabilityOracle", "CapabilityOracleArmRequest", "CapabilityOracleObservation", "CapabilityOracleRequest",
    "CommandExecutionError", "CommandResult", "CommandRunner", "ContainerExecutor",
    "HiddenOracleScorer", "RuntimeExecutionError", "RuntimeValidationError",
    "SubprocessCommandRunner",
]
