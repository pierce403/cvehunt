from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import time
from pathlib import Path

import pytest

from cvehunt.stage_harness import (
    DeclaredInput,
    StageHarness,
    StageHarnessError,
    StageRequest,
    StageStatus,
)


def executable(path: Path, source: str) -> Path:
    path.write_text("#!/usr/bin/env python3\n" + source, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def fake_policy_validation(harness: StageHarness, policy: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    policy.write_text('{"research_hosts":["example.com"]}\n', encoding="utf-8")
    monkeypatch.setattr(harness, "_validated_research_policy", lambda: policy)


def all_regular_bytes(root: Path) -> bytes:
    values = []
    for path in root.rglob("*"):
        if path.is_file() and not path.is_symlink():
            values.append(path.read_bytes())
    return b"\n".join(values)


def test_prepare_isolates_and_copies_declared_inputs_read_only(tmp_path: Path) -> None:
    source = tmp_path / "evidence.txt"
    source.write_text("evidence", encoding="utf-8")
    paths = StageHarness(tmp_path / "runs").prepare(
        "research", [DeclaredInput(source, "sources/evidence.txt")]
    )
    copied = paths.input / "sources/evidence.txt"
    assert copied.read_text() == "evidence"
    assert not copied.is_symlink()
    assert copied.resolve() != source.resolve()
    assert copied.stat().st_mode & 0o222 == 0
    assert {p.name for p in (paths.input, paths.workspace, paths.output, paths.log)} == {
        "input", "workspace", "output", "log"
    }


def test_input_traversal_links_special_files_and_sizes_are_rejected(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.write_text("12345", encoding="utf-8")
    harness = StageHarness(tmp_path / "runs", max_input_file_bytes=4)
    with pytest.raises(StageHarnessError, match="unsafe input destination"):
        harness.prepare("traversal", [DeclaredInput(source, "../oracle")])
    with pytest.raises(StageHarnessError, match="size limit"):
        harness.prepare("large", [DeclaredInput(source, "source")])

    link = tmp_path / "link"
    link.symlink_to(source)
    with pytest.raises(StageHarnessError, match="symlink input rejected"):
        harness.prepare("link", [DeclaredInput(link, "input")])

    original = tmp_path / "original"
    original.write_text("x")
    hardlink = tmp_path / "hardlink"
    os.link(original, hardlink)
    with pytest.raises(StageHarnessError, match="hardlink input rejected"):
        StageHarness(tmp_path / "hard-runs").prepare("hard", [DeclaredInput(hardlink, "input")])

    tree = tmp_path / "tree"
    tree.mkdir()
    fifo = tree / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(StageHarnessError, match="non-regular declared input rejected"):
        StageHarness(tmp_path / "fifo-runs").prepare("fifo", [DeclaredInput(tree, "tree")])


def test_input_total_limit_is_enforced(tmp_path: Path) -> None:
    one, two = tmp_path / "one", tmp_path / "two"
    one.write_bytes(b"123")
    two.write_bytes(b"456")
    with pytest.raises(StageHarnessError, match="size limit"):
        StageHarness(tmp_path / "runs", max_input_file_bytes=4, max_input_total_bytes=5).prepare(
            "total", [DeclaredInput(one, "one"), DeclaredInput(two, "two")]
        )


def test_pi_prompt_is_stdin_not_argv_and_metrics_are_incremental(tmp_path: Path) -> None:
    fake = executable(tmp_path / "fake-pi", """
import hashlib, json, os, pathlib, sys
log = pathlib.Path(os.environ['CVEHUNT_STAGE_LOG'])
out = pathlib.Path(os.environ['CVEHUNT_STAGE_OUTPUT'])
prompt = sys.stdin.read()
(log / 'seen.json').write_text(json.dumps({'argv':sys.argv, 'prompt_hash':hashlib.sha256(prompt.encode()).hexdigest(), 'env':dict(os.environ)}))
(out / 'artifact.txt').write_text('artifact')
print(json.dumps({'type':'message_delta','tool_arguments':{'type':'tool_call','usage':{'input_tokens':999999}}}))
print(json.dumps({'type':'tool_call','name':'stage_read'}))
print(json.dumps({'type':'message_end','message':{'role':'assistant','content':[{'type':'text','text':'completed'}], 'usage':{'input_tokens':11,'output_tokens':7,'total_tokens':18}}}))
""")
    extension = tmp_path / "tools.ts"
    extension.write_text("extension")
    prompt = "--private prompt value"
    result = StageHarness(tmp_path / "runs", pi_binary=fake, pi_extension=extension).run(
        StageRequest("author", "pi", "provider/model", prompt, authoring=True, timeout_seconds=5)
    )
    seen = json.loads((result.paths.log / "seen.json").read_text())
    assert prompt not in seen["argv"]
    assert seen["prompt_hash"] == hashlib.sha256(prompt.encode()).hexdigest()
    assert seen["argv"] == [
        str(fake), "-p", "--no-builtin-tools", "--no-extensions", "--no-skills",
        "--no-prompt-templates", "--no-context-files", "--tools", "stage_read,stage_list,stage_write",
        "--no-session", "--mode", "json", "--offline", "--extension", str(extension),
        "--model", "provider/model", "--thinking", "minimal", "@/dev/stdin",
    ]
    assert result.status is StageStatus.SUCCESS
    assert result.response == "completed"
    assert result.metrics == result.metrics.__class__(result.metrics.elapsed_seconds, 11, 7, 18, 1, 0)
    assert result.output_hashes == {"artifact.txt": hashlib.sha256(b"artifact").hexdigest()}
    assert result.native_output_bytes["stdout"] > 0
    assert len(result.native_output_hashes["stdout"]) == 64
    assert (result.paths.log / "events.ndjson").stat().st_size < 1024


def test_huge_native_output_is_streamed_bounded_hashed_and_killed(tmp_path: Path) -> None:
    fake = executable(tmp_path / "noisy-pi", """
import os
block = b'x' * 65536
for _ in range(1024): os.write(1, block)
""")
    result = StageHarness(
        tmp_path / "runs", pi_binary=fake, pi_extension=tmp_path / "x.ts",
        max_native_output_bytes=512 * 1024, max_native_tail_bytes=4096,
        terminate_grace_seconds=0.05,
    ).run(StageRequest("huge", "pi", "m", "prompt", timeout_seconds=5))
    assert result.status is StageStatus.ERROR
    assert "native provider output exceeds" in (result.error or "")
    assert result.native_output_bytes["stdout"] > 512 * 1024
    assert len(result.native_output_hashes["stdout"]) == 64
    assert (result.paths.log / "events.ndjson").stat().st_size <= 4096


def test_output_per_file_total_hardlink_and_special_file_rejection(tmp_path: Path) -> None:
    cases = {
        "large": "out.joinpath('large').write_bytes(b'x'*9); time.sleep(60)",
        "total": "out.joinpath('a').write_bytes(b'12345'); out.joinpath('b').write_bytes(b'67890')",
        "hard": "out.joinpath('a').write_text('x'); os.link(out/'a', out/'b')",
        "fifo": "os.mkfifo(out/'fifo')",
    }
    for name, action in cases.items():
        fake = executable(tmp_path / f"pi-{name}", f"""
import os, pathlib, time
out = pathlib.Path(os.environ['CVEHUNT_STAGE_OUTPUT'])
{action}
print('done')
""")
        result = StageHarness(
            tmp_path / f"runs-{name}", pi_binary=fake, pi_extension=tmp_path / "x.ts",
            max_output_file_bytes=8, max_output_total_bytes=9,
        ).run(StageRequest("stage", "pi", "m", "p", timeout_seconds=5))
        assert result.status is StageStatus.ERROR, name
        assert result.output_hashes == {}, name
        assert any(word in (result.error or "") for word in ("limit", "hardlink", "non-regular", "special")), name


def test_stage_disk_limit_kills_writer(tmp_path: Path) -> None:
    fake = executable(tmp_path / "disk-pi", """
import os, pathlib, time
p = pathlib.Path(os.environ['CVEHUNT_STAGE_WORKSPACE']) / 'growth'
with p.open('wb') as f:
  while True:
    f.write(b'x' * 65536); f.flush()
""")
    result = StageHarness(
        tmp_path / "runs", pi_binary=fake, pi_extension=tmp_path / "x.ts",
        max_stage_disk_bytes=512 * 1024, terminate_grace_seconds=0.05,
    ).run(StageRequest("disk", "pi", "m", "p", timeout_seconds=5))
    assert result.status is StageStatus.ERROR
    assert "disk usage" in (result.error or "")


def test_transport_success_is_not_prose_refusal_and_contract_is_explicit(tmp_path: Path) -> None:
    fake = executable(tmp_path / "pi", "print('I cannot comply with this request')\n")
    harness = StageHarness(tmp_path / "runs", pi_binary=fake, pi_extension=tmp_path / "x.ts")
    prose = harness.run(StageRequest("prose", "pi", "m", "p", timeout_seconds=5))
    refused = harness.run(StageRequest(
        "explicit", "pi", "m", "p", timeout_seconds=5,
        contract=lambda _response, _paths: StageStatus.REFUSAL,
    ))
    assert prose.status is StageStatus.SUCCESS
    assert refused.status is StageStatus.REFUSAL


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("import sys; print('authentication failed', file=sys.stderr); sys.exit(2)", StageStatus.PROVIDER_ERROR),
        ("import sys; print('malformed event', file=sys.stderr); sys.exit(2)", StageStatus.ERROR),
    ],
)
def test_provider_and_transport_errors_are_distinct(tmp_path: Path, source: str, expected: StageStatus) -> None:
    fake = executable(tmp_path / f"pi-{expected.value}", source + "\n")
    result = StageHarness(tmp_path / expected.value, pi_binary=fake, pi_extension=tmp_path / "x.ts").run(
        StageRequest("stage", "pi", "m", "p", timeout_seconds=5)
    )
    assert result.status is expected


def test_preflight_validates_pi_model_and_creates_no_stage(tmp_path: Path) -> None:
    fake = executable(tmp_path / "pi", "print('unused')\n")
    extension = tmp_path / "tools.ts"
    extension.write_text("trusted extension")
    models = tmp_path / "models.json"
    models.write_text(json.dumps({"providers": {"safe": {
        "baseUrl": "https://provider.example/v1", "api": "openai-completions",
        "apiKey": "OPENAI_API_KEY", "models": [{"id": "safe-model"}],
    }}}))
    harness = StageHarness(
        tmp_path / "runs", pi_binary=fake, pi_extension=extension,
        pi_models_source=models, provider_environment={"OPENAI_API_KEY": "secret"},
    )
    summary = harness.preflight(provider="pi", model="safe/safe-model")
    assert summary["provider"] == "pi" and summary["model"] == "safe/safe-model"
    assert all("/" not in value for key, value in summary.items() if key.endswith("sha256"))
    assert not (tmp_path / "runs").exists()
    with pytest.raises(StageHarnessError, match="absent"):
        harness.preflight(provider="pi", model="safe/missing")
    with pytest.raises(StageHarnessError, match="outer OS sandbox"):
        harness.preflight(provider="codex", model="gpt-test")


def test_pi_models_bootstrap_is_sanitized_and_secrets_never_persist(tmp_path: Path) -> None:
    secret = "transport-secret-123"
    models = tmp_path / "models.json"
    models.write_text(json.dumps({"providers": {"safe": {
        "baseUrl": "https://provider.example/v1", "api": "openai-completions",
        "apiKey": "OPENAI_API_KEY", "models": [{"id": "safe-model"}],
    }}}))
    fake = executable(tmp_path / "pi", """
import os
assert os.environ['OPENAI_API_KEY']
print('transport credential present')
""")
    result = StageHarness(
        tmp_path / "runs", pi_binary=fake, pi_extension=tmp_path / "x.ts",
        pi_models_source=models, provider_environment={"OPENAI_API_KEY": secret},
    ).run(StageRequest("stage", "pi", "safe/safe-model", "p", timeout_seconds=5))
    copied = result.paths.config / "pi" / "models.json"
    assert copied.is_file() and copied.stat().st_mode & 0o077 == 0
    assert b"OPENAI_API_KEY" in copied.read_bytes()
    assert secret.encode() not in all_regular_bytes(result.paths.root)
    assert result.status is StageStatus.SUCCESS

    literal = tmp_path / "literal.json"
    literal.write_text(models.read_text().replace("OPENAI_API_KEY", secret))
    with pytest.raises(StageHarnessError, match="apiKey must reference"):
        StageHarness(
            tmp_path / "bad", pi_models_source=literal,
            provider_environment={"OPENAI_API_KEY": secret},
        ).prepare("stage")


def test_credential_exfiltration_to_stage_is_removed_and_fails_closed(tmp_path: Path) -> None:
    secret = "never-persist-this"
    fake = executable(tmp_path / "pi", """
import os, pathlib
(pathlib.Path(os.environ['CVEHUNT_STAGE_OUTPUT']) / 'leak').write_text(os.environ['OPENAI_API_KEY'])
print('ok')
""")
    result = StageHarness(
        tmp_path / "runs", pi_binary=fake, pi_extension=tmp_path / "x.ts",
        provider_environment={"OPENAI_API_KEY": secret},
    ).run(StageRequest("stage", "pi", "m", "p", timeout_seconds=5))
    assert result.status is StageStatus.ERROR
    assert result.output_hashes == {}
    assert secret.encode() not in all_regular_bytes(result.paths.root)


def test_research_requires_root_owned_policy_and_extension_has_hostname_controls(tmp_path: Path) -> None:
    policy = tmp_path / "policy.json"
    policy.write_text('{"research_hosts":["example.com"]}')
    harness = StageHarness(tmp_path / "runs", research_policy_file=policy)
    with pytest.raises(StageHarnessError, match="root-owned"):
        harness.run(StageRequest("research", "pi", "m", "p", research=True))

    extension = (Path(__file__).parents[1] / "scripts" / "pi_cvehunt_stage_tools.ts").read_text()
    assert "researchHosts.has(host)" in extension
    assert "answers.some((answer) => isForbiddenAddress(answer.address))" in extension
    assert "dns.promises.resolve4(host)" in extension and "dns.promises.lookup" not in extension
    assert 'hostname: answer.address' in extension and "servername: host" in extension
    assert "redirects are rejected" in extension
    assert "parsed.toString()" not in extension
    log_function = extension[extension.index("async function logNetwork"):extension.index("async function retrieve")]
    assert "rawUrl" not in log_function
    audit_function = extension[extension.index("function auditTarget"):extension.index("async function logNetwork")]
    assert "path_sha256" in audit_function and "parsed.search" not in audit_function


def test_research_environment_references_validated_policy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = executable(tmp_path / "pi", """
import json, os, pathlib
(pathlib.Path(os.environ['CVEHUNT_STAGE_LOG'])/'policy-seen').write_text(os.environ['CVEHUNT_STAGE_POLICY'])
print('ok')
""")
    policy = tmp_path / "policy.json"
    harness = StageHarness(tmp_path / "runs", pi_binary=fake, pi_extension=tmp_path / "x.ts", research_policy_file=policy)
    fake_policy_validation(harness, policy, monkeypatch)
    result = harness.run(StageRequest("research", "pi", "m", "p", research=True, timeout_seconds=5))
    assert (result.paths.log / "policy-seen").read_text() == str(policy)


def test_network_metrics_are_stream_counted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = executable(tmp_path / "pi", """
import os, pathlib
p = pathlib.Path(os.environ['CVEHUNT_STAGE_LOG']) / 'network.ndjson'
p.write_text('{"request_id":"one","outcome":"started","origin":"https://one.example","path_sha256":"a"}\\n{"request_id":"one","outcome":"completed","origin":"https://one.example","path_sha256":"a"}\\n')
print('ok')
""")
    policy = tmp_path / "policy.json"
    harness = StageHarness(tmp_path / "runs", pi_binary=fake, pi_extension=tmp_path / "x.ts", research_policy_file=policy)
    fake_policy_validation(harness, policy, monkeypatch)
    result = harness.run(StageRequest("research", "pi", "m", "p", research=True, timeout_seconds=5))
    assert result.metrics.network_requests == 1


def test_codex_remains_fail_closed_and_prompt_uses_stdin(tmp_path: Path) -> None:
    fake = executable(tmp_path / "codex", """
import json, os, pathlib, sys
args = sys.argv[1:]
pathlib.Path(args[args.index('--output-last-message') + 1]).write_text('codex answer')
(pathlib.Path(os.environ['CVEHUNT_STAGE_LOG'])/'seen.json').write_text(json.dumps({'argv':sys.argv,'stdin':sys.stdin.read()}))
print('{"usage":{"input_tokens":3,"output_tokens":2}}')
""")
    harness = StageHarness(tmp_path / "runs", codex_binary=fake)
    paths = harness.prepare("blocked")
    with pytest.raises(StageHarnessError, match="does not guarantee host read isolation"):
        harness.build_argv(StageRequest("blocked", "codex", "gpt-test", "prompt"), paths)
    result = harness.run(StageRequest(
        "codex", "codex", "gpt-test", "prompt", timeout_seconds=5,
        allow_codex_residual_read_risk=True,
    ))
    seen = json.loads((result.paths.log / "seen.json").read_text())
    assert seen["stdin"] == "prompt"
    assert "prompt" not in seen["argv"]
    assert result.response == "codex answer"
    assert result.metrics.total_tokens == 5


def test_timeout_kills_entire_process_group(tmp_path: Path) -> None:
    fake = executable(tmp_path / "slow-pi", """
import os, pathlib, signal, subprocess, sys, time
child = subprocess.Popen([sys.executable, '-c', 'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)'])
(pathlib.Path(os.environ['CVEHUNT_STAGE_LOG'])/'child.pid').write_text(str(child.pid))
signal.signal(signal.SIGTERM, signal.SIG_IGN)
time.sleep(60)
""")
    result = StageHarness(
        tmp_path / "runs", pi_binary=fake, pi_extension=tmp_path / "x.ts", terminate_grace_seconds=0.05,
    ).run(StageRequest("timeout", "pi", "m", "p", timeout_seconds=0.15))
    child_pid = int((result.paths.log / "child.pid").read_text())
    assert result.status is StageStatus.TIMEOUT
    deadline = time.monotonic() + 2
    state = ""
    while time.monotonic() < deadline:
        try:
            state = Path(f"/proc/{child_pid}/stat").read_text().split()[2]
        except FileNotFoundError:
            state = "gone"
            break
        if state == "Z":
            break
        time.sleep(0.02)
    assert state in {"gone", "Z"}


def test_real_pi_loads_extension_and_parses_cli_without_provider_request(tmp_path: Path) -> None:
    pi = shutil.which("pi")
    if not pi:
        pytest.skip("Pi CLI is not installed")
    extension = Path(__file__).parents[1] / "scripts" / "pi_cvehunt_stage_tools.ts"
    roots = {name: tmp_path / name for name in ("input", "workspace", "output", "log", "home", "config", "sessions")}
    for root in roots.values():
        root.mkdir()
    env = {
        "PATH": os.environ.get("PATH", os.defpath), "HOME": str(roots["home"]),
        "PI_CODING_AGENT_DIR": str(roots["config"]), "PI_CODING_AGENT_SESSION_DIR": str(roots["sessions"]),
        "PI_OFFLINE": "1", "PI_TELEMETRY": "0",
        "CVEHUNT_STAGE_INPUT": str(roots["input"]), "CVEHUNT_STAGE_WORKSPACE": str(roots["workspace"]),
        "CVEHUNT_STAGE_OUTPUT": str(roots["output"]), "CVEHUNT_STAGE_LOG": str(roots["log"]),
        "CVEHUNT_STAGE_AUTHORING": "0", "CVEHUNT_STAGE_RESEARCH": "0",
        "CVEHUNT_STAGE_MAX_WRITE_BYTES": "1024",
    }
    command = [
        pi, "-p", "--offline", "--no-builtin-tools", "--no-extensions", "--no-skills",
        "--no-prompt-templates", "--no-context-files", "--tools", "stage_read,stage_list",
        "--no-session", "--mode", "json", "--extension", str(extension),
        "--model", "definitely-not-a-provider/definitely-not-a-model", "@/dev/stdin",
    ]
    completed = subprocess.run(command, input="validation only", text=True, capture_output=True, env=env, timeout=30)
    assert completed.returncode != 0
    assert "not found" in completed.stderr.lower()
    assert "extension" not in completed.stderr.lower()
    assert "api" not in completed.stderr.lower() or "api key" not in completed.stderr.lower()

    # Removing a required boundary makes module initialization fail before any
    # model lookup/request, proving the real CLI actually loaded the extension.
    missing_boundary = dict(env)
    del missing_boundary["CVEHUNT_STAGE_INPUT"]
    load_failure = subprocess.run(
        command, input="validation only", text=True, capture_output=True,
        env=missing_boundary, timeout=30,
    )
    assert load_failure.returncode != 0
    assert "missing stage boundary CVEHUNT_STAGE_INPUT" in load_failure.stderr


def test_extension_surface_and_stage_write_limit_are_explicit() -> None:
    extension = (Path(__file__).parents[1] / "scripts" / "pi_cvehunt_stage_tools.ts").read_text()
    assert extension.count("pi.registerTool({") == 4
    for name in ("stage_read", "stage_list", "stage_write", "https_retrieve"):
        assert f'name: "{name}"' in extension
    assert 'name: "bash"' not in extension and "child_process" not in extension
    assert "CVEHUNT_STAGE_MAX_WRITE_BYTES" in extension
    assert "Buffer.byteLength(args.content" in extension
    assert "info.nlink > 1" in extension
    assert "crypto.randomUUID()" in extension and "request_id: requestId" in extension
    assert 'content_sha256: crypto.createHash("sha256").update(rawBody).digest("hex")' in extension
