from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

import pytest

import cvehunt.pipeline_runtime as pipeline_runtime

from cvehunt.agent_pipeline import TrustedCallbackContext, TrustedInput
from cvehunt.pipeline_runtime import (
    CAPABILITY_RECEIPT_SCHEMA,
    CapabilityOracleArmRequest,
    CapabilityOracleObservation,
    CapabilityOracleRequest,
    CommandResult,
    ContainerExecutor,
    HiddenOracleScorer,
    RuntimeExecutionError,
    RuntimeValidationError,
    SubprocessCommandRunner,
)
from cvehunt.stage_contracts import canonical_json

BASE = "python:3.12@sha256:" + "1" * 64
RUNNER = "python:3.12-alpine@sha256:" + "2" * 64
CVE = "CVE-2026-12345"
PARENT = "a" * 64
RECEIPT_KEYS = {
    "schema", "cve_id", "variant", "trusted_result", "candidate_commitment",
    "target_digest", "oracle_digest", "nonce_commitment",
    "observed_interaction_commitment", "execution_result",
    "infrastructure_disposition", "evidence_sha256", "evidence_bytes",
}


@dataclass
class FakeRunner:
    fail_operation: str | None = None
    rootless: bool = True
    calls: list[tuple[tuple[str, ...], bytes | None, float, int]] = field(default_factory=list)
    built_app_bytes: list[bytes] = field(default_factory=list)

    def run(self, argv, *, timeout_seconds, max_output_bytes, input_data=None):
        args = tuple(argv)
        self.calls.append((args, input_data, timeout_seconds, max_output_bytes))
        operation = args[1]
        if operation == "build":
            self.built_app_bytes.append((Path(args[-1]) / "app.py").read_bytes())
        if operation == "info":
            stdout = json.dumps(["name=rootless"] if self.rootless else ["name=seccomp"]).encode()
        elif "/candidate/candidate.py" in args:
            variant = "patched" if any("patched" in item for item in args) else "vulnerable"
            stdout = json.dumps({"triggered": variant == "vulnerable", "evidence": f"bounded-{variant}"}).encode()
        else:
            stdout = b""
        return CommandResult(args, 7 if operation == self.fail_operation else 0, stdout, b"")


@dataclass
class FakeCapabilityOracle:
    cve_id: str = CVE
    oracle_sha256: str = "9" * 64
    requests: list[CapabilityOracleRequest] = field(default_factory=list)
    armed: list[CapabilityOracleArmRequest] = field(default_factory=list)

    def arm(self, request: CapabilityOracleArmRequest) -> None:
        self.armed.append(request)

    def observe(self, request: CapabilityOracleRequest) -> CapabilityOracleObservation:
        assert self.armed
        armed = self.armed[-1]
        assert request.nonce == armed.nonce
        assert request.variant == armed.variant
        assert request.target_digest == armed.target_digest
        assert request.candidate_commitment == armed.candidate_commitment
        self.requests.append(request)
        proved = request.variant == "vulnerable"
        interaction = b"host-observed-capability" if proved else b"host-observed-negative-control"
        return CapabilityOracleObservation(proved, interaction)


def artifact(tmp_path: Path, artifact_id: str, data: bytes) -> TrustedInput:
    path = tmp_path / artifact_id
    path.write_bytes(data)
    return TrustedInput(artifact_id, hashlib.sha256(data).hexdigest(), path)


def plans() -> tuple[dict, dict]:
    harness = {
        "target_class": "service",
        "backend": "docker",
        "variants": [],
        "services": [],
        "commands": [],
        "safety": {},
        "container_plan": {
            "schema": "cvehunt.container-plan/v1",
            "files": [
                {"artifact_id": "docker-v", "destination": "docker/Dockerfile.vulnerable"},
                {"artifact_id": "docker-p", "destination": "docker/Dockerfile.patched"},
                {"artifact_id": "app", "destination": "app.py"},
            ],
            "variants": [
                {"name": "vulnerable", "dockerfile_artifact_id": "docker-v"},
                {"name": "patched", "dockerfile_artifact_id": "docker-p"},
            ],
            "container_port": 8080,
            "readiness_path": "/ready",
        },
    }
    exploiter = {
        "hypothesis_ids": [],
        "candidate": {
            "schema": "cvehunt.candidate-plan/v1",
            "artifact_id": "candidate",
            "runtime": "python",
            "timeout_seconds": 10,
            "args": ["--fixed", "value"],
            "data": {"probe": "fixed"},
        },
        "derivation": {},
        "runtime_requirements": {},
    }
    return harness, exploiter


def context(
    tmp_path: Path,
    *,
    harness: dict | None = None,
    exploiter: dict | None = None,
    remaining_run_seconds: float = 7200.0,
):
    default_harness, default_exploiter = plans()
    dockerfile = f"FROM {BASE}\nCOPY app.py /app/app.py\nCMD [\"python\",\"/app/app.py\"]\n".encode()
    inputs = (
        artifact(tmp_path, "docker-v", dockerfile),
        artifact(tmp_path, "docker-p", dockerfile),
        artifact(tmp_path, "app", b"print('service')\n"),
        artifact(tmp_path, "candidate", b"import json; print(json.dumps({'triggered':False,'evidence':'x'}))\n"),
    )
    records = {
        "harness_builder": {"stage": "harness_builder", "status": "completed", "payload": harness or default_harness},
        "exploiter": {"stage": "exploiter", "status": "completed", "payload": exploiter or default_exploiter},
    }
    return TrustedCallbackContext(
        "run-1", CVE, "exploiter", PARENT, {}, inputs, records,
        remaining_run_seconds,
    )


def executor(runner: FakeRunner, *, oracle=None) -> ContainerExecutor:
    return ContainerExecutor(
        allowed_base_images=[BASE], python_runner_image=RUNNER, runner=runner,
        capability_oracle=oracle,
    )


def evidence_context(tmp_path: Path, *, mode: str, fix_payload: dict | None = None) -> TrustedCallbackContext:
    tmp_path.mkdir(parents=True, exist_ok=True)
    base = context(tmp_path)
    challenge = artifact(tmp_path, "challenge", b"print('challenge')\n")
    replacement = artifact(tmp_path, "replacement", b"print('fixed')\n")
    adversarial = {
        "round_budget": 1, "rounds": [], "rounds_executed": 1, "stop_reason": "complete",
        "adversarial_plan": {
            "schema": "cvehunt.adversarial-plan/v1",
            "rounds": [{
                "id": "round-1", "artifact_id": "challenge", "runtime": "python",
                "timeout_seconds": 10, "args": ["--bounded"], "data": {"probe": 1},
            }],
        },
    }
    fix = fix_payload or {
        "root_cause": {}, "patch": {}, "security_invariant": "safe",
        "expected_behavior": {}, "limitations": [],
        "fix_plan": {"schema": "cvehunt.fix-plan/v1", "replacements": [
            {"artifact_id": "replacement", "destination": "app.py"},
        ]},
    }
    records = dict(base.public_stage_records)
    records.update({
        "provision_execution": {"stage": "provision_execution", "status": "completed", "payload": {"receipt": True}},
        "adversarial_loop": {"stage": "adversarial_loop", "status": "completed", "payload": adversarial},
        "adversarial_execution": {"stage": "adversarial_execution", "status": "completed", "payload": {"receipt": True}},
        "fix_developer": {"stage": "fix_developer", "status": "completed", "payload": fix},
    })
    predecessor = "adversarial_loop" if mode == "adversarial" else "fix_developer"
    return TrustedCallbackContext(
        base.run_id, base.cve_id, predecessor, PARENT, {},
        (*base.inputs, challenge, replacement), records,
    )


def test_fixed_argv_internal_network_and_containment(tmp_path: Path) -> None:
    fake = FakeRunner()
    output = tmp_path / "output"
    output.mkdir()
    result = executor(fake).provision_and_execute(context=context(tmp_path), output_dir=output)
    receipts = result.payload["candidate_runs"]
    assert isinstance(receipts, list)
    assert [item["variant"] for item in receipts] == ["vulnerable", "patched"]
    assert all(item["trusted_result"] is False for item in receipts)
    assert len({item["candidate_commitment"] for item in receipts}) == 1
    assert all(set(item) == RECEIPT_KEYS for item in receipts)
    assert all(item["schema"] == CAPABILITY_RECEIPT_SCHEMA for item in receipts)
    assert all(item["cve_id"] == CVE and item["oracle_digest"] is None for item in receipts)
    assert len({item["nonce_commitment"] for item in receipts}) == 2
    assert len({item["target_digest"] for item in receipts}) == 2
    assert all(item["execution_result"]["status"] == "completed" for item in receipts)
    calls = [call[0] for call in fake.calls]
    assert calls[0] == ("docker", "info", "--format", "{{json .SecurityOptions}}")
    inspected = [call[-1] for call in calls if call[:3] == ("docker", "image", "inspect")]
    assert inspected[:2] == sorted([BASE, RUNNER])
    assert any(call[:4] == ("docker", "network", "create", "--internal") for call in calls)
    builds = [call for call in calls if call[1] == "build"]
    assert len(builds) == 2
    assert all("--network=none" in call and "--pull=false" in call for call in builds)
    creates = [call for call in calls if call[1] == "create"]
    assert len(creates) == 2
    assert all("--read-only" in call and ("--cap-drop", "ALL") == call[call.index("--cap-drop"):call.index("--cap-drop") + 2] for call in creates)
    assert all("--publish" not in call and "-p" not in call and "--mount" not in call for call in creates)
    candidate_calls = [call for call in calls if "/candidate/candidate.py" in call]
    assert len(candidate_calls) == 2
    assert all(call.count("--mount") == 1 and "--network" in call and "--env" in call for call in candidate_calls)
    assert all("python" in call and "-I" in call and "--fixed" in call for call in candidate_calls)
    # The candidate sees one invariant DNS alias regardless of the hidden control.
    # Runtime object names are fresh and must not encode vulnerable/patched identity.
    assert all("CVEHUNT_TARGET=http://target:8080" in call for call in candidate_calls)
    runtime_names = [
        call[call.index("--name") + 1]
        for call in calls
        if "--name" in call
    ]
    assert runtime_names and all(
        "vulnerable" not in name and "patched" not in name and "fixed" not in name
        for name in runtime_names
    )
    target_connects = [call for call in calls if call[1:3] == ("network", "connect")]
    assert len(target_connects) == 2
    assert all(call[3:5] == ("--alias", "target") for call in target_connects)
    assert not any("/bin/sh" in call or "sh" in call for call in calls)
    assert {path.name for path in output.iterdir()} == {"execution-summary.json", "execution-audit.json"}
    assert [item.classification for item in result.artifacts] == ["public_summary", "local_audit"]
    public = (output / "execution-summary.json").read_text()
    assert "candidate.py" not in public and "stdout" not in public
    assert "bounded-vulnerable" not in public and "internal_url" not in public
    public_data = json.loads(public)
    assert public_data["candidate_runs"][0]["trusted_result"] is False
    assert len(public_data["candidate_runs"][0]["candidate_commitment"]) == 64
    assert len(public_data["candidate_runs"][0]["evidence_sha256"]) == 64


def test_cve_specific_oracle_creates_nonce_bound_host_receipt(tmp_path: Path) -> None:
    fake = FakeRunner()
    oracle = FakeCapabilityOracle()
    output = tmp_path / "output"
    output.mkdir()

    result = executor(fake, oracle=oracle).provision_and_execute(
        context=context(tmp_path), output_dir=output,
    )

    receipts = result.payload["candidate_runs"]
    assert [item["trusted_result"] for item in receipts] == [True, False]
    assert all(item["oracle_digest"] == oracle.oracle_sha256 for item in receipts)
    assert len(oracle.armed) == 2
    assert len(oracle.requests) == 2
    assert len({request.nonce for request in oracle.requests}) == 2
    assert all(len(request.nonce) == 32 for request in oracle.requests)
    assert [request.variant for request in oracle.requests] == ["vulnerable", "patched"]
    assert all(request.cve_id == CVE for request in oracle.requests)
    assert all(request.candidate_stdout.startswith(b"{") for request in oracle.requests)
    assert [request.nonce for request in oracle.armed] == [request.nonce for request in oracle.requests]
    assert receipts[0]["nonce_commitment"] == hashlib.sha256(oracle.requests[0].nonce).hexdigest()
    assert receipts[0]["observed_interaction_commitment"] == hashlib.sha256(canonical_json({
        "nonce_sha256": hashlib.sha256(oracle.requests[0].nonce).hexdigest(),
        "observation_sha256": hashlib.sha256(b"host-observed-capability").hexdigest(),
    })).hexdigest()
    assert receipts[0]["target_digest"] == oracle.requests[0].target_digest
    assert receipts[0]["execution_result"]["commitment"] == oracle.requests[0].execution_result_commitment


def test_wrong_cve_or_invalid_oracle_fails_before_runner_side_effects(tmp_path: Path) -> None:
    oracles = (
        FakeCapabilityOracle(cve_id="CVE-2026-99999"),
        FakeCapabilityOracle(oracle_sha256="not-a-digest"),
    )
    for index, oracle in enumerate(oracles):
        root = tmp_path / str(index)
        output = root / "output"
        output.mkdir(parents=True)
        fake = FakeRunner()
        with pytest.raises(RuntimeValidationError, match="oracle"):
            executor(fake, oracle=oracle).provision_and_execute(
                context=context(root), output_dir=output,
            )
        assert fake.calls == []


def test_complete_attempt_deadline_caps_every_executor_command(tmp_path: Path) -> None:
    fake = FakeRunner()
    output = tmp_path / "output"
    output.mkdir()
    executor(fake).provision_and_execute(
        context=context(tmp_path, remaining_run_seconds=0.05), output_dir=output
    )
    assert fake.calls
    assert all(0 < call[2] <= 0.05 for call in fake.calls)


def test_runtime_reserves_deadline_budget_for_bounded_cleanup(monkeypatch) -> None:
    class Clock:
        value = 100.0

        def __call__(self):
            return self.value

    clock = Clock()
    monkeypatch.setattr(pipeline_runtime.time, "monotonic", clock)
    fake = FakeRunner()
    bounded = executor(fake)
    audit = []

    with pipeline_runtime._runtime_deadline(100.0):
        bounded._command(("docker", "info"), audit)
        assert fake.calls[-1][2] == pytest.approx(80.0)
        clock.value = 181.0
        with pytest.raises(pipeline_runtime.CommandExecutionError, match="deadline"):
            bounded._command(("docker", "info"), audit)
        before_cleanup = len(fake.calls)
        failures = []
        bounded._cleanup(
            ("docker", "rm", "--force", "opaque"), "container", failures, audit,
        )

    assert len(fake.calls) == before_cleanup + 1
    assert 0 < fake.calls[-1][2] <= 19.0
    assert failures == []


@pytest.mark.parametrize("remaining", [0, -1, float("nan"), float("inf")])
def test_exhausted_deadline_has_zero_runner_side_effects(
    tmp_path: Path, remaining: float
) -> None:
    fake = FakeRunner()
    output = tmp_path / "output"
    output.mkdir()
    with pytest.raises(RuntimeValidationError, match="deadline"):
        executor(fake).provision_and_execute(
            context=context(tmp_path, remaining_run_seconds=remaining), output_dir=output
        )
    assert fake.calls == []


def test_adversarial_and_fix_use_fixed_candidate_runner_and_public_hashes(tmp_path: Path) -> None:
    adversarial_runner = FakeRunner()
    adversarial_out = tmp_path / "adversarial-out"
    adversarial_out.mkdir()
    adversarial = executor(adversarial_runner).execute_adversarial(
        context=evidence_context(tmp_path / "a", mode="adversarial"), output_dir=adversarial_out,
    )
    assert len(adversarial.payload["adversarial_runs"]) == 2
    assert all("evidence" not in item for item in adversarial.payload["adversarial_runs"])
    candidate_calls = [call[0] for call in adversarial_runner.calls if "/candidate/candidate.py" in call[0]]
    assert len(candidate_calls) == 2
    assert all("python" in call and "-I" in call and call.count("--mount") == 1 for call in candidate_calls)
    assert all("CVEHUNT_TARGET=http://target:8080" in call for call in candidate_calls)
    adversarial_names = [
        call[0][call[0].index("--name") + 1]
        for call in adversarial_runner.calls
        if "--name" in call[0]
    ]
    assert adversarial_names and all(
        "vulnerable" not in name and "patched" not in name and "fixed" not in name
        for name in adversarial_names
    )
    public = json.loads((adversarial_out / "adversarial-execution-summary.json").read_text())
    assert set(public["runs"][0]) == RECEIPT_KEYS
    assert all(item["trusted_result"] is False for item in public["runs"])
    assert "bounded-" not in json.dumps(public)

    fix_runner = FakeRunner()
    fix_out = tmp_path / "fix-out"
    fix_out.mkdir()
    fixed = executor(fix_runner).execute_fix(
        context=evidence_context(tmp_path / "f", mode="fix"), output_dir=fix_out,
    )
    assert fix_runner.built_app_bytes == [b"print('fixed')\n"]
    fixed_receipts = fixed.payload["candidate_runs"]
    assert isinstance(fixed_receipts, list)
    assert len(fixed_receipts) == 2
    assert len({item["candidate_commitment"] for item in fixed_receipts}) == 2
    assert all(item["trusted_result"] is False for item in fixed_receipts)
    fix_commitment = fixed.payload["fix_commitment"]
    assert isinstance(fix_commitment, str) and len(fix_commitment) == 64
    assert all(character in "0123456789abcdef" for character in fix_commitment)
    assert len([call for call in fix_runner.calls if "/candidate/candidate.py" in call[0]]) == 2
    serialized = (fix_out / "fix-execution-summary.json").read_text()
    public_fix = json.loads(serialized)
    assert public_fix["fix_commitment"] == fix_commitment
    assert "bounded-" not in serialized and "internal_url" not in serialized and "candidate_id" not in serialized


def test_fixed_target_receipt_binds_the_exact_fix_commitment(tmp_path: Path) -> None:
    initial_oracle = FakeCapabilityOracle()
    initial_inputs = tmp_path / "initial-inputs"
    initial_inputs.mkdir()
    initial_out = tmp_path / "initial-out"
    initial_out.mkdir()
    initial = executor(FakeRunner(), oracle=initial_oracle).provision_and_execute(
        context=context(initial_inputs), output_dir=initial_out,
    )
    vulnerable = initial.payload["candidate_runs"][0]

    fixed_oracle = FakeCapabilityOracle()
    fixed_out = tmp_path / "fixed-out"
    fixed_out.mkdir()
    fixed = executor(FakeRunner(), oracle=fixed_oracle).execute_fix(
        context=evidence_context(tmp_path / "fixed-inputs", mode="fix"),
        output_dir=fixed_out,
    )
    fixed_receipt = fixed.payload["candidate_runs"][0]

    assert fixed_receipt["candidate_commitment"] == vulnerable["candidate_commitment"]
    assert fixed_receipt["target_digest"] != vulnerable["target_digest"]
    assert fixed_receipt["target_digest"] == fixed_oracle.armed[0].target_digest
    assert fixed.payload["fix_commitment"] is not None


def test_fix_overlay_rejects_unknown_traversal_duplicate_and_dockerfile(tmp_path: Path) -> None:
    base_fix = {
        "root_cause": {}, "patch": {}, "security_invariant": "safe", "expected_behavior": {}, "limitations": [],
        "fix_plan": {"schema": "cvehunt.fix-plan/v1", "replacements": []},
    }
    bad_replacements = [
        [{"artifact_id": "replacement", "destination": "new.py"}],
        [{"artifact_id": "replacement", "destination": "../app.py"}],
        [
            {"artifact_id": "replacement", "destination": "app.py"},
            {"artifact_id": "replacement", "destination": "app.py"},
        ],
        [{"artifact_id": "replacement", "destination": "docker/Dockerfile.vulnerable"}],
    ]
    for index, replacements in enumerate(bad_replacements):
        payload = json.loads(json.dumps(base_fix))
        payload["fix_plan"]["replacements"] = replacements
        root = tmp_path / str(index)
        out = root / "out"
        out.mkdir(parents=True)
        fake = FakeRunner()
        with pytest.raises(RuntimeValidationError):
            executor(fake).execute_fix(
                context=evidence_context(root / "inputs", mode="fix", fix_payload=payload), output_dir=out,
            )
        assert fake.calls == []


def test_bounded_execution_failure_cleans_up_and_raises(tmp_path: Path) -> None:
    fake = FakeRunner(fail_operation="build")
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(RuntimeExecutionError):
        executor(fake).execute_adversarial(
            context=evidence_context(tmp_path / "inputs", mode="adversarial"), output_dir=out,
        )
    operations = [call[0][1] for call in fake.calls]
    assert "network" in operations[operations.index("build") + 1:]
    assert "image" in operations[operations.index("build") + 1:]


def test_rootless_required_and_explicit_opt_out(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="explicit"):
        ContainerExecutor(
            allowed_base_images=[BASE], python_runner_image=RUNNER,
            require_rootless=False,
        )
    ContainerExecutor(
        allowed_base_images=[BASE], python_runner_image=RUNNER,
        require_rootless=False, administrator_allow_non_rootless=True,
    )
    output = tmp_path / "out"
    output.mkdir()
    with pytest.raises(RuntimeExecutionError) as caught:
        executor(FakeRunner(rootless=False)).provision_and_execute(
            context=context(tmp_path), output_dir=output
        )
    assert "rootless" in str(caught.value.primary)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda h, e: h["container_plan"].update(extra=True),
        lambda h, e: h["container_plan"]["files"][0].update(destination="../Dockerfile"),
        lambda h, e: h["container_plan"]["variants"].pop(),
        lambda h, e: e["candidate"].update(runtime="shell"),
        lambda h, e: e["candidate"].update(command="id"),
        lambda h, e: e["candidate"].update(timeout_seconds=61),
    ],
)
def test_schema_unknown_key_path_runtime_and_timeout_rejected_before_commands(tmp_path: Path, mutation) -> None:
    harness, exploiter = plans()
    mutation(harness, exploiter)
    fake = FakeRunner()
    output = tmp_path / "out"
    output.mkdir()
    with pytest.raises(RuntimeValidationError):
        executor(fake).provision_and_execute(
            context=context(tmp_path, harness=harness, exploiter=exploiter), output_dir=output
        )
    assert fake.calls == []


@pytest.mark.parametrize(
    "line",
    [
        "# syntax=docker/dockerfile:1\n",
        "FROM evil.example/x@sha256:" + "3" * 64 + "\n",
        f"FROM {BASE}\nRUN --mount=type=secret echo x\n",
        f"FROM {BASE}\nRUN echo ordinary-build-code\n",
        f"FROM {BASE}\nONBUILD RUN true\n",
        f"FROM {BASE}\nVOLUME /data\n",
        f"FROM {BASE}\nADD https://example.test/x /x\n",
        f"FROM {BASE}\nADD local.tar /x\n",
        f"FROM {BASE}\nCOPY --from=other /x /x\n",
        f"FROM --platform=linux/amd64 {BASE}\n",
        f"FROM {BASE}\nFROM {BASE}\n",
        f"FROM {BASE}\nRUN mount /dev/x /x\n",
    ],
)
def test_dockerfile_policy_rejected(tmp_path: Path, line: str) -> None:
    ctx = context(tmp_path)
    Path(ctx.inputs[0].path).write_text(line)
    changed = list(ctx.inputs)
    changed[0] = TrustedInput("docker-v", hashlib.sha256(line.encode()).hexdigest(), ctx.inputs[0].path)
    ctx = TrustedCallbackContext(ctx.run_id, ctx.cve_id, ctx.predecessor_stage, ctx.predecessor_handoff_sha256,
                                 ctx.predecessor_envelope, tuple(changed), ctx.public_stage_records)
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(RuntimeValidationError):
        executor(FakeRunner()).provision_and_execute(context=ctx, output_dir=out)


def test_hash_symlink_hardlink_and_oversize_rejected(tmp_path: Path) -> None:
    for kind in ("hash", "symlink", "hardlink", "oversize"):
        root = tmp_path / kind
        root.mkdir()
        ctx = context(root)
        items = list(ctx.inputs)
        candidate = Path(items[-1].path)
        if kind == "hash":
            items[-1] = TrustedInput("candidate", "0" * 64, candidate)
        elif kind == "symlink":
            original = root / "original"
            candidate.rename(original)
            candidate.symlink_to(original)
        elif kind == "hardlink":
            os.link(candidate, root / "other")
        else:
            candidate.write_bytes(b"x" * 1025)
            items[-1] = TrustedInput("candidate", hashlib.sha256(candidate.read_bytes()).hexdigest(), candidate)
        changed = TrustedCallbackContext(ctx.run_id, ctx.cve_id, ctx.predecessor_stage, ctx.predecessor_handoff_sha256,
                                         ctx.predecessor_envelope, tuple(items), ctx.public_stage_records)
        out = root / "out"
        out.mkdir()
        limited = ContainerExecutor(allowed_base_images=[BASE], python_runner_image=RUNNER,
                                    runner=FakeRunner(), max_artifact_bytes=1024)
        with pytest.raises(RuntimeValidationError):
            limited.provision_and_execute(context=changed, output_dir=out)


def test_cleanup_runs_on_build_failure_and_primary_is_preserved(tmp_path: Path) -> None:
    fake = FakeRunner(fail_operation="build")
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(RuntimeExecutionError) as caught:
        executor(fake).provision_and_execute(context=context(tmp_path), output_dir=out)
    operations = [call[0][1] for call in fake.calls]
    assert operations[:3] == ["info", "image", "image"]
    assert operations.index("network") < operations.index("build")
    assert "network" in operations[operations.index("build") + 1:] and "image" in operations[operations.index("build") + 1:]
    assert type(caught.value.primary).__name__ == "CommandExecutionError"
    assert json.loads((out / "execution-audit.json").read_text())["primary_error"] == "CommandExecutionError"


def test_subprocess_runner_caps_output_and_kills_timed_out_group() -> None:
    runner = SubprocessCommandRunner()
    capped = runner.run(
        [sys.executable, "-c", "import sys;sys.stdout.write('x'*10000);sys.stderr.write('y'*10000)"],
        timeout_seconds=5, max_output_bytes=100,
    )
    assert capped.returncode == 0
    assert len(capped.stdout) == len(capped.stderr) == 100
    assert capped.stdout_truncated and capped.stderr_truncated
    timed = runner.run(
        [sys.executable, "-c", "import time;time.sleep(5)"],
        timeout_seconds=0.05, max_output_bytes=100,
    )
    assert timed.timed_out and timed.returncode != 0


def score_context(records: dict) -> TrustedCallbackContext:
    return TrustedCallbackContext("run", CVE, "judge", PARENT, {}, (), records)


def test_hidden_oracle_scoring_commitment_and_no_secret_disclosure(tmp_path: Path) -> None:
    secret = "SECRET-EXPECTED-VALUE"
    oracle = {
        "schema": "cvehunt.hidden-score/v1",
        "cve_id": CVE,
        "max_score": 10,
        "rules": [
            {"id": "decision", "stage": "judge", "path": ["payload", "decision"], "operator": "equals", "expected": secret, "weight": 4},
            {"id": "eligible", "stage": "validator", "path": ["payload", "valid"], "operator": "truthy", "weight": 3},
            {"id": "present", "stage": "judge", "path": ["status"], "operator": "present", "weight": 2},
            {"id": "false", "stage": "judge", "path": ["payload", "bad"], "operator": "falsey", "weight": 1},
        ],
    }
    oracle_path = tmp_path / "oracle.json"
    oracle_path.write_bytes(canonical_json(oracle))
    out = tmp_path / "out"
    out.mkdir()
    records = {
        "judge": {"stage": "judge", "status": "completed", "payload": {"decision": secret, "bad": False}},
        "validator": {"stage": "validator", "status": "completed", "payload": {"valid": True}},
    }
    result = HiddenOracleScorer(oracle_path).official_score(context=score_context(records), output_dir=out)
    assert result.payload["score"] == result.payload["max_score"] == 10
    assert result.payload["oracle_commitment"] == hashlib.sha256(canonical_json(oracle)).hexdigest()
    assert set(result.payload) == {
        "score", "max_score", "eligible", "oracle_commitment", "scoring_input_commitment",
    }
    serialized = json.dumps(result.payload)
    assert secret not in serialized and "decision" not in serialized and str(oracle_path) not in serialized
    assert list(out.iterdir()) == []


def test_hidden_oracle_replacement_after_pinning_fails_without_score_output(tmp_path: Path) -> None:
    oracle = {
        "schema": "cvehunt.hidden-score/v1", "cve_id": CVE, "max_score": 1,
        "rules": [{
            "id": "secret-rule-id", "stage": "judge", "path": ["status"],
            "operator": "present", "weight": 1,
        }],
    }
    oracle_path = tmp_path / "oracle.json"
    oracle_path.write_bytes(canonical_json(oracle))
    scorer = HiddenOracleScorer(oracle_path)
    replacement = tmp_path / "replacement.json"
    replacement.write_bytes(canonical_json(oracle))
    replacement.replace(oracle_path)
    out = tmp_path / "out"
    out.mkdir()

    with pytest.raises(RuntimeValidationError, match="changed after preflight"):
        scorer.official_score(context=score_context({"judge": {"status": "completed"}}), output_dir=out)

    assert list(out.iterdir()) == []


@pytest.mark.parametrize("change", ["wrong_cve", "malformed", "unknown", "bad_operator"])
def test_hidden_oracle_fail_closed(tmp_path: Path, change: str) -> None:
    oracle: dict = {
        "schema": "cvehunt.hidden-score/v1", "cve_id": CVE, "max_score": 1,
        "rules": [{"id": "x", "stage": "judge", "path": ["status"], "operator": "present", "weight": 1}],
    }
    path = tmp_path / "oracle.json"
    if change == "wrong_cve":
        oracle["cve_id"] = "CVE-2026-99999"
    elif change == "unknown":
        oracle["secret_path"] = "/hidden"
    elif change == "bad_operator":
        oracle["rules"][0]["operator"] = "contains"
    path.write_text("{" if change == "malformed" else json.dumps(oracle))
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(RuntimeValidationError):
        HiddenOracleScorer(path).official_score(context=score_context({}), output_dir=out)
