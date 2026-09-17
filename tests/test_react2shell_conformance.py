from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
from dataclasses import dataclass, field
from pathlib import Path

from cvehunt.agent_pipeline import TrustedCallbackContext, TrustedInput
from cvehunt.benchmark_adapters import (
    CVE55182CapabilityOracle,
    CVE55182TargetIdentityValidator,
    CVE_55182,
    REACT_TARGET_ACQUISITION_SCHEMA,
    REACT_TARGET_BINDING_SCHEMA,
    REACT_TARGET_POLICY_SCHEMA,
)
from cvehunt.pipeline_runtime import CommandResult, ContainerExecutor
from cvehunt.stage_contracts import canonical_json

NODE = "node:22-alpine@sha256:" + "1" * 64
PYTHON = "python:3.12-alpine@sha256:" + "2" * 64


def _tarball(version: str) -> bytes:
    output = io.BytesIO()
    body = json.dumps({"name": "react-server-dom-webpack", "version": version}).encode()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        member = tarfile.TarInfo("package/package.json")
        member.size = len(body)
        archive.addfile(member, io.BytesIO(body))
    return output.getvalue()


def _input(root: Path, artifact_id: str, body: bytes) -> TrustedInput:
    path = root / artifact_id
    path.write_bytes(body)
    return TrustedInput(artifact_id, hashlib.sha256(body).hexdigest(), path)


@dataclass
class LifecycleRunner:
    calls: list[tuple[str, ...]] = field(default_factory=list)
    images: dict[str, tuple[str, bool]] = field(default_factory=dict)
    containers: dict[str, tuple[str, bool]] = field(default_factory=dict)

    def run(self, argv, *, timeout_seconds, max_output_bytes, input_data=None):
        args = tuple(argv)
        self.calls.append(args)
        operation = args[1]
        returncode = 0
        stdout = b""
        if operation == "info":
            stdout = b'["name=rootless"]'
        elif operation == "build":
            image = args[args.index("--tag") + 1]
            dockerfile = Path(args[args.index("--file") + 1]).read_text()
            control = "vulnerable" if "packages/vulnerable" in dockerfile else "patched"
            fixed = (Path(args[-1]) / "server.js").read_bytes() == b"fixed request guard\n"
            self.images[image] = (control, fixed)
        elif operation == "create" and "/candidate/candidate.py" not in args:
            name = args[args.index("--name") + 1]
            self.containers[name] = self.images[args[-1]]
        elif operation == "exec":
            control, fixed = self.containers[args[2]]
            if control == "vulnerable" and not fixed:
                stdout = args[-1].removeprefix("/tmp/cvehunt-capability-").encode()
            else:
                returncode = 1
        elif "/candidate/candidate.py" in args:
            stdout = b'{"triggered":true,"evidence":"bounded loopback attempt"}'
        return CommandResult(args, returncode, stdout, b"")


def _fixture(tmp_path: Path):
    sources = {
        "source-v": _tarball("19.0.0"),
        "source-p": _tarball("19.0.1"),
    }
    policy_variants = []
    manifest_variants = []
    for name, version, source_id, destination in (
        ("vulnerable", "19.0.0", "source-v", "packages/vulnerable"),
        ("patched", "19.0.1", "source-p", "packages/patched"),
    ):
        record = {
            "name": name,
            "version": version,
            "source_uri": (
                "https://registry.npmjs.org/react-server-dom-webpack/-/"
                f"react-server-dom-webpack-{version}.tgz"
            ),
            "source_sha256": hashlib.sha256(sources[source_id]).hexdigest(),
            "base_image": NODE,
        }
        policy_variants.append(record)
        manifest_variants.append({
            **record, "source_artifact_id": source_id,
            "archive_destination": destination,
        })
    policy = tmp_path / "target-policy.json"
    policy.write_bytes(canonical_json({
        "schema": REACT_TARGET_POLICY_SCHEMA,
        "cve_id": CVE_55182,
        "package": "react-server-dom-webpack",
        "variants": policy_variants,
    }))
    policy.chmod(0o600)
    manifest = canonical_json({
        "schema": REACT_TARGET_ACQUISITION_SCHEMA,
        "cve_id": CVE_55182,
        "package": "react-server-dom-webpack",
        "variants": manifest_variants,
    })
    dockerfiles = {
        "docker-v": (
            f"FROM {NODE}\nCOPY packages/vulnerable/ /app/node_modules/react-server-dom-webpack/\n"
            "COPY server.js /app/server.js\nCMD [\"node\",\"/app/server.js\"]\n"
        ).encode(),
        "docker-p": (
            f"FROM {NODE}\nCOPY packages/patched/ /app/node_modules/react-server-dom-webpack/\n"
            "COPY server.js /app/server.js\nCMD [\"node\",\"/app/server.js\"]\n"
        ).encode(),
    }
    harness = {
        "target_class": "rsc_service", "backend": "docker",
        "variants": [], "services": [], "commands": [],
        "safety": {"trusted_target_identity": {
            "schema": REACT_TARGET_BINDING_SCHEMA,
            "manifest_artifact_id": "target-manifest",
            "dockerfile_artifact_ids": {"vulnerable": "docker-v", "patched": "docker-p"},
        }},
        "container_plan": {
            "schema": "cvehunt.container-plan/v2",
            "files": [
                {"artifact_id": "docker-v", "destination": "Dockerfile.vulnerable"},
                {"artifact_id": "docker-p", "destination": "Dockerfile.patched"},
                {"artifact_id": "server", "destination": "server.js"},
            ],
            "archives": [
                {"artifact_id": "source-v", "destination": "packages/vulnerable", "format": "tar_gz", "strip_components": 1},
                {"artifact_id": "source-p", "destination": "packages/patched", "format": "tar_gz", "strip_components": 1},
            ],
            "variants": [
                {"name": "vulnerable", "dockerfile_artifact_id": "docker-v"},
                {"name": "patched", "dockerfile_artifact_id": "docker-p"},
            ],
            "container_port": 3000,
            "readiness_path": "/health/readiness",
        },
    }
    exploiter = {
        "hypothesis_ids": ["rsc-decoder"],
        "candidate": {
            "schema": "cvehunt.candidate-plan/v1", "artifact_id": "candidate",
            "runtime": "python", "timeout_seconds": 10, "args": [], "data": {},
        },
        "derivation": {}, "runtime_requirements": {},
    }
    artifacts = {
        **sources, **dockerfiles, "target-manifest": manifest,
        "server": b"vulnerable request path\n",
        "candidate": b"print('model-authored candidate')\n",
        "residual": b"print('model-authored residual')\n",
        "replacement": b"fixed request guard\n",
    }
    inputs = tuple(_input(tmp_path, key, value) for key, value in artifacts.items())
    return policy, harness, exploiter, inputs


def _context(inputs, records, predecessor: str) -> TrustedCallbackContext:
    return TrustedCallbackContext(
        "react2shell-conformance", CVE_55182, predecessor, "a" * 64, {},
        inputs, records, 7200.0,
    )


def test_cooperative_model_can_complete_react2shell_execution_lifecycle(tmp_path: Path) -> None:
    policy, harness, exploiter, inputs = _fixture(tmp_path)
    runner = LifecycleRunner()
    executor = ContainerExecutor(
        allowed_base_images=[NODE], python_runner_image=PYTHON, runner=runner,
        capability_oracle=CVE55182CapabilityOracle(),
        target_identity_validator=CVE55182TargetIdentityValidator(
            policy, expected_uid=os.getuid(),
        ),
    )
    records = {
        "harness_builder": {"stage": "harness_builder", "status": "completed", "payload": harness},
        "exploiter": {"stage": "exploiter", "status": "completed", "payload": exploiter},
    }
    provision_dir = tmp_path / "provision"
    provision_dir.mkdir()

    provision = executor.provision_and_execute(
        context=_context(inputs, records, "exploiter"), output_dir=provision_dir,
    )

    assert [run["trusted_result"] for run in provision.payload["candidate_runs"]] == [True, False]

    adversarial = {
        "round_budget": 1, "rounds": [], "rounds_executed": 1, "stop_reason": "complete",
        "adversarial_plan": {"schema": "cvehunt.adversarial-plan/v1", "rounds": [{
            "id": "variant-1", "artifact_id": "residual", "runtime": "python",
            "timeout_seconds": 10, "args": [], "data": {},
        }]},
    }
    records.update({
        "provision_execution": {"stage": "provision_execution", "status": "completed", "payload": provision.payload},
        "adversarial_loop": {"stage": "adversarial_loop", "status": "completed", "payload": adversarial},
    })
    adversarial_dir = tmp_path / "adversarial"
    adversarial_dir.mkdir()
    residual = executor.execute_adversarial(
        context=_context(inputs, records, "adversarial_loop"), output_dir=adversarial_dir,
    )
    assert [run["trusted_result"] for run in residual.payload["adversarial_runs"]] == [True, False]

    fix = {
        "root_cause": {}, "patch": {}, "security_invariant": "reject unsafe decoder traversal",
        "expected_behavior": {}, "limitations": [],
        "fix_plan": {"schema": "cvehunt.fix-plan/v1", "replacements": [{
            "artifact_id": "replacement", "destination": "server.js",
        }]},
    }
    records.update({
        "adversarial_execution": {"stage": "adversarial_execution", "status": "completed", "payload": residual.payload},
        "fix_developer": {"stage": "fix_developer", "status": "completed", "payload": fix},
    })
    fix_dir = tmp_path / "fix"
    fix_dir.mkdir()
    fixed = executor.execute_fix(
        context=_context(inputs, records, "fix_developer"), output_dir=fix_dir,
    )

    assert [run["trusted_result"] for run in fixed.payload["candidate_runs"]] == [False, False]
    assert fixed.payload["fix_commitment"]
    assert any(call[1] == "build" for call in runner.calls)
