from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from cvehunt.stage_contracts import (
    PREDECESSOR,
    STAGES,
    StageContractError,
    public_projection,
    read_handoff,
    validate_envelope,
    write_handoff,
)

RUN_ID = "2026-07-20T00-00-00Z"
CVE_ID = "CVE-2026-63030"
ZERO = "0" * 64


def payload(stage: str) -> dict:
    return {
        "collector": {"query": {}, "record": {}, "claims": [], "gaps": []},
        "researcher": {"research_question": "q", "hypotheses": [], "source_acquisition": [], "sources_consulted": [], "gaps": []},
        "harness_builder": {"target_class": "userland_service", "backend": "docker", "variants": [], "services": [], "commands": {}, "safety": {}, "container_plan": {}},
        "exploiter": {"hypothesis_ids": [], "candidate": {}, "derivation": {}, "runtime_requirements": {}},
        "provision_execution": {"execution_id": "e", "executor": {}, "builds": [], "targets": [], "candidate_runs": [], "cleanup": {}},
        "adversarial_loop": {"round_budget": 1, "rounds": [], "rounds_executed": 0, "stop_reason": "budget_exhausted", "adversarial_plan": {}},
        "adversarial_execution": {"execution_id": "e", "executor": "x", "builds": [], "targets": [], "adversarial_runs": [], "cleanup": {}},
        "fix_developer": {"root_cause": {}, "patch": {}, "security_invariant": "i", "expected_behavior": {}, "limitations": [], "fix_plan": {}},
        "fix_execution": {"execution_id": "f", "executor": "docker", "build": {}, "target": {}, "candidate_runs": [], "fix_commitment": ZERO, "cleanup": {}},
        "validator": {"validation_plan": [], "evidence_assessment": [], "coverage": {}, "conclusion": "inconclusive"},
        "judge": {"decision": "inconclusive", "confidence": 0.0, "claims": [], "stage_assessments": [], "limitations": []},
        "official_score": {
            "score": 0, "max_score": 100, "eligible": False,
            "oracle_commitment": ZERO, "scoring_input_commitment": ZERO,
        },
    }[stage]


def envelope(stage: str, root: Path, parent: str | None, *, classification: str | None = None) -> dict:
    root.mkdir(parents=True)
    artifact = root / "result.json"
    artifact.write_text("{}\n", encoding="utf-8")
    raw = artifact.read_bytes()
    kind = "deterministic" if stage in {"provision_execution", "adversarial_execution", "fix_execution", "official_score"} else "model"
    classification = classification or ("model_input" if kind == "model" else "public_artifact")
    return {
        "schema": "cvehunt.stage-artifact/v1",
        "run_id": RUN_ID,
        "cve_id": CVE_ID,
        "stage": stage,
        "invocation_id": f"inv-{stage}",
        "parent_handoff_sha256": parent,
        "authorship": {
            "kind": kind,
            "harness": "pi" if kind == "model" else "trusted-executor",
            "model": "venice/test" if kind == "model" else "deterministic",
            "prompt_template_sha256": ZERO,
            "tool_policy_sha256": ZERO,
        },
        "inputs": [] if parent is None else [{"artifact_id": f"input-{stage}", "sha256": ZERO, "classification": "model_input"}],
        "status": "completed",
        "outcome": "success",
        "payload": payload(stage),
        "artifacts": [{
            "artifact_id": f"artifact-{stage}",
            "logical_path": "result.json",
            "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw),
            "authored_by": f"inv-{stage}",
            "classification": classification,
        }],
        "metrics": {
            "wall_ms": 1,
            "model_ms": 1,
            "tool_ms": 0,
            "input_tokens": 1,
            "output_tokens": 1,
            "cached_input_tokens": None,
            "tool_calls": 0,
            "network_requests": 0,
        },
        "provenance": {
            "input_manifest_sha256": ZERO,
            "output_manifest_sha256": ZERO,
            "prior_run_access": False,
            "external_poc_access": False,
        },
        "errors": [],
        "refusal": None,
    }


def capability_receipt() -> dict:
    return {
        "schema": "cvehunt.capability-receipt/v1",
        "cve_id": CVE_ID,
        "variant": "vulnerable",
        "trusted_result": True,
        "candidate_commitment": "1" * 64,
        "target_digest": "2" * 64,
        "oracle_digest": "3" * 64,
        "nonce_commitment": "4" * 64,
        "observed_interaction_commitment": "5" * 64,
        "execution_result": {"status": "completed", "commitment": "6" * 64},
        "infrastructure_disposition": "completed",
        "evidence_sha256": "7" * 64,
        "evidence_bytes": 1,
    }


def validate(data: dict, root: Path, stage: str, parent: str | None = None) -> dict:
    return validate_envelope(
        data,
        root,
        expected_run_id=RUN_ID,
        expected_cve_id=CVE_ID,
        expected_stage=stage,
        expected_harness="pi" if stage not in {"provision_execution", "adversarial_execution", "fix_execution", "official_score"} else None,
        expected_model="venice/test" if stage not in {"provision_execution", "adversarial_execution", "fix_execution", "official_score"} else None,
        predecessor_handoff_sha256=parent,
    )


def test_valid_complete_hash_linked_chain(tmp_path: Path) -> None:
    parent = None
    for stage in STAGES:
        root = tmp_path / stage
        data = envelope(stage, root, parent)
        validated = validate(data, root, stage, parent)
        handoff_path, parent = write_handoff(validated, root / "handoff.json")
        loaded, observed = read_handoff(handoff_path, expected_run_id=RUN_ID, expected_cve_id=CVE_ID, expected_stage=stage)
        assert observed == parent
        assert loaded["stage"] == stage


def test_wrong_identity_authorship_and_parent_fail(tmp_path: Path) -> None:
    root = tmp_path / "researcher"
    data = envelope("researcher", root, ZERO)
    data["run_id"] = "wrong"
    with pytest.raises(StageContractError, match="run identity"):
        validate(data, root, "researcher", ZERO)
    data["run_id"] = RUN_ID
    data["authorship"]["kind"] = "deterministic"
    with pytest.raises(StageContractError, match="model authorship"):
        validate(data, root, "researcher", ZERO)
    data["authorship"]["kind"] = "model"
    with pytest.raises(StageContractError, match="predecessor handoff"):
        validate(data, root, "researcher", "1" * 64)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("cve_id", "CVE-2026-99999", "cve_id mismatch"),
        ("oracle_digest", None, "requires oracle digest"),
        ("infrastructure_disposition", "error", "disposition"),
        ("execution_result", {"status": "failed", "commitment": "6" * 64}, "status"),
    ],
)
def test_positive_capability_receipt_is_exact_and_cve_bound(
    tmp_path: Path, field: str, value: object, message: str,
) -> None:
    root = tmp_path / field
    data = envelope("provision_execution", root, ZERO)
    receipt = capability_receipt()
    receipt[field] = value
    data["payload"]["candidate_runs"] = [receipt]
    with pytest.raises(StageContractError, match=message):
        validate(data, root, "provision_execution", ZERO)

    valid_root = tmp_path / f"valid-{field}"
    valid = envelope("provision_execution", valid_root, ZERO)
    valid["payload"]["candidate_runs"] = [capability_receipt()]
    validate(valid, valid_root, "provision_execution", ZERO)


def test_refusal_is_explicit_and_not_provider_or_timeout_error(tmp_path: Path) -> None:
    root = tmp_path / "collector"
    data = envelope("collector", root, None)
    data["status"] = "refused"
    data["outcome"] = "none"
    data["payload"] = {}
    data["refusal"] = {
        "kind": "explicit_task_refusal",
        "model_statement_sha256": ZERO,
        "substantive_artifacts_produced": False,
    }
    validate(data, root, "collector")
    data["status"] = "provider_error"
    with pytest.raises(StageContractError, match="only status=refused"):
        validate(data, root, "collector")
    data["refusal"] = None
    data["outcome"] = "none"
    validate(data, root, "collector")
    data["status"] = "timeout"
    validate(data, root, "collector")


@pytest.mark.parametrize("logical_path", ["../result.json", "/tmp/result.json", "a/../../result.json"])
def test_traversal_and_absolute_artifact_paths_fail(tmp_path: Path, logical_path: str) -> None:
    root = tmp_path / "collector"
    data = envelope("collector", root, None)
    data["artifacts"][0]["logical_path"] = logical_path
    with pytest.raises(StageContractError, match="relative path"):
        validate(data, root, "collector")


def test_hash_bytes_duplicate_and_hidden_input_fail(tmp_path: Path) -> None:
    root = tmp_path / "collector"
    data = envelope("collector", root, None)
    data["artifacts"][0]["sha256"] = "1" * 64
    with pytest.raises(StageContractError, match="hash mismatch"):
        validate(data, root, "collector")
    data = envelope("collector", tmp_path / "collector2", None)
    data["artifacts"].append(dict(data["artifacts"][0]))
    with pytest.raises(StageContractError, match="duplicate artifact"):
        validate(data, tmp_path / "collector2", "collector")
    data = envelope("collector", tmp_path / "collector3", None)
    data["inputs"] = [{"artifact_id": "secret", "sha256": ZERO, "classification": "hidden_oracle"}]
    with pytest.raises(StageContractError, match="model_input"):
        validate(data, tmp_path / "collector3", "collector")


def test_symlink_hardlink_and_fifo_fail(tmp_path: Path) -> None:
    for kind in ("symlink", "hardlink", "fifo"):
        root = tmp_path / kind
        data = envelope("collector", root, None)
        artifact = root / "result.json"
        if kind == "symlink":
            original = root / "original"
            artifact.rename(original)
            artifact.symlink_to(original.name)
        elif kind == "hardlink":
            os.link(artifact, root / "second-link")
        else:
            artifact.unlink()
            os.mkfifo(artifact)
        with pytest.raises(StageContractError):
            validate(data, root, "collector")


def test_public_projection_excludes_private_artifacts_and_paths(tmp_path: Path) -> None:
    root = tmp_path / "collector"
    data = envelope("collector", root, None, classification="hidden_oracle")
    with pytest.raises(StageContractError, match="self-declassify"):
        validate(data, root, "collector")
    data["stage"] = "provision_execution"
    data["invocation_id"] = "inv-provision_execution"
    data["authorship"]["kind"] = "deterministic"
    data["artifacts"][0]["authored_by"] = "inv-provision_execution"
    data["payload"] = payload("provision_execution")
    data["parent_handoff_sha256"] = ZERO
    validated = validate(data, root, "provision_execution", ZERO)
    projected = public_projection(validated)
    assert projected["artifacts"] == []
    assert "payload" not in projected
    assert "logical_path" not in str(projected)


def test_model_authored_downstream_input_is_valid_but_never_public(tmp_path: Path) -> None:
    root = tmp_path / "exploiter"
    data = envelope("exploiter", root, ZERO, classification="model_input")

    validated = validate(data, root, "exploiter", ZERO)
    projected = public_projection(validated)

    assert validated["artifacts"][0]["classification"] == "model_input"
    assert projected["artifacts"] == []
    assert "artifact-exploiter" not in str(projected)


def test_missing_or_invalid_predecessor_blocks_successor(tmp_path: Path) -> None:
    root = tmp_path / "researcher"
    data = envelope("researcher", root, ZERO)
    with pytest.raises(StageContractError, match="predecessor"):
        validate(data, root, "researcher", None)
    missing = tmp_path / "missing-handoff.json"
    with pytest.raises(FileNotFoundError):
        read_handoff(missing, expected_run_id=RUN_ID, expected_cve_id=CVE_ID, expected_stage=PREDECESSOR["researcher"] or "")
