from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from cvehunt.agent_entry import (
    PUBLIC_RESULT_FIELDS,
    PUBLIC_STAGE_FIELDS,
    PUBLIC_TOP_LEVEL_FIELDS,
)
from cvehunt.evaluation_contract import (
    EVALUATION_CONTRACT_SCHEMA,
    evaluation_contract_sha256,
)
from cvehunt.stage_contracts import STAGES

ROOT = Path(__file__).resolve().parents[1]


def module():
    path = ROOT / "scripts" / "agent_benchmark_worker.py"
    spec = importlib.util.spec_from_file_location("agent_benchmark_worker", path)
    assert spec is not None and spec.loader is not None
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def bundle(tmp_path: Path) -> tuple[Path, str, str]:
    cve_id = "CVE-2026-63030"
    run_id = "run-1"
    run = tmp_path / "run"
    run.mkdir()
    stage_fields = list(PUBLIC_STAGE_FIELDS)
    result = {
        "schema": "cvehunt.dimensioned-result/v1",
        "implementation_status": "pre_conformance",
        "headline_eligible": False,
        "termination_reason": "trusted_capability_not_proved",
        "run_boundary": {
            "kind": "wall_clock", "limit_seconds": 7200.0,
            "elapsed_seconds": 1.0, "deadline_exhausted": False,
        },
        "target": {"realism_status": "model_claim_unverified", "identity_commitment": None},
        "attempts": [],
        "primary_exploit": {
            "status": "not_proved", "trusted_capability_receipts": [],
            "time_to_proof_seconds": None,
        },
        "defensive_remediation": {
            "status": "not_attempted", "fix_commitment": None,
            "validation_receipts": [],
        },
        "safety_refusal": {"status": "not_observed"},
        "infrastructure": {"disposition": "no_error_observed"},
    }
    public = {
        "schema": "cvehunt.public-pipeline/v1",
        "run_id": run_id,
        "cve_id": cve_id,
        "model": {"provider": "pi", "model": "venice/test", "harness": "StageHarness"},
        "evaluation_contract": {
            "schema": EVALUATION_CONTRACT_SCHEMA,
            "sha256": evaluation_contract_sha256(),
            "run_timeout_seconds": 7200.0,
        },
        "result": result,
        "stages": [{key: None for key in stage_fields} for _ in STAGES],
    }
    for stage, record in zip(STAGES, public["stages"], strict=True):
        record.update(
            stage=stage, status="completed", outcome="success",
            authorship=("model" if stage in {
                "collector", "researcher", "harness_builder", "exploiter",
                "adversarial_loop", "fix_developer", "validator", "judge",
            } else "deterministic"),
            refusal=False,
        )
    public_bytes = json.dumps(public, sort_keys=True, separators=(",", ":")).encode()
    (run / "public-pipeline.json").write_bytes(public_bytes)
    manifest = {
        "schema": "cvehunt.public-export-manifest/v1",
        "run_id": run_id,
        "cve_id": cve_id,
        "disposition": "completed",
        "evaluation_contract_sha256": evaluation_contract_sha256(),
        "headline_eligible": False,
        "exports": [{
            "artifact_id": "public-pipeline",
            "relative_path": "public-pipeline.json",
            "sha256": hashlib.sha256(public_bytes).hexdigest(),
            "bytes": len(public_bytes),
            "classification": "public_summary",
            "top_level_fields": list(PUBLIC_TOP_LEVEL_FIELDS),
            "stage_fields": stage_fields,
            "result_fields": list(PUBLIC_RESULT_FIELDS),
        }],
    }
    (run / "public-export-manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":"))
    )
    return run, cve_id, run_id


def test_worker_copies_only_manifest_bound_preconformance_projection(tmp_path: Path) -> None:
    worker = module()
    run, cve_id, run_id = bundle(tmp_path)
    (run / "private-poc.py").write_text("secret")

    destination = worker.publish_export_bundle(
        run, tmp_path / "published", cve_id=cve_id, run_id=run_id,
    )

    assert {path.name for path in destination.iterdir()} == {
        "agent-run.json", "export-manifest.json",
    }
    assert "private-poc" not in "".join(path.read_text() for path in destination.iterdir())
    # Idempotent replay is allowed only when bytes are unchanged.
    assert worker.publish_export_bundle(
        run, tmp_path / "published", cve_id=cve_id, run_id=run_id,
    ) == destination


@pytest.mark.parametrize(
    "mutation", [
        "hash", "headline", "scope", "forged_result", "forged_stage",
        "forged_outcome", "collision",
    ],
)
def test_worker_fails_closed_for_unbound_or_colliding_exports(
    tmp_path: Path, mutation: str,
) -> None:
    worker = module()
    run, cve_id, run_id = bundle(tmp_path)
    manifest_path = run / "public-export-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if mutation == "hash":
        manifest["exports"][0]["sha256"] = "0" * 64
    elif mutation == "headline":
        public_path = run / "public-pipeline.json"
        public = json.loads(public_path.read_text())
        public["result"]["headline_eligible"] = True
        public_path.write_text(json.dumps(public))
    elif mutation == "scope":
        manifest["exports"][0]["stage_fields"].append("prompt")
    elif mutation == "forged_result":
        public_path = run / "public-pipeline.json"
        public = json.loads(public_path.read_text())
        public["result"]["forged_success"] = True
        forged = json.dumps(public, sort_keys=True, separators=(",", ":")).encode()
        public_path.write_bytes(forged)
        manifest["exports"][0]["sha256"] = hashlib.sha256(forged).hexdigest()
        manifest["exports"][0]["bytes"] = len(forged)
    elif mutation == "forged_stage":
        public_path = run / "public-pipeline.json"
        public = json.loads(public_path.read_text())
        public["stages"][4]["authorship"] = "model"
        forged = json.dumps(public, sort_keys=True, separators=(",", ":")).encode()
        public_path.write_bytes(forged)
        manifest["exports"][0]["sha256"] = hashlib.sha256(forged).hexdigest()
        manifest["exports"][0]["bytes"] = len(forged)
    elif mutation == "forged_outcome":
        public_path = run / "public-pipeline.json"
        public = json.loads(public_path.read_text())
        public["stages"][0]["outcome"] = {"private_prompt": "must-not-declassify"}
        forged = json.dumps(public, sort_keys=True, separators=(",", ":")).encode()
        public_path.write_bytes(forged)
        manifest["exports"][0]["sha256"] = hashlib.sha256(forged).hexdigest()
        manifest["exports"][0]["bytes"] = len(forged)
    else:
        destination = tmp_path / "published" / cve_id / run_id
        destination.mkdir(parents=True)
        (destination / "agent-run.json").write_text("different")
    if mutation in {
        "hash", "scope", "forged_result", "forged_stage", "forged_outcome",
    }:
        manifest_path.write_text(json.dumps(manifest))

    with pytest.raises(worker.WorkerError):
        worker.publish_export_bundle(
            run, tmp_path / "published", cve_id=cve_id, run_id=run_id,
        )


def test_worker_rejects_symlinked_export_before_publication(tmp_path: Path) -> None:
    worker = module()
    run, cve_id, run_id = bundle(tmp_path)
    public = run / "public-pipeline.json"
    outside = tmp_path / "outside-private.json"
    outside.write_bytes(public.read_bytes())
    public.unlink()
    public.symlink_to(outside)

    with pytest.raises(worker.WorkerError, match="unsafe export file"):
        worker.publish_export_bundle(
            run, tmp_path / "published", cve_id=cve_id, run_id=run_id,
        )

    assert not (tmp_path / "published").exists()
