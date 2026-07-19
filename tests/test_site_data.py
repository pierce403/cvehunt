from __future__ import annotations

import hashlib
import importlib.util
from dataclasses import fields
from pathlib import Path
from typing import get_args

from cvehunt.models import FixStatus, RunMetadata


ROOT = Path(__file__).resolve().parents[1]


def _load_site_data_module():
    path = ROOT / "scripts" / "generate_site_data.py"
    spec = importlib.util.spec_from_file_location("generate_site_data", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_cve_2026_63030_executed_evidence_is_reported_as_analyzed() -> None:
    site_data = _load_site_data_module()
    data = site_data.build()
    item = next(
        entry
        for entry in data["cves"]
        if entry["cve"]["cve_id"] == "CVE-2026-63030"
    )

    report = item["report"]
    pipeline_status = item["pipeline_status"]
    assert report is not None
    assert pipeline_status is not None
    assert item["progress"]["autonomous_status"] == "defensive_signal_observed"
    assert item["artifacts"]["report_exists"] is True
    assert item["artifacts"]["report_md_exists"] is True
    assert item["artifacts"]["pipeline_status_exists"] is True
    assert item["artifacts"]["full_chain_poc_exists"] is True
    assert item["artifacts"]["full_chain_runner_exists"] is True
    assert item["artifacts"]["full_chain_readme_exists"] is True
    assert item["artifacts"]["full_chain_outcome_exists"] is True
    assert item["artifacts"]["full_chain_poc_url"].endswith("/exploiter/full-chain-poc.py")
    assert report["exploiter"]["full_chain_verified"] is True
    assert report["exploiter"]["poc_path"] == "exploiter/full-chain-poc.py"
    assert report["exploiter"]["runner_path"] == "exploiter/run-full-chain.sh"
    assert "complete published pre-authentication RCE chain" in item["progress"]["summary"]

    run_dir = ROOT / "cves/CVE-2026-63030/runs/2026-07-19T03-53-05Z"
    outcome = site_data.read_json(run_dir / "harness/evidence/full-chain-replay-outcome.json")
    assert outcome is not None
    poc_path = run_dir / outcome["implementation"]["path"]
    runner_path = run_dir / outcome["runner"]["path"]
    assert hashlib.sha256(poc_path.read_bytes()).hexdigest() == outcome["implementation"]["sha256"]
    assert hashlib.sha256(runner_path.read_bytes()).hexdigest() == outcome["runner"]["sha256"]
    assert outcome["vulnerable"]["result_stage"] == "chain_complete"
    assert outcome["vulnerable"]["canary_executed"] is True
    assert outcome["patched"]["result_stage"] == "primitive_blocked"
    assert outcome["patched"]["canary_executed"] is False
    assert outcome["runner"]["cleanup_verified"] is True

    # This is an imported run-local validation, not a native contribute.sh
    # model evaluation or a leaderboard entry.
    assert report["run"]["model"] == "imported-validation"
    assert set(report["run"]) == {field.name for field in fields(RunMetadata)}
    assert pipeline_status["run_mode"] == "imported_run_local_validation"
    assert pipeline_status["requested_full_pipeline_completed"] is False
    assert "not a native contribute.sh model-evaluation run" in item["progress"]["summary"]
    assert item["visible_run_count"] == 0
    assert all(
        run["cve"]["cve_id"] != "CVE-2026-63030"
        for run in data["runs"]
    )

    # Keep the stored report compatible with model enums and prevent an
    # unexecuted negotiation stage from displaying a patch-effectiveness claim.
    assert report["fix"]["status"] in get_args(FixStatus)
    assert pipeline_status["negotiation"] is None
    assert item["progress"]["negotiation"] is None
    assert pipeline_status["adversarial_verdict"] == "not_executed"

    derived_score = site_data.run_score_from_report(report)
    stored_score = pipeline_status["run_score"]
    assert stored_score["score"] == derived_score["score"] == 60
    assert stored_score["max_score"] == derived_score["max_score"] == 100
    assert stored_score["percent"] == derived_score["percent"] == 60.0
    assert [
        (component["name"], component["points"], component["earned"])
        for component in stored_score["components"]
    ] == [
        (component["name"], component["points"], component["earned"])
        for component in derived_score["components"]
    ]
