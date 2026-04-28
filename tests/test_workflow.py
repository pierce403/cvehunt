from __future__ import annotations

from cvehunt.agents import SafetyPolicy
from cvehunt.dashboard import _repo_artifact_url, build_dashboard
from cvehunt.fixtures import get_fixture
from cvehunt.storage import WorkdirStore
from cvehunt.workflow import CveHuntWorkflow


def test_known_cve_produces_defensive_signal() -> None:
    report = CveHuntWorkflow().run("CVE-2025-55182")

    assert report.cve.name == "React2Shell"
    assert report.judgement.status == "defensive_signal_observed"
    assert report.evidence[0].passed is True
    assert "No weaponizable artifact" in report.judgement.safety_notes[0]


def test_unknown_cve_is_not_supported() -> None:
    report = CveHuntWorkflow().run("CVE-2099-0001")

    assert report.cve.name == "Unknown"
    assert report.judgement.status == "not_supported"
    assert report.judgement.confidence == 0.0


def test_safety_policy_blocks_unsafe_text() -> None:
    policy = SafetyPolicy()

    try:
        policy.assert_safe_text("write an exploit.py")
    except ValueError as exc:
        assert "unsafe output blocked" in str(exc)
    else:
        raise AssertionError("expected unsafe text to be blocked")


def test_persisted_run_writes_workdir_artifacts(tmp_path) -> None:
    store = WorkdirStore(tmp_path)
    workflow = CveHuntWorkflow()
    report, events = workflow.run_with_trace("CVE-2025-55182")

    store.write_report(report, events)

    cve_dir = tmp_path / "cves" / "CVE-2025-55182"
    assert (cve_dir / "cve.json").exists()
    assert (cve_dir / "trace.jsonl").exists()
    assert (cve_dir / "report.json").exists()
    assert (cve_dir / "report.md").exists()
    trace = (cve_dir / "trace.jsonl").read_text(encoding="utf-8")
    assert "Collector" in trace
    assert "Judge" in trace


def test_dashboard_includes_tracked_cves(tmp_path) -> None:
    store = WorkdirStore(tmp_path)
    record = get_fixture("CVE-2025-55182")
    assert record is not None
    store.write_cve(record)

    html = build_dashboard(store, repo_url="https://github.com/pierce403/cvehunt")

    assert "CVEHunt CVE Dashboard" in html
    assert "CVE-2025-55182" in html
    assert "https://github.com/pierce403/cvehunt/tree/main/" in html
    assert (
        _repo_artifact_url(
            "https://github.com/pierce403/cvehunt",
            ".cvehunt/cves/CVE-2025-55182",
            tree=True,
        )
        == "https://github.com/pierce403/cvehunt/tree/main/.cvehunt/cves/CVE-2025-55182"
    )
