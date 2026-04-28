from __future__ import annotations

from pathlib import Path

from cvehunt.agents import ResearcherAgent, SafetyPolicy
from cvehunt.dashboard import _repo_artifact_url, build_dashboard
from cvehunt.fixtures import get_fixture
from cvehunt.models import ChangedFile, ResearchFinding, SourceBundle
from cvehunt.storage import WorkdirStore
from cvehunt.workflow import CveHuntWorkflow


def _patch_researcher(monkeypatch) -> None:
    def fake_research(self, cve, artifact_root: Path):
        vulnerable_root = artifact_root / "sources" / "vulnerable" / "package"
        patched_root = artifact_root / "sources" / "patched" / "package"
        research_dir = artifact_root / "research"
        vulnerable_root.mkdir(parents=True, exist_ok=True)
        patched_root.mkdir(parents=True, exist_ok=True)
        research_dir.mkdir(parents=True, exist_ok=True)
        (vulnerable_root / "index.js").write_text("dangerousLookup(metadata[2])\n", encoding="utf-8")
        (patched_root / "index.js").write_text(
            "const hasOwnProperty = Object.prototype.hasOwnProperty;\n"
            "if (hasOwnProperty.call(moduleExports, metadata[2])) {}\n",
            encoding="utf-8",
        )
        (research_dir / "source_diff.patch").write_text(
            "--- a/index.js\n+++ b/index.js\n+const hasOwnProperty = Object.prototype.hasOwnProperty;\n",
            encoding="utf-8",
        )
        finding = ResearchFinding(
            impacted_surface="request parsing and server function argument materialization",
            vulnerability_class="unsafe deserialization",
            defensive_hypothesis="Inspect published vulnerable and patched package releases.",
            relevant_patch_signal="Object.prototype.hasOwnProperty observed in index.js.",
            changed_files=["index.js"],
            research_notes=["Test fixture patched the Researcher stage with a local diff."],
        )
        sources = SourceBundle(
            status="materialized",
            ecosystem=cve.ecosystem,
            package="react-server-dom-webpack",
            vulnerable_version="19.0.0",
            patched_version="19.0.1",
            vulnerable_tarball_url="https://example.invalid/vulnerable.tgz",
            patched_tarball_url="https://example.invalid/patched.tgz",
            vulnerable_tarball_sha256="vuln-sha256",
            patched_tarball_sha256="patched-sha256",
            vulnerable_root="sources/vulnerable/package",
            patched_root="sources/patched/package",
            diff_path="research/source_diff.patch",
            changed_files=[
                ChangedFile(
                    path="index.js",
                    additions=2,
                    deletions=1,
                    patch_signal="Object.prototype.hasOwnProperty",
                )
            ],
            notes=["Downloaded test tarballs from local fixtures."],
        )
        return finding, sources

    monkeypatch.setattr(ResearcherAgent, "research", fake_research)


def test_known_cve_produces_defensive_signal(monkeypatch, tmp_path) -> None:
    _patch_researcher(monkeypatch)
    workflow = CveHuntWorkflow(model="test-model")
    report, _events = workflow.run_with_trace(
        "CVE-2025-55182",
        artifact_root=tmp_path / "artifacts",
    )

    assert report.run.model == "test-model"
    assert report.cve.name == "React2Shell"
    assert report.harness is not None
    assert report.harness.status == "built"
    assert report.exploiter is not None
    assert report.exploiter.status == "stubbed"
    assert report.judgement.status == "defensive_signal_observed"
    assert report.evidence[0].passed is True
    assert "The Exploiter stage is a documented stub" in report.judgement.safety_notes[0]


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


def test_persisted_run_writes_workdir_artifacts(monkeypatch, tmp_path) -> None:
    _patch_researcher(monkeypatch)
    store = WorkdirStore(tmp_path)
    workflow = CveHuntWorkflow()
    report, events = workflow.run_with_trace(
        "CVE-2025-55182",
        artifact_root=tmp_path / "artifacts",
    )

    store.write_report(report, events, artifact_root=workflow.last_artifact_root)

    cve_dir = tmp_path / "cves" / "CVE-2025-55182"
    run_dir = cve_dir / "runs" / report.run.run_id
    assert (run_dir / "cve.json").exists()
    assert (run_dir / "trace.jsonl").exists()
    assert (run_dir / "report.json").exists()
    assert (run_dir / "report.md").exists()
    assert (run_dir / "pipeline_status.json").exists()
    assert (run_dir / "research" / "source_diff.patch").exists()
    assert (run_dir / "harness" / "README.md").exists()
    assert (run_dir / "exploiter" / "README.md").exists()
    assert not (cve_dir / "report.json").exists()
    trace = (run_dir / "trace.jsonl").read_text(encoding="utf-8")
    assert "Harness Builder" in trace
    assert "Exploiter" in trace
    pipeline_status = (run_dir / "pipeline_status.json").read_text(encoding="utf-8")
    assert '"status": "stubbed"' in pipeline_status
    assert '"requested_full_pipeline_completed": false' in pipeline_status
    report_md = (run_dir / "report.md").read_text(encoding="utf-8")
    assert "Model: unspecified" in report_md
    assert "Real package sources acquired: yes" in report_md


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
            "cves/CVE-2025-55182",
            tree=True,
        )
        == "https://github.com/pierce403/cvehunt/tree/main/cves/CVE-2025-55182"
    )
