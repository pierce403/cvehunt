from __future__ import annotations

import json
import subprocess
from pathlib import Path

from cvehunt import agents as agents_module
from cvehunt.agents import (
    ExploiterAgent,
    HarnessBuilderAgent,
    HarnessRunnerAgent,
    ResearcherAgent,
    SafetyPolicy,
)
from cvehunt.dashboard import _repo_artifact_url, build_dashboard
from cvehunt.fixtures import get_fixture
from cvehunt.models import (
    ChangedFile,
    CveRecord,
    ExploiterArtifact,
    HarnessArtifact,
    ResearchFinding,
    SourceBundle,
)
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
    assert report.exploiter.status == "scaffolded"
    assert report.exploiter.implemented is True
    assert report.exploiter.poc_path is not None
    assert report.fix is not None
    assert report.fix.status == "generated"
    assert report.judgement.status == "defensive_signal_observed"
    assert report.evidence[0].passed is True
    assert any("127.0.0.1" in note for note in report.judgement.safety_notes)


def test_unknown_cve_is_not_supported() -> None:
    report = CveHuntWorkflow().run("CVE-2099-0001")

    assert report.cve.name == "Unknown"
    assert report.judgement.status == "not_supported"
    assert report.judgement.confidence == 0.0


def test_safety_policy_blocks_external_targets() -> None:
    policy = SafetyPolicy()

    try:
        policy.assert_localhost_scoped("requests.get('https://api.openai.com/v1')")
    except ValueError as exc:
        assert "outside harness scope" in str(exc)
    else:
        raise AssertionError("expected external target to be blocked")

    policy.assert_localhost_scoped("urllib.request.urlopen('http://127.0.0.1:4000/x')")


def test_safety_policy_blocks_explicit_unsafe_phrases() -> None:
    policy = SafetyPolicy()

    try:
        policy.assert_safe_text("set up a reverse shell to attacker box")
    except ValueError as exc:
        assert "unsafe output blocked" in str(exc)
    else:
        raise AssertionError("expected reverse shell language to be blocked")


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
    assert '"status": "scaffolded"' in pipeline_status
    assert '"exploit_generated": true' in pipeline_status
    assert '"fix_generated": true' in pipeline_status
    assert (run_dir / "exploiter" / "poc.py").exists()
    assert (run_dir / "exploiter" / "run-poc.sh").exists()
    assert (run_dir / "fix" / "candidate.patch").exists()
    report_md = (run_dir / "report.md").read_text(encoding="utf-8")
    assert "Model: unspecified" in report_md
    assert "Real package sources acquired: yes" in report_md
    assert "Source patch generated: yes" in report_md


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


def test_unsupported_ecosystem_without_fixture_fails_differential_check(tmp_path) -> None:
    workflow = CveHuntWorkflow()
    cve = CveRecord(
        cve_id="CVE-2099-0002",
        name="MysteryCVE",
        summary="A SQL injection in an unsupported ecosystem.",
        cvss=9.3,
        disclosed="2099-01-01",
        ecosystem="maven",
        vulnerable_versions=["org.example:mystery 1.0.0"],
        patched_versions=["org.example:mystery 1.0.1"],
    )
    report, _events = workflow.run_with_trace(
        "CVE-2099-0002",
        cve_record=cve,
        artifact_root=tmp_path / "artifacts",
    )

    assert report.finding.vulnerability_class == "sql injection"
    assert report.sources is not None
    assert report.sources.status == "not_supported"
    assert report.harness is not None
    assert report.harness.status == "not_supported"
    assert report.exploiter is not None
    assert report.exploiter.status == "not_supported"
    assert report.judgement.status == "insufficient_evidence"


def _patch_pypi_researcher(monkeypatch) -> None:
    from cvehunt.agents import ResearcherAgent

    def fake_research(self, cve, artifact_root: Path):
        vulnerable_root = artifact_root / "sources" / "vulnerable" / "litellm"
        patched_root = artifact_root / "sources" / "patched" / "litellm"
        research_dir = artifact_root / "research"
        vulnerable_root.mkdir(parents=True, exist_ok=True)
        patched_root.mkdir(parents=True, exist_ok=True)
        research_dir.mkdir(parents=True, exist_ok=True)
        (vulnerable_root / "auth.py").write_text(
            "def verify_key(key):\n"
            "    return db.execute(\n"
            "        f\"SELECT * FROM keys WHERE key_value = '{key}'\"\n"
            "    )\n",
            encoding="utf-8",
        )
        (patched_root / "auth.py").write_text(
            "def verify_key(key):\n"
            "    return db.execute(\n"
            "        \"SELECT * FROM keys WHERE key_value = ?\", (key,)\n"
            "    )\n",
            encoding="utf-8",
        )
        (research_dir / "source_diff.patch").write_text(
            "--- a/auth.py\n+++ b/auth.py\n+    return db.execute(\"SELECT ?\", (key,))\n",
            encoding="utf-8",
        )
        finding = ResearchFinding(
            impacted_surface="authentication and proxy API key verification query construction",
            vulnerability_class="sql injection",
            defensive_hypothesis="Inspect parameterized query handling.",
            relevant_patch_signal="? observed in auth.py.",
            changed_files=["auth.py"],
            research_notes=["Test fixture patched the Researcher stage with a local diff."],
        )
        sources = SourceBundle(
            status="materialized",
            ecosystem=cve.ecosystem,
            package="litellm",
            vulnerable_version="1.81.16",
            patched_version="1.83.7",
            vulnerable_tarball_url="https://pypi.example/litellm-1.81.16.tar.gz",
            patched_tarball_url="https://pypi.example/litellm-1.83.7.tar.gz",
            vulnerable_tarball_sha256="vuln-sha256",
            patched_tarball_sha256="patched-sha256",
            vulnerable_root="sources/vulnerable/litellm",
            patched_root="sources/patched/litellm",
            diff_path="research/source_diff.patch",
            changed_files=[
                ChangedFile(
                    path="auth.py",
                    additions=2,
                    deletions=1,
                    patch_signal="?",
                )
            ],
            notes=["Fixture-backed pypi acquisition for tests."],
        )
        return finding, sources

    monkeypatch.setattr(ResearcherAgent, "research", fake_research)


def test_litellm_pipeline_scaffolds_poc_and_fix(monkeypatch, tmp_path) -> None:
    _patch_pypi_researcher(monkeypatch)
    workflow = CveHuntWorkflow(model="test-model")
    report, _events = workflow.run_with_trace(
        "CVE-2026-42208",
        artifact_root=tmp_path / "artifacts",
    )

    assert report.cve.cve_id == "CVE-2026-42208"
    assert report.finding.vulnerability_class == "sql injection"
    assert report.sources is not None
    assert report.sources.status == "materialized"
    assert report.sources.package == "litellm"
    assert report.harness is not None
    assert report.harness.status == "built"
    assert any("docker-compose.yml" in path for path in report.harness.helper_scripts)
    assert report.exploiter is not None
    assert report.exploiter.status == "scaffolded"
    assert report.exploiter.implemented is True
    assert report.exploiter.poc_path == "exploiter/poc.py"
    assert report.fix is not None
    assert report.fix.status == "generated"
    assert report.fix.candidate_patch == "fix/candidate.patch"
    poc_text = (
        tmp_path / "artifacts" / "exploiter" / "poc.py"
    ).read_text(encoding="utf-8")
    assert "127.0.0.1" in poc_text
    assert "openai.com" not in poc_text
    assert "anthropic.com" not in poc_text


def test_litellm_harness_emits_config_and_postgres_sidecar(monkeypatch, tmp_path) -> None:
    _patch_pypi_researcher(monkeypatch)
    workflow = CveHuntWorkflow(model="test-model")
    workflow.run_with_trace(
        "CVE-2026-42208",
        artifact_root=tmp_path / "artifacts",
    )

    harness_dir = tmp_path / "artifacts" / "harness"
    config_yaml = (harness_dir / "config.yaml").read_text(encoding="utf-8")
    db_init = (harness_dir / "db-init.sql").read_text(encoding="utf-8")
    compose = (harness_dir / "docker-compose.yml").read_text(encoding="utf-8")
    assert "master_key: sk-harness-master" in config_yaml
    assert "database_url: os.environ/DATABASE_URL" in config_yaml
    assert "CREATE DATABASE litellm_vuln" in db_init
    assert "CREATE DATABASE litellm_patched" in db_init
    assert "postgres:16-alpine" in compose
    assert "DATABASE_URL: postgresql://litellm:litellm@db:5432/litellm_vuln" in compose
    assert "DATABASE_URL: postgresql://litellm:litellm@db:5432/litellm_patched" in compose
    assert "condition: service_healthy" in compose
    runner = (tmp_path / "artifacts" / "exploiter" / "run-poc.sh").read_text(encoding="utf-8")
    assert "seq 1 90" in runner
    assert "exploiter/logs/compose.log" in runner


def _build_exploiter_state(tmp_path: Path) -> tuple[CveRecord, HarnessArtifact, ExploiterArtifact]:
    cve = get_fixture("CVE-2026-42208")
    assert cve is not None
    artifact_root = tmp_path / "artifacts"
    (artifact_root / "exploiter").mkdir(parents=True, exist_ok=True)
    (artifact_root / "exploiter" / "run-poc.sh").write_text("#!/usr/bin/env bash\n", encoding="utf-8")
    harness = HarnessArtifact(
        status="built",
        runtime="dockerized offline harness for litellm",
        isolation="local package sources only",
        workspace=".",
        dockerfiles=["harness/Dockerfile.vulnerable", "harness/Dockerfile.patched"],
        helper_scripts=[
            "harness/build-images.sh",
            "harness/docker-compose.yml",
            "harness/config.yaml",
            "harness/db-init.sql",
            "harness/README.md",
        ],
    )
    exploiter = ExploiterArtifact(
        implemented=True,
        status="scaffolded",
        message="Generated a localhost-scoped PoC.",
        artifact="exploiter/README.md",
        next_step="Run bash exploiter/run-poc.sh.",
        poc_path="exploiter/poc.py",
        runner_path="exploiter/run-poc.sh",
    )
    return cve, harness, exploiter


def test_harness_runner_skips_when_docker_missing(monkeypatch, tmp_path) -> None:
    cve, harness, exploiter = _build_exploiter_state(tmp_path)
    monkeypatch.setattr(agents_module, "_docker_available", lambda: False)
    runner = HarnessRunnerAgent()
    result = runner.run(cve, harness, exploiter, tmp_path / "artifacts")
    assert result.outcomes == []
    assert result.status == "scaffolded"
    assert "Install Docker" in result.next_step


def test_harness_runner_parses_outcome_into_evidence(monkeypatch, tmp_path) -> None:
    cve, harness, exploiter = _build_exploiter_state(tmp_path)
    artifact_root = tmp_path / "artifacts"
    monkeypatch.setattr(agents_module, "_docker_available", lambda: True)

    fake_outcome = {
        "cve_id": cve.cve_id,
        "vulnerable": {
            "base_url": "http://127.0.0.1:4000",
            "triggered": True,
            "detail": "/key/info returned 200 for payload Bearer ' OR 1=1-- ",
        },
        "patched": {
            "base_url": "http://127.0.0.1:4001",
            "triggered": False,
            "detail": "no permissive 2xx response observed",
        },
    }

    def fake_run(cmd, cwd, capture_output, text, timeout, check):
        (Path(cwd) / "exploiter" / "outcome.json").write_text(
            json.dumps(fake_outcome), encoding="utf-8"
        )
        return subprocess.CompletedProcess(cmd, 0, stdout="ok", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = HarnessRunnerAgent().run(cve, harness, exploiter, artifact_root)

    assert result.status == "executed"
    assert len(result.outcomes) == 2
    triggered = next(item for item in result.outcomes if item.variant == "vulnerable")
    blocked = next(item for item in result.outcomes if item.variant == "patched")
    assert triggered.triggered is True
    assert blocked.triggered is False
    assert "triggered the vulnerable container" in result.message


def test_workflow_execute_poc_flag_threads_outcomes_into_judge(monkeypatch, tmp_path) -> None:
    _patch_pypi_researcher(monkeypatch)
    monkeypatch.setattr(agents_module, "_docker_available", lambda: True)

    fake_outcome = {
        "cve_id": "CVE-2026-42208",
        "vulnerable": {"base_url": "http://127.0.0.1:4000", "triggered": True, "detail": "vulnerable triggered"},
        "patched": {"base_url": "http://127.0.0.1:4001", "triggered": False, "detail": "patched blocked"},
    }

    def fake_run(cmd, cwd, capture_output, text, timeout, check):
        (Path(cwd) / "exploiter" / "outcome.json").write_text(
            json.dumps(fake_outcome), encoding="utf-8"
        )
        return subprocess.CompletedProcess(cmd, 0, stdout="ok", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    workflow = CveHuntWorkflow(model="test-model")
    report, _events = workflow.run_with_trace(
        "CVE-2026-42208",
        artifact_root=tmp_path / "artifacts",
        execute_poc=True,
    )

    assert report.exploiter is not None
    assert report.exploiter.status == "executed"
    triggered_evidence = [
        item for item in report.evidence
        if item.check_name == "harness poc triggered vulnerable container"
    ]
    blocked_evidence = [
        item for item in report.evidence
        if item.check_name == "harness poc blocked by patched container"
    ]
    assert triggered_evidence and triggered_evidence[0].passed
    assert blocked_evidence and blocked_evidence[0].passed
    assert report.judgement.confidence >= 0.95
    assert "triggered the vulnerable container" in report.judgement.rationale


def test_workflow_default_does_not_invoke_runner(monkeypatch, tmp_path) -> None:
    _patch_pypi_researcher(monkeypatch)

    def fail_if_called(*args, **kwargs):
        raise AssertionError("subprocess.run must not be called when execute_poc is off")

    monkeypatch.setattr(subprocess, "run", fail_if_called)
    workflow = CveHuntWorkflow(model="test-model")
    report, _events = workflow.run_with_trace(
        "CVE-2026-42208",
        artifact_root=tmp_path / "artifacts",
    )
    assert report.exploiter is not None
    assert report.exploiter.status == "scaffolded"
