from __future__ import annotations

import json
import subprocess
from pathlib import Path

from cvehunt import agents as agents_module
from cvehunt.agents import (
    ExploiterAgent,
    HarnessBuilderAgent,
    HarnessRunnerAgent,
    ProvisionAgent,
    ResearcherAgent,
    SafetyPolicy,
)
from cvehunt.agents import JudgeAgent
from cvehunt.dashboard import _repo_artifact_url, build_dashboard
from cvehunt.fixtures import get_fixture
from cvehunt.reporting import calculate_run_score
from cvehunt.models import (
    ChangedFile,
    CveRecord,
    Evidence,
    ExploiterArtifact,
    HarnessArtifact,
    NegotiationLog,
    ProvisionArtifact,
    ResearchFinding,
    SourceBundle,
)
from cvehunt.storage import WorkdirStore
from cvehunt.workflow import CveHuntWorkflow


EXPECTED_AGENT_NOTE_SLUGS = [
    "collector",
    "researcher",
    "harness-builder",
    "exploiter",
    "harness-runner",
    "provision",
    "adversarial-loop",
    "fix-developer",
    "validator",
    "judge",
]


def _assert_run_notes(run_dir: Path) -> None:
    notes_index = run_dir / "NOTES.md"
    assert notes_index.exists()
    index_text = notes_index.read_text(encoding="utf-8")
    assert "# CVEHunt Run Notes" in index_text
    assert "Collector" in index_text
    assert "Harness Builder" in index_text
    assert "Judge" in index_text

    for slug in EXPECTED_AGENT_NOTE_SLUGS:
        note_path = run_dir / "agent-notes" / slug / "NOTES.md"
        assert note_path.exists(), slug
        note_text = note_path.read_text(encoding="utf-8")
        assert "Things Discovered" in note_text
        assert "Things Tried" in note_text
        assert "Things That Did Not Work / Blockers" in note_text
        assert "Artifacts" in note_text
        assert "Next Steps" in note_text


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
            "--- a/index.js\n"
            "+++ b/index.js\n"
            "@@ -1 +1,2 @@\n"
            "-dangerousLookup(metadata[2])\n"
            "+const hasOwnProperty = Object.prototype.hasOwnProperty;\n"
            "+if (hasOwnProperty.call(moduleExports, metadata[2])) {}\n",
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
    assert report.fix.status == "validated"
    # Honest contract: a scaffold-only run with NO behavioral observation
    # (--execute-poc not set) must NOT be a defensive signal, even though a
    # harness, PoC, and fix were all materialized. It is needs_human_review
    # at a capped low confidence.
    assert report.judgement.status == "needs_human_review"
    assert report.judgement.confidence <= 0.50
    assert "NOT a defensive signal" in report.judgement.rationale
    assert any("127.0.0.1" in note for note in report.judgement.safety_notes)


def test_unknown_cve_is_not_supported(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(agents_module, "fetch_cve", lambda cve_id: None)
    report, _events = CveHuntWorkflow().run_with_trace(
        "CVE-2099-0001",
        artifact_root=tmp_path / "artifacts",
    )

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


def test_safety_policy_permits_attacker_capability_vocabulary() -> None:
    """The pipeline's job is to fully characterize what an attacker can do,
    so attacker-capability vocabulary (reverse shell, bind shell, weaponize,
    credential exfiltration, persistence, …) must NOT be content-filtered.
    The only enforcement is the operational targeting boundary
    (loopback-only), exercised separately.
    """
    policy = SafetyPolicy()
    # These describe attacker capabilities, not real targets. They must pass.
    assert not hasattr(policy, "assert_safe_text")
    assert not hasattr(policy, "forbidden_phrases")
    # The operational boundary still holds: an external host is rejected.
    try:
        policy.assert_localhost_scoped("set up a reverse shell to 10.0.0.5:4444")
    except ValueError as exc:
        assert "outside harness scope" in str(exc)
    # Loopback reverse-shell description is fully allowed — vocabulary only.
    policy.assert_localhost_scoped("reverse shell to 127.0.0.1:4444 via /bin/sh")


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
    _assert_run_notes(run_dir)
    assert (run_dir / "research" / "source_diff.patch").exists()
    assert (run_dir / "harness" / "README.md").exists()
    assert (run_dir / "harness" / "SETUP.md").exists()
    assert (run_dir / "harness" / "run-targets.sh").exists()
    assert (run_dir / "harness" / "target-environment.json").exists()
    assert (run_dir / "exploiter" / "README.md").exists()
    assert not (cve_dir / "report.json").exists()
    trace = (run_dir / "trace.jsonl").read_text(encoding="utf-8")
    assert "Harness Builder" in trace
    assert "Exploiter" in trace
    pipeline_status = (run_dir / "pipeline_status.json").read_text(encoding="utf-8")
    pipeline_status_json = json.loads(pipeline_status)
    assert '"status": "scaffolded"' in pipeline_status
    assert '"exploit_generated": true' in pipeline_status
    assert '"fix_generated": true' in pipeline_status
    assert pipeline_status_json["run_score"]["score"] == 70
    assert (run_dir / "exploiter" / "poc.py").exists()
    assert (run_dir / "exploiter" / "run-poc.sh").exists()
    assert (run_dir / "fix" / "candidate.patch").exists()
    report_md = (run_dir / "report.md").read_text(encoding="utf-8")
    assert "Model: unspecified" in report_md
    assert "Run score: 70/100" in report_md
    assert "## Target Environment" in report_md
    assert "Vulnerable versions: react-server-dom-webpack 19.0.0" in report_md
    assert "PoC vulnerable target: http://127.0.0.1:4000" in report_md
    assert "Real package sources acquired: yes" in report_md
    assert "Source patch generated: yes" in report_md


def test_default_artifact_root_is_run_directory(monkeypatch, tmp_path) -> None:
    _patch_researcher(monkeypatch)
    monkeypatch.chdir(tmp_path)
    workflow = CveHuntWorkflow(model="test-model")

    report, _events = workflow.run_with_trace("CVE-2025-55182")

    expected = Path("cves") / "CVE-2025-55182" / "runs" / report.run.run_id
    assert workflow.last_artifact_root == expected
    _assert_run_notes(tmp_path / expected)
    assert (tmp_path / expected / "research" / "source_diff.patch").exists()
    assert (tmp_path / expected / "harness" / "target-environment.json").exists()
    assert report.run.model == "test-model"


def test_persisted_run_can_finalize_in_place(monkeypatch, tmp_path) -> None:
    _patch_researcher(monkeypatch)
    store = WorkdirStore(tmp_path)
    run_id = "2099-01-02T03-04-05Z"
    run_dir = store.run_dir("CVE-2025-55182", run_id)
    workflow = CveHuntWorkflow()

    report, events = workflow.run_with_trace(
        "CVE-2025-55182",
        artifact_root=run_dir,
        run_id=run_id,
    )
    store.write_report(report, events, artifact_root=workflow.last_artifact_root)

    assert workflow.last_artifact_root == run_dir
    assert report.run.run_id == run_id
    assert (run_dir / "research" / "source_diff.patch").exists()
    assert (run_dir / "trace.jsonl").exists()
    assert (run_dir / "pipeline_status.json").exists()


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
    assert report.harness.status == "blocked_needs_artifact"
    assert report.exploiter is not None
    assert report.exploiter.status == "not_supported"
    assert report.judgement.status == "blocked_needs_artifact"
    target_env = json.loads(
        (tmp_path / "artifacts" / "harness" / "target-environment.json").read_text(
            encoding="utf-8"
        )
    )
    assert target_env["backend"] == "manual_artifact_required"
    assert target_env["target_class"] == "userland_service"
    assert "vulnerable_target_artifact" in target_env["missing_artifacts"]
    assert (tmp_path / "artifacts" / "harness" / "SETUP.md").exists()
    assert (tmp_path / "artifacts" / "harness" / "run-targets.sh").exists()


def test_linux_kernel_cve_selects_qemu_and_requests_artifacts(tmp_path) -> None:
    workflow = CveHuntWorkflow()
    cve = CveRecord(
        cve_id="CVE-2099-0100",
        name="LinuxKernelBug",
        summary="A Linux kernel eBPF use-after-free can trigger privilege escalation.",
        cvss=9.8,
        disclosed="2099-02-01",
        ecosystem="linux-kernel",
        vulnerable_versions=["linux 6.1.0"],
        patched_versions=["linux 6.1.1"],
    )
    report, _events = workflow.run_with_trace(
        "CVE-2099-0100",
        cve_record=cve,
        artifact_root=tmp_path / "artifacts",
        execute_poc=True,
    )

    assert report.harness is not None
    assert report.harness.status == "blocked_needs_artifact"
    assert report.provision is not None
    assert report.provision.status == "blocked_needs_artifact"
    assert report.judgement.status == "blocked_needs_artifact"
    harness_dir = tmp_path / "artifacts" / "harness"
    target_env = json.loads((harness_dir / "target-environment.json").read_text(encoding="utf-8"))
    qemu_target = json.loads((harness_dir / "qemu" / "target.json").read_text(encoding="utf-8"))
    deploy_script = (harness_dir / "run-targets.sh").read_text(encoding="utf-8")
    setup_md = (harness_dir / "SETUP.md").read_text(encoding="utf-8")
    assert target_env["target_class"] == "linux_kernel"
    assert target_env["backend"] == "qemu_vm"
    assert target_env["instrumentation"]["engine"] == "qemu_trace"
    assert "vulnerable_kernel_image" in target_env["missing_artifacts"]
    assert qemu_target["guest_os"] == "linux"
    assert "qemu-system-x86_64" in deploy_script
    assert "blocked_needs_artifact" in deploy_script
    assert "QEMU Profile" in setup_md
    assert "vulnerable_kernel_image" in setup_md
    subprocess.run(
        ["bash", str(harness_dir / "run-targets.sh"), "up"],
        cwd=tmp_path / "artifacts",
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    provision = json.loads(
        (tmp_path / "artifacts" / "provision" / "provision.json").read_text(
            encoding="utf-8"
        )
    )
    assert provision["status"] == "blocked_needs_artifact"
    assert "vulnerable_kernel_image" in provision["missing_artifacts"]


def test_chromium_v8_cve_selects_browser_engine_contract(tmp_path) -> None:
    workflow = CveHuntWorkflow()
    cve = CveRecord(
        cve_id="CVE-2099-0110",
        name="Google Chrome / Chromium V8",
        summary=(
            "Out of bounds read and write in V8 in Google Chrome prior to "
            "149.0.7827.103 allowed a remote attacker to execute arbitrary code "
            "inside a sandbox via a crafted HTML page."
        ),
        cvss=8.8,
        disclosed="2099-02-10",
        ecosystem="chromium",
        vulnerable_versions=["google chrome < 149.0.7827.103"],
        patched_versions=["google chrome 149.0.7827.103"],
        kev=True,
        references=[
            "https://chromereleases.googleblog.com/example",
            "https://issues.chromium.org/issues/123",
        ],
        cwes=["CWE-125", "CWE-787"],
    )
    report, _events = workflow.run_with_trace(
        "CVE-2099-0110",
        cve_record=cve,
        artifact_root=tmp_path / "artifacts",
        execute_poc=True,
    )

    assert report.finding.vulnerability_class == "memory corruption"
    assert report.harness is not None
    assert report.harness.status == "blocked_needs_artifact"
    assert report.provision is not None
    assert report.provision.status == "blocked_needs_artifact"
    assert report.judgement.status == "blocked_needs_artifact"
    harness_dir = tmp_path / "artifacts" / "harness"
    target_env = json.loads((harness_dir / "target-environment.json").read_text(encoding="utf-8"))
    setup_md = (harness_dir / "SETUP.md").read_text(encoding="utf-8")
    qemu_target = json.loads((harness_dir / "qemu" / "target.json").read_text(encoding="utf-8"))

    assert target_env["target_class"] == "browser_engine"
    assert target_env["backend"] == "qemu_vm"
    assert target_env["instrumentation"]["engine"] == "qemu_browser_engine_trace"
    assert "chromium_or_v8_checkout" in target_env["missing_artifacts"]
    assert "vulnerable_engine_revision" in target_env["missing_artifacts"]
    assert "patched_engine_revision" in target_env["missing_artifacts"]
    assert "browser_guest_image" in target_env["missing_artifacts"]
    assert qemu_target["guest_os"] == "linux-desktop"
    assert target_env["cve"]["references"] == cve.references
    assert [step["id"] for step in target_env["setup_playbook"]] == [
        "resolve_fix_revision",
        "fetch_public_source",
        "checkout_vulnerable_and_patched",
        "build_browser_targets",
        "run_html_candidate",
    ]
    assert (
        target_env["exploiter_candidate_contract"]["primary_input"]
        == "exploiter/candidate.html"
    )
    assert target_env["exploiter_candidate_contract"]["runner"] == "harness/browser-run-candidate.sh"
    assert "depot_tools" in setup_md
    assert "fetch --nohooks chromium" in setup_md
    assert "exploiter/candidate.html" in setup_md
    assert "harness/browser-run-candidate.sh" in setup_md
    assert "https://issues.chromium.org/issues/123" in setup_md


def test_collector_metadata_drives_browser_engine_contract(monkeypatch, tmp_path) -> None:
    cve = CveRecord(
        cve_id="CVE-2026-11645",
        name="Google Chrome / Chromium V8",
        summary=(
            "Out of bounds read and write in V8 in Google Chrome prior to "
            "149.0.7827.103 allowed a remote attacker to execute arbitrary code "
            "inside a sandbox via a crafted HTML page."
        ),
        cvss=8.8,
        disclosed="2026-06-08",
        ecosystem="chromium",
        vulnerable_versions=["google chrome < 149.0.7827.103"],
        patched_versions=["google chrome 149.0.7827.103"],
        kev=True,
        references=[
            "https://chromereleases.googleblog.com/2026/06/stable-channel-update.html",
            "https://issues.chromium.org/issues/506689381",
        ],
        cwes=["CWE-125", "CWE-787"],
        metadata_source="cve_services",
    )
    monkeypatch.setattr(agents_module, "fetch_cve", lambda cve_id, timeout: cve)

    report, _events = CveHuntWorkflow().run_with_trace(
        "CVE-2026-11645",
        artifact_root=tmp_path / "artifacts",
    )

    assert report.cve.metadata_source == "cve_services"
    assert report.finding.vulnerability_class == "memory corruption"
    target_env = json.loads(
        (tmp_path / "artifacts" / "harness" / "target-environment.json").read_text(
            encoding="utf-8"
        )
    )
    assert target_env["cve"]["metadata_source"] == "cve_services"
    assert target_env["target_class"] == "browser_engine"
    assert target_env["backend"] == "qemu_vm"
    assert "chromium_or_v8_checkout" in target_env["missing_artifacts"]


def test_windows_driver_cve_requests_vm_and_driver_installers(tmp_path) -> None:
    workflow = CveHuntWorkflow()
    cve = CveRecord(
        cve_id="CVE-2099-0101",
        name="WindowsDriverBug",
        summary="A Windows driver kernel-mode driver flaw allows local privilege escalation.",
        cvss=8.8,
        disclosed="2099-02-02",
        ecosystem="windows",
        vulnerable_versions=["Vendor Driver 1.0"],
        patched_versions=["Vendor Driver 1.1"],
    )
    report, _events = workflow.run_with_trace(
        "CVE-2099-0101",
        cve_record=cve,
        artifact_root=tmp_path / "artifacts",
    )

    target_env = json.loads(
        (tmp_path / "artifacts" / "harness" / "target-environment.json").read_text(
            encoding="utf-8"
        )
    )
    assert report.harness is not None
    assert report.harness.status == "blocked_needs_artifact"
    assert report.judgement.status == "blocked_needs_artifact"
    assert target_env["target_class"] == "windows_driver"
    assert target_env["backend"] == "qemu_vm"
    assert target_env["qemu"]["guest_os"] == "windows"
    assert "windows_base_image" in target_env["missing_artifacts"]
    assert "vulnerable_driver_installer" in target_env["missing_artifacts"]
    assert "patched_driver_installer" in target_env["missing_artifacts"]


def test_container_escape_requires_qemu_not_host_docker(tmp_path) -> None:
    workflow = CveHuntWorkflow()
    cve = CveRecord(
        cve_id="CVE-2099-0102",
        name="ContainerEscapeBug",
        summary="A runc container escape reaches the host namespace from a crafted container.",
        cvss=9.8,
        disclosed="2099-02-03",
        ecosystem="container-runtime",
        vulnerable_versions=["runc 1.0.0"],
        patched_versions=["runc 1.0.1"],
    )
    report, _events = workflow.run_with_trace(
        "CVE-2099-0102",
        cve_record=cve,
        artifact_root=tmp_path / "artifacts",
    )

    target_env = json.loads(
        (tmp_path / "artifacts" / "harness" / "target-environment.json").read_text(
            encoding="utf-8"
        )
    )
    assert report.harness is not None
    assert report.harness.status == "blocked_needs_artifact"
    assert target_env["target_class"] == "container_escape"
    assert target_env["backend"] == "qemu_vm"
    assert target_env["deployment"]["isolation_backend"] == "qemu_vm"
    assert target_env["deployment"]["loopback_only"] is False
    assert "host Docker must not be the target boundary" in target_env["safety_boundaries"][0]


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
            "--- a/auth.py\n"
            "+++ b/auth.py\n"
            "@@ -1,5 +1,4 @@\n"
            " def verify_key(key):\n"
            "     return db.execute(\n"
            "-        f\"SELECT * FROM keys WHERE key_value = '{key}'\"\n"
            "-    )\n"
            "+        \"SELECT * FROM keys WHERE key_value = ?\", (key,)\n"
            "+    )\n",
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
    assert report.fix.status == "validated"
    assert report.fix.candidate_patch == "fix/candidate.patch"
    poc_text = (
        tmp_path / "artifacts" / "exploiter" / "poc.py"
    ).read_text(encoding="utf-8")
    assert "127.0.0.1" in poc_text
    assert "openai.com" not in poc_text
    assert "anthropic.com" not in poc_text


def test_workflow_base_port_updates_harness_and_poc(monkeypatch, tmp_path) -> None:
    _patch_pypi_researcher(monkeypatch)
    workflow = CveHuntWorkflow(model="test-model", base_port=4100)
    report, _events = workflow.run_with_trace(
        "CVE-2026-42208",
        artifact_root=tmp_path / "artifacts",
    )

    assert report.exploiter is not None
    assert report.exploiter.target_urls["vulnerable"] == "http://127.0.0.1:4100"
    compose = (tmp_path / "artifacts" / "harness" / "docker-compose.yml").read_text(encoding="utf-8")
    poc = (tmp_path / "artifacts" / "exploiter" / "poc.py").read_text(encoding="utf-8")
    assert "127.0.0.1:4100:4000" in compose
    assert "127.0.0.1:4101:4000" in compose
    assert "http://127.0.0.1:4100" in poc
    assert "http://127.0.0.1:4101" in poc


def test_pypi_harness_uses_dynamic_target_contract(monkeypatch, tmp_path) -> None:
    _patch_pypi_researcher(monkeypatch)
    workflow = CveHuntWorkflow(model="test-model")
    workflow.run_with_trace(
        "CVE-2026-42208",
        artifact_root=tmp_path / "artifacts",
    )

    harness_dir = tmp_path / "artifacts" / "harness"
    vulnerable_dockerfile = (harness_dir / "Dockerfile.vulnerable").read_text(encoding="utf-8")
    compose = (harness_dir / "docker-compose.yml").read_text(encoding="utf-8")
    deploy_script = (harness_dir / "run-targets.sh").read_text(encoding="utf-8")
    setup_md = (harness_dir / "SETUP.md").read_text(encoding="utf-8")
    target_env = json.loads((harness_dir / "target-environment.json").read_text(encoding="utf-8"))
    assert "COPY sources/vulnerable/litellm /workspace/package" in vulnerable_dockerfile
    assert '"/workspace/package[proxy]"' not in vulnerable_dockerfile
    assert "COPY harness/instrumented" not in vulnerable_dockerfile
    assert not (harness_dir / "config.yaml").exists()
    assert not (harness_dir / "db-init.sql").exists()
    assert not (harness_dir / "instrumented").exists()
    assert "postgres:16-alpine" not in compose
    assert "DATABASE_URL" not in compose
    assert target_env["agent_phase_contract"][0]["phase"] == "Collector"
    assert target_env["instrumentation"]["engine"] == "agent_authored_http_probe"
    assert target_env["dynamic_target_contract"]["runtime_plan"] == "harness/agent-target.json"
    assert target_env["dynamic_target_contract"]["runtime_driver"] == "harness/agent-runtime.sh"
    assert target_env["deployment"]["commands"]["up"] == "bash harness/run-targets.sh up"
    assert target_env["deployment"]["commands"]["down"] == "bash harness/run-targets.sh down"
    assert {target["name"] for target in target_env["targets"]} == {"vulnerable", "patched"}
    assert target_env["sidecars"] == []
    assert "## Dynamic Instrumentation Contract" in setup_md
    assert "## Agent Contract" in setup_md
    assert "not servable unless its declared readiness probe" in setup_md
    assert "case \"${1:-up}\" in" in deploy_script
    assert "build|up|probe|logs|down" in deploy_script
    assert "harness/agent-runtime.sh" in deploy_script
    assert "/__cvehunt/probe" in deploy_script
    assert "provision/provision.json" in deploy_script
    assert "exploiter/logs/compose.log" in deploy_script
    runner = (tmp_path / "artifacts" / "exploiter" / "run-poc.sh").read_text(encoding="utf-8")
    assert "bash harness/run-targets.sh up" in runner
    assert "bash harness/run-targets.sh logs" in runner
    assert "bash harness/run-targets.sh down" in runner


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
            "harness/target-environment.json",
            "harness/SETUP.md",
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

    def fake_run(cmd, cwd=None, timeout=None, check=False, **kwargs):
        if cwd is not None:
            (Path(cwd) / "exploiter" / "outcome.json").write_text(
                json.dumps(fake_outcome), encoding="utf-8"
            )
        return subprocess.CompletedProcess(cmd, 0)

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

    def fake_run(cmd, cwd=None, timeout=None, check=False, **kwargs):
        if cwd is not None:
            (Path(cwd) / "exploiter" / "outcome.json").write_text(
                json.dumps(fake_outcome), encoding="utf-8"
            )
        return subprocess.CompletedProcess(cmd, 0)

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
    assert report.judgement.status == "defensive_signal_observed"
    assert report.judgement.confidence >= 0.95
    assert "adversarial loop reproduced" in report.judgement.rationale
    assert report.negotiation is not None
    assert report.negotiation.escalation_achieved is True
    assert report.negotiation.patch_effective is True
    assert report.negotiation.residual_bypass is False


def test_sql_injection_harness_does_not_emit_synthetic_shim(monkeypatch, tmp_path) -> None:
    _patch_pypi_researcher(monkeypatch)
    workflow = CveHuntWorkflow(model="test-model")
    workflow.run_with_trace(
        "CVE-2026-42208",
        artifact_root=tmp_path / "artifacts",
    )
    shim_dir = tmp_path / "artifacts" / "harness" / "shim"
    compose = (
        tmp_path / "artifacts" / "harness" / "docker-compose.yml"
    ).read_text(encoding="utf-8")
    poc = (tmp_path / "artifacts" / "exploiter" / "poc.py").read_text(encoding="utf-8")
    assert not shim_dir.exists()
    assert "shim" not in compose.lower()
    assert "SHIM_" not in poc
    assert "127.0.0.1:4010" not in poc and "127.0.0.1:4011" not in poc


def test_synthetic_shim_outcomes_do_not_drive_judge(monkeypatch, tmp_path) -> None:
    _patch_pypi_researcher(monkeypatch)
    monkeypatch.setattr(agents_module, "_docker_available", lambda: True)

    fake_outcome = {
        "cve_id": "CVE-2026-42208",
        "vulnerable": {
            "base_url": "http://127.0.0.1:4000",
            "triggered": False,
            "detail": "no auth-bypass response observed against probed paths",
        },
        "patched": {
            "base_url": "http://127.0.0.1:4001",
            "triggered": False,
            "detail": "no auth-bypass response observed against probed paths",
        },
        "shim_vulnerable": {
            "base_url": "http://127.0.0.1:4010",
            "triggered": True,
            "detail": "/verify returned 200 with auth-shaped body for payload \"Bearer ' OR 1=1-- \"",
        },
        "shim_patched": {
            "base_url": "http://127.0.0.1:4011",
            "triggered": False,
            "detail": "no auth-bypass response observed against probed paths",
        },
    }

    def fake_run(cmd, cwd=None, timeout=None, check=False, **kwargs):
        if cwd is not None:
            (Path(cwd) / "exploiter" / "outcome.json").write_text(
                json.dumps(fake_outcome), encoding="utf-8"
            )
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    workflow = CveHuntWorkflow(model="test-model")
    report, _events = workflow.run_with_trace(
        "CVE-2026-42208",
        artifact_root=tmp_path / "artifacts",
        execute_poc=True,
    )

    assert not [
        item for item in report.evidence
        if "shim" in item.check_name
    ]
    assert report.judgement.status == "target_not_servable"
    assert report.judgement.confidence <= 0.50
    assert report.negotiation is not None
    assert report.negotiation.escalation_achieved is False
    assert report.negotiation.patch_effective is True


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


def test_no_behavior_run_is_not_defensive_signal(monkeypatch, tmp_path) -> None:
    """Regression: scaffold-only run with no --execute-poc must NOT be a
    defensive signal even though sources were acquired, a harness was built,
    a PoC was scaffolded, and a fix was validated.

    This is exactly the CVE-2025-55182 70/100 run that was previously
    mislabeled `defensive_signal_observed @ 0.92` purely from artifact
    existence.
    """
    _patch_researcher(monkeypatch)
    workflow = CveHuntWorkflow(model="test-model")
    report, _events = workflow.run_with_trace(
        "CVE-2025-55182",
        artifact_root=tmp_path / "artifacts",
    )
    score = calculate_run_score(report)
    earned = {c["name"]: c["earned"] for c in score["components"]}
    assert earned["poc_triggers_vulnerable_target"] is False
    assert earned["patched_target_blocks_poc"] is False
    assert score["score"] == 70  # honest partial: scaffolding only, no behavior
    assert report.judgement.status == "needs_human_review"
    assert report.judgement.confidence <= 0.50
    assert "NOT a defensive signal" in report.judgement.rationale
    assert report.negotiation is None
    assert report.provision is None


def test_npm_harness_uses_dynamic_target_contract(monkeypatch, tmp_path) -> None:
    _patch_researcher(monkeypatch)
    workflow = CveHuntWorkflow(model="test-model")
    report, _events = workflow.run_with_trace(
        "CVE-2025-55182",
        artifact_root=tmp_path / "artifacts",
    )

    assert report.harness is not None
    assert report.harness.status == "built"
    harness_dir = tmp_path / "artifacts" / "harness"
    vulnerable_dockerfile = (harness_dir / "Dockerfile.vulnerable").read_text(encoding="utf-8")
    patched_dockerfile = (harness_dir / "Dockerfile.patched").read_text(encoding="utf-8")
    compose = (harness_dir / "docker-compose.yml").read_text(encoding="utf-8")
    deploy_script = (harness_dir / "run-targets.sh").read_text(encoding="utf-8")
    setup_md = (harness_dir / "SETUP.md").read_text(encoding="utf-8")
    target_env = json.loads((harness_dir / "target-environment.json").read_text(encoding="utf-8"))
    runner = (tmp_path / "artifacts" / "exploiter" / "run-poc.sh").read_text(encoding="utf-8")

    assert "COPY sources/vulnerable/package /workspace/package" in vulnerable_dockerfile
    assert "COPY sources/patched/package /workspace/package" in patched_dockerfile
    assert "COPY harness/instrumented" not in vulnerable_dockerfile
    assert 'CMD ["node", "-e"' in vulnerable_dockerfile
    assert "corepack enable" in vulnerable_dockerfile
    assert "pnpm install" in vulnerable_dockerfile
    assert not (harness_dir / "instrumented").exists()
    assert "127.0.0.1:4000:4000" in compose
    assert {target["name"] for target in target_env["targets"]} == {"vulnerable", "patched"}
    assert target_env["instrumentation"]["engine"] == "agent_authored_http_probe"
    assert target_env["dynamic_target_contract"]["runtime_plan"] == "harness/agent-target.json"
    assert target_env["deployment"]["commands"]["up"] == "bash harness/run-targets.sh up"
    assert target_env["agent_phase_contract"][2]["phase"] == "Harness Builder"
    assert "## Dynamic Instrumentation Contract" in setup_md
    assert "## Agent Contract" in setup_md
    assert "/__cvehunt/probe" in deploy_script
    assert "harness/agent-runtime.sh" in deploy_script
    assert "bash harness/run-targets.sh up" in runner


def test_provision_gate_requires_instrumented_probe(monkeypatch, tmp_path) -> None:
    cve = get_fixture("CVE-2025-55182")
    assert cve is not None
    finding = ResearchFinding(
        impacted_surface="request parsing and server function argument materialization",
        vulnerability_class="unsafe deserialization",
        defensive_hypothesis="exercise local instrumented target",
        relevant_patch_signal="hasOwnProperty guard",
    )
    harness = HarnessArtifact(
        status="built",
        runtime="dockerized offline harness",
        isolation="localhost ports 4000/4001",
        workspace=".",
    )
    monkeypatch.setattr(agents_module, "_docker_available", lambda: True)

    def readiness_only(url, **kwargs):
        if url.endswith("/health/readiness"):
            return 200, '{"status":"ok"}'
        if url.endswith("/__cvehunt/probe"):
            return 404, "not found"
        return None, "unhandled"

    monkeypatch.setattr(agents_module, "_http_probe", readiness_only)
    result = ProvisionAgent().run(
        cve,
        harness,
        finding,
        tmp_path / "artifacts-readiness-only",
    )
    assert result.status == "not_servable"
    assert result.targets
    assert all(target.ready for target in result.targets)
    assert not any(target.servable for target in result.targets)
    assert "instrumented probe HTTP 404" in result.targets[0].detail

    def instrumented(url, **kwargs):
        if url.endswith("/health/readiness"):
            return 200, '{"status":"ok"}'
        if url.endswith("/__cvehunt/probe"):
            return 200, '{"instrumented":true,"status":"ok"}'
        return None, "unhandled"

    monkeypatch.setattr(agents_module, "_http_probe", instrumented)
    result = ProvisionAgent().run(
        cve,
        harness,
        finding,
        tmp_path / "artifacts-instrumented",
    )
    assert result.status == "servable"
    assert all(target.servable for target in result.targets)


def test_adversarial_loop_records_rounds_and_verdict(monkeypatch, tmp_path) -> None:
    """When the real vulnerable target triggers and the real patched target
    blocks, the adversarial loop emits per-round ndjson logs and a verdict.json,
    and escalates the Judge to defensive_signal_observed.
    """
    _patch_pypi_researcher(monkeypatch)
    monkeypatch.setattr(agents_module, "_docker_available", lambda: True)
    fake_outcome = {
        "cve_id": "CVE-2026-42208",
        "vulnerable": {
            "base_url": "http://127.0.0.1:4000",
            "triggered": True,
            "detail": "declared functional oracle returned vulnerable escalation",
        },
        "patched": {
            "base_url": "http://127.0.0.1:4001",
            "triggered": False,
            "detail": "declared functional oracle blocked the primitive",
        },
    }

    def fake_run(cmd, cwd=None, timeout=None, check=False, **kwargs):
        if cwd is not None:
            (Path(cwd) / "exploiter" / "outcome.json").write_text(
                json.dumps(fake_outcome), encoding="utf-8"
            )
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    workflow = CveHuntWorkflow(model="test-model")
    report, _events = workflow.run_with_trace(
        "CVE-2026-42208",
        artifact_root=tmp_path / "artifacts",
        execute_poc=True,
    )
    neg_dir = tmp_path / "artifacts" / "negotiation"
    assert (neg_dir / "exploit-rounds.ndjson").exists()
    assert (neg_dir / "defense-rounds.ndjson").exists()
    assert (neg_dir / "verdict.json").exists()
    verdict = json.loads((neg_dir / "verdict.json").read_text(encoding="utf-8"))
    assert verdict["escalation_achieved"] is True
    assert verdict["patch_effective"] is True
    assert verdict["residual_bypass"] is False
    assert verdict["verdict"] == "defensive_signal_observed"
    assert report.judgement.status == "defensive_signal_observed"
    assert report.judgement.confidence == 0.95


def test_residual_bypass_downgrades_verdict(tmp_path) -> None:
    """If a residual primitive later re-escalates the patched target, the
    Judge must downgrade to residual_bypass_found at a capped low confidence
    and must NOT be a defensive signal — even if escalation and patch-block
    were otherwise observed.
    """
    cve = get_fixture("CVE-2026-42208")
    assert cve is not None
    finding = ResearchFinding(
        impacted_surface="query construction",
        vulnerability_class="sql injection",
        defensive_hypothesis="parameterized queries",
        relevant_patch_signal="? observed in auth.py.",
    )
    sources = SourceBundle(
        status="materialized",
        ecosystem="pypi",
        package="litellm",
        vulnerable_version="1.81.16",
        patched_version="1.83.7",
        vulnerable_tarball_url=None,
        patched_tarball_url=None,
        vulnerable_tarball_sha256=None,
        patched_tarball_sha256=None,
        vulnerable_root="sources/vulnerable/litellm",
        patched_root="sources/patched/litellm",
        diff_path="research/source_diff.patch",
        notes=["fixture"],
    )
    harness = HarnessArtifact(
        status="built",
        runtime="dockerized offline harness for litellm",
        isolation="localhost ports 4000/4001",
        workspace=".",
        dockerfiles=["harness/Dockerfile.vulnerable", "harness/Dockerfile.patched"],
    )
    structural_evidence = [
        Evidence(check_name="published package pair retrieved",
                 vulnerable_signal="sources/vulnerable/litellm",
                 patched_signal="sources/patched/litellm", passed=True, artifact="sources"),
        Evidence(check_name="patch diff captured",
                 vulnerable_signal="1 changed file(s)",
                 patched_signal="? observed in auth.py.", passed=True,
                 artifact="research/source_diff.patch"),
        Evidence(check_name="container harness scaffolded",
                 vulnerable_signal="harness/Dockerfile.vulnerable",
                 patched_signal="harness/Dockerfile.patched", passed=True,
                 artifact="harness/README.md"),
    ]
    provisional = ProvisionArtifact(status="servable", note="2/2 servable")
    negotiation = NegotiationLog(
        executed=True,
        escalation_achieved=True,
        patch_effective=True,
        residual_bypass=True,
        rounds=[],
        rounds_total=0,
        exploit_rounds=1,
        defense_rounds=1,
        residual_rounds=1,
        verdict="residual_bypass_found",
        rationale="residual primitive re-escalated",
        log_path="negotiation/negotiation.log",
        verdict_path="negotiation/verdict.json",
    )
    judgement = JudgeAgent().judge(
        cve, finding, sources, harness, None, None,
        structural_evidence, provisional, negotiation,
    )
    assert judgement.status == "residual_bypass_found"
    assert judgement.confidence == 0.45
    assert "NOT a defensive signal" in judgement.rationale
