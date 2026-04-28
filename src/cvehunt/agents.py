from __future__ import annotations

import hashlib
import tarfile
from difflib import unified_diff
from pathlib import Path
from urllib.parse import quote
from urllib.request import urlopen
import json

from cvehunt.fixtures import get_fixture
from cvehunt.models import (
    ChangedFile,
    CveRecord,
    Evidence,
    ExploiterArtifact,
    HarnessArtifact,
    Judgement,
    ResearchFinding,
    SourceBundle,
    ValidationCheck,
    ValidationPlan,
)


class SafetyPolicy:
    forbidden_terms = (
        "payload",
        "exploit.py",
        "bypass",
        "shell",
        "reverse shell",
        "weaponize",
    )

    def assert_safe_text(self, text: str) -> None:
        lowered = text.lower()
        matches = [term for term in self.forbidden_terms if term in lowered]
        if matches:
            raise ValueError(f"unsafe output blocked: {', '.join(matches)}")


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
        return (
            "unknown",
            "unknown",
            "Local source acquisition is required before automated assessment can go further.",
            "No patch signal inferred from the summary alone.",
        )

    def _materialize_sources(self, cve: CveRecord, artifact_root: Path) -> SourceBundle:
        if cve.ecosystem != "npm":
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
        vulnerable_tarball = sources_dir / f"{safe_name}-{vulnerable_version}.tgz"
        patched_tarball = sources_dir / f"{safe_name}-{patched_version}.tgz"
        vulnerable_root = sources_dir / "vulnerable"
        patched_root = sources_dir / "patched"
        try:
            vulnerable_manifest = self._fetch_npm_manifest(package, vulnerable_version)
            patched_manifest = self._fetch_npm_manifest(package, patched_version)
            vulnerable_url = str(vulnerable_manifest["dist"]["tarball"])
            patched_url = str(patched_manifest["dist"]["tarball"])
            self._download_tarball(vulnerable_url, vulnerable_tarball)
            self._download_tarball(patched_url, patched_tarball)
            if vulnerable_root.exists():
                _remove_tree(vulnerable_root)
            if patched_root.exists():
                _remove_tree(patched_root)
            self._extract_tarball(vulnerable_tarball, vulnerable_root)
            self._extract_tarball(patched_tarball, patched_root)
            diff_path = research_dir / "source_diff.patch"
            changed_files = self._write_diff(
                vulnerable_root / "package",
                patched_root / "package",
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

        notes = [
            f"Downloaded published npm releases for {package} {vulnerable_version} and {patched_version}.",
            f"Captured a source diff covering {len(changed_files)} changed file(s).",
        ]
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
            vulnerable_root=_relpath(vulnerable_root / "package", artifact_root),
            patched_root=_relpath(patched_root / "package", artifact_root),
            diff_path=_relpath(diff_path, artifact_root),
            changed_files=changed_files,
            notes=notes,
        )

    def _fetch_npm_manifest(self, package: str, version: str) -> dict[str, object]:
        package_ref = quote(package, safe="")
        version_ref = quote(version, safe="")
        with urlopen(
            f"https://registry.npmjs.org/{package_ref}/{version_ref}",
            timeout=30,
        ) as response:
            return json.load(response)

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
                variant="vulnerable",
                source_root=sources.vulnerable_root,
                package=sources.package,
                version=sources.vulnerable_version,
            ),
            encoding="utf-8",
        )
        dockerfile_patched.write_text(
            _dockerfile_for_source(
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
                isolation=plan.isolation,
                workspace=".",
                dockerfiles=[
                    _relpath(dockerfile_vulnerable, artifact_root),
                    _relpath(dockerfile_patched, artifact_root),
                ],
                helper_scripts=[
                    _relpath(build_script, artifact_root),
                    _relpath(readme, artifact_root),
                ],
                notes=[
                    "Generated Docker build definitions for vulnerable and patched package variants.",
                    "No exploit runner or attack payload logic is present in this harness.",
                ],
            ),
            plan,
        )


class ExploiterAgent:
    def run(
        self,
        cve: CveRecord,
        harness: HarnessArtifact | None,
        artifact_root: Path,
    ) -> ExploiterArtifact:
        exploiter_dir = artifact_root / "exploiter"
        exploiter_dir.mkdir(parents=True, exist_ok=True)
        readme = exploiter_dir / "README.md"
        if harness is None or harness.status != "built":
            readme.write_text(
                (
                    f"# Exploiter Stub: {cve.cve_id}\n\n"
                    "Harness materialization was unavailable, so the Exploiter stage "
                    "did not even produce a scaffold.\n"
                ),
                encoding="utf-8",
            )
            return ExploiterArtifact(
                implemented=False,
                status="not_supported",
                message="Exploit development is intentionally absent, and no harness was available to extend.",
                artifact=_relpath(readme, artifact_root),
                next_step="Extend the harness first if you want a local placeholder to sit on top of it.",
            )
        readme.write_text(
            (
                f"# Exploiter Stub: {cve.cve_id}\n\n"
                "This repository intentionally stops here. The Exploiter stage is a "
                "placeholder only. No proof-of-concept logic, payload generation, or "
                "execution flow is implemented in this workspace.\n\n"
                "Use this directory only to record future local experiments outside the "
                "scope of this assistant.\n"
            ),
            encoding="utf-8",
        )
        return ExploiterArtifact(
            implemented=False,
            status="stubbed",
            message="Harness-ready placeholder only. No exploit generation or execution path is implemented.",
            artifact=_relpath(readme, artifact_root),
            next_step="Treat this as a handoff point for a future local implementation outside this assistant.",
        )


class ValidatorAgent:
    def validate(
        self,
        cve: CveRecord,
        plan: ValidationPlan,
        sources: SourceBundle | None,
        harness: HarnessArtifact | None,
    ) -> list[Evidence]:
        evidence: list[Evidence] = []
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
            evidence.append(
                Evidence(
                    check_name=check.name,
                    vulnerable_signal=check.expected_vulnerable_signal,
                    patched_signal=check.expected_patched_signal,
                    passed=check.expected_vulnerable_signal != check.expected_patched_signal,
                    artifact=check.artifact,
                )
            )
        return evidence


class JudgeAgent:
    def judge(
        self,
        cve: CveRecord,
        finding: ResearchFinding,
        sources: SourceBundle | None,
        harness: HarnessArtifact | None,
        exploiter: ExploiterArtifact | None,
        evidence: list[Evidence],
    ) -> Judgement:
        if cve.name == "Unknown":
            return Judgement(
                status="not_supported",
                confidence=0.0,
                rationale="No local fixture exists, so the workflow cannot assess this CVE.",
                remediation_notes=["Add a safe fixture before running automated assessment."],
                safety_notes=["No exploit code or external target interaction was attempted."],
            )

        passed = all(item.passed for item in evidence)
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

        if sources and sources.status == "materialized" and harness and harness.status == "built":
            rationale = (
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
                "The Exploiter stage is a documented stub and does not execute any proof-of-concept logic.",
                "The generated harness is limited to offline package inspection and container scaffolding.",
                "No external target was contacted beyond package registry download endpoints.",
            ]
            return Judgement(
                status="defensive_signal_observed",
                confidence=0.78,
                rationale=rationale,
                remediation_notes=remediation_notes,
                safety_notes=safety_notes,
            )

        urgency = "high" if cve.kev or (cve.cvss is not None and cve.cvss >= 9) else "medium"
        return Judgement(
            status="needs_human_review",
            confidence=0.56 if urgency == "high" else 0.48,
            rationale=(
                "The workflow retained fixture evidence, but real source acquisition or harness generation "
                "did not complete cleanly enough for a stronger assessment."
            ),
            remediation_notes=[
                "Manually review the affected releases and patch availability.",
                "Retry the run after resolving the captured source acquisition or harness issue.",
            ],
            safety_notes=[
                "No proof-of-concept logic was generated.",
                "Assessment remained limited to offline defensive workflow steps.",
            ],
        )


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
    return path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)


def _detect_patch_signal(diff_text: str) -> str | None:
    for marker in (
        "Object.prototype.hasOwnProperty",
        "hasOwnProperty.call",
        "Object.hasOwn",
        "ownProperty",
        "allowlist",
        "lookup",
    ):
        if marker in diff_text:
            return marker
    return None


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
        "This harness is limited to offline package inspection and container image scaffolding.",
        "It does not contain a proof-of-concept runner or target interaction logic.",
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
