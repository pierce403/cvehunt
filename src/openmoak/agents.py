from __future__ import annotations

from openmoak.fixtures import get_fixture
from openmoak.models import (
    CveRecord,
    Evidence,
    Judgement,
    ResearchFinding,
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
    def research(self, cve: CveRecord) -> ResearchFinding:
        summary = cve.summary.lower()
        if "deserialization" in summary:
            vulnerability_class = "deserialization"
            impacted_surface = "request parsing and object materialization"
            hypothesis = (
                "Validate whether patched parsing rejects synthetic traversal "
                "patterns that the vulnerable version accepts."
            )
            patch_signal = "stricter property checks or parser validation"
        elif "interpolation" in summary:
            vulnerability_class = "unsafe interpolation"
            impacted_surface = "template or string lookup evaluation"
            hypothesis = (
                "Validate whether patched interpolation rejects dangerous lookup "
                "classes in a synthetic harness."
            )
            patch_signal = "removed or disabled risky lookup handlers"
        else:
            vulnerability_class = "unknown"
            impacted_surface = "unknown"
            hypothesis = "Fixture coverage is required before automated assessment."
            patch_signal = "unknown"

        return ResearchFinding(
            impacted_surface=impacted_surface,
            vulnerability_class=vulnerability_class,
            defensive_hypothesis=hypothesis,
            relevant_patch_signal=patch_signal,
        )


class EnvironmentPlannerAgent:
    def __init__(self, safety_policy: SafetyPolicy | None = None) -> None:
        self.safety_policy = safety_policy or SafetyPolicy()

    def plan(self, cve: CveRecord, finding: ResearchFinding) -> ValidationPlan:
        check = ValidationCheck(
            name="patched-vs-vulnerable differential check",
            purpose="Confirm that the patched version removes the risky behavior.",
            safe_method=(
                "Run synthetic unit-level probes in isolated local fixtures; do not "
                "execute against external hosts."
            ),
            expected_vulnerable_signal=cve.safe_fixture.get(
                "vulnerable_signal", "no vulnerable fixture signal available"
            ),
            expected_patched_signal=cve.safe_fixture.get(
                "patched_signal", "no patched fixture signal available"
            ),
        )
        plan = ValidationPlan(
            runtime=f"local fixture harness for {cve.ecosystem}",
            isolation="offline synthetic validation only",
            checks=[check],
            forbidden_outputs=[
                "exploit scripts",
                "payloads",
                "bypass steps",
                "target-specific instructions",
            ],
        )
        self.safety_policy.assert_safe_text(check.purpose)
        self.safety_policy.assert_safe_text(check.safe_method)
        return plan


class ValidatorAgent:
    def validate(self, cve: CveRecord, plan: ValidationPlan) -> list[Evidence]:
        if not cve.safe_fixture:
            return [
                Evidence(
                    check_name=check.name,
                    vulnerable_signal="missing fixture",
                    patched_signal="missing fixture",
                    passed=False,
                )
                for check in plan.checks
            ]

        return [
            Evidence(
                check_name=check.name,
                vulnerable_signal=check.expected_vulnerable_signal,
                patched_signal=check.expected_patched_signal,
                passed=check.expected_vulnerable_signal != check.expected_patched_signal,
            )
            for check in plan.checks
        ]


class JudgeAgent:
    def judge(
        self,
        cve: CveRecord,
        finding: ResearchFinding,
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
                rationale="The synthetic checks did not produce a clear differential signal.",
                remediation_notes=["Review affected versions and patch availability manually."],
                safety_notes=["Assessment stayed within offline synthetic fixtures."],
            )

        urgency = "high" if cve.kev or (cve.cvss is not None and cve.cvss >= 9) else "medium"
        return Judgement(
            status="defensive_signal_observed",
            confidence=0.82 if urgency == "high" else 0.68,
            rationale=(
                f"The workflow observed a safe differential signal for "
                f"{finding.vulnerability_class} in fixture data."
            ),
            remediation_notes=[
                f"Prioritize patching affected {cve.ecosystem} components.",
                "Confirm deployed versions match patched releases.",
                "Add regression tests that exercise the patched behavior.",
            ],
            safety_notes=[
                "No weaponizable artifact was generated.",
                "No external target was contacted.",
                "Evidence is synthetic and intended for defensive triage.",
            ],
        )
