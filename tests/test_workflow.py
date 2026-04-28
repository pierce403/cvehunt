from __future__ import annotations

from openmoak.agents import SafetyPolicy
from openmoak.workflow import OpenMoakWorkflow


def test_known_cve_produces_defensive_signal() -> None:
    report = OpenMoakWorkflow().run("CVE-2025-55182")

    assert report.cve.name == "React2Shell"
    assert report.judgement.status == "defensive_signal_observed"
    assert report.evidence[0].passed is True
    assert "No weaponizable artifact" in report.judgement.safety_notes[0]


def test_unknown_cve_is_not_supported() -> None:
    report = OpenMoakWorkflow().run("CVE-2099-0001")

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

