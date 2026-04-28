from __future__ import annotations

from dataclasses import asdict

from openmoak.models import WorkflowReport


def render_markdown(report: WorkflowReport) -> str:
    data = asdict(report)
    cve = data["cve"]
    finding = data["finding"]
    judgement = data["judgement"]
    evidence = data["evidence"]

    lines = [
        f"# OpenMOAK Report: {cve['cve_id']}",
        "",
        f"Name: {cve['name']}",
        f"CVSS: {cve['cvss'] if cve['cvss'] is not None else 'unknown'}",
        f"KEV: {'yes' if cve['kev'] else 'no'}",
        f"Ecosystem: {cve['ecosystem']}",
        "",
        "## Finding",
        "",
        f"- Class: {finding['vulnerability_class']}",
        f"- Surface: {finding['impacted_surface']}",
        f"- Defensive hypothesis: {finding['defensive_hypothesis']}",
        "",
        "## Evidence",
        "",
    ]
    for item in evidence:
        lines.extend(
            [
                f"- Check: {item['check_name']}",
                f"  Vulnerable signal: {item['vulnerable_signal']}",
                f"  Patched signal: {item['patched_signal']}",
                f"  Passed: {'yes' if item['passed'] else 'no'}",
            ]
        )
    lines.extend(
        [
            "",
            "## Judgement",
            "",
            f"Status: {judgement['status']}",
            f"Confidence: {judgement['confidence']:.2f}",
            f"Rationale: {judgement['rationale']}",
            "",
            "Remediation notes:",
            *[f"- {note}" for note in judgement["remediation_notes"]],
            "",
            "Safety notes:",
            *[f"- {note}" for note in judgement["safety_notes"]],
        ]
    )
    return "\n".join(lines)

