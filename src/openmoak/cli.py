from __future__ import annotations

import argparse
import json
from dataclasses import asdict

from openmoak.workflow import OpenMoakWorkflow


def render_markdown(report: object) -> str:
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="openmoak")
    subcommands = parser.add_subparsers(dest="command", required=True)

    run = subcommands.add_parser("run", help="Run the defensive workflow for a CVE")
    run.add_argument("cve_id", help="CVE identifier, for example CVE-2025-55182")
    run.add_argument("--json", action="store_true", help="Emit structured JSON")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.command == "run":
        report = OpenMoakWorkflow().run(args.cve_id)
        if args.json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print(render_markdown(report))


if __name__ == "__main__":
    main()

