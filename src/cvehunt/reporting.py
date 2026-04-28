from __future__ import annotations

from dataclasses import asdict

from cvehunt.models import TraceEvent, WorkflowReport


FULL_PIPELINE_PHASES = [
    {
        "phase": "Collector",
        "goal": "Collect CVE metadata and local fixture context.",
        "implemented": True,
    },
    {
        "phase": "Researcher",
        "goal": "Acquire supported package sources and derive patch signals from the real release diff.",
        "implemented": True,
    },
    {
        "phase": "Harness Builder",
        "goal": "Generate isolated vulnerable and patched environment scaffolding from the acquired sources.",
        "implemented": True,
    },
    {
        "phase": "Exploiter",
        "goal": "Develop a harness-scoped proof-of-concept.",
        "implemented": False,
    },
    {
        "phase": "Fix Developer",
        "goal": "Generate or apply a candidate source fix and re-validate it.",
        "implemented": False,
    },
    {
        "phase": "Validator",
        "goal": "Compare vulnerable and patched/fixed behavior and capture evidence.",
        "implemented": True,
    },
    {
        "phase": "Judge",
        "goal": "Assess evidence, safety boundaries, and remediation efficacy.",
        "implemented": True,
    },
]


def render_markdown(report: WorkflowReport) -> str:
    data = asdict(report)
    cve = data["cve"]
    run = data["run"]
    finding = data["finding"]
    sources = data["sources"]
    harness = data["harness"]
    exploiter = data["exploiter"]
    judgement = data["judgement"]
    evidence = data["evidence"]

    lines = [
        f"# CVEHunt Report: {cve['cve_id']}",
        "",
        f"Name: {cve['name']}",
        f"CVSS: {cve['cvss'] if cve['cvss'] is not None else 'unknown'}",
        f"KEV: {'yes' if cve['kev'] else 'no'}",
        f"Ecosystem: {cve['ecosystem']}",
        f"Run ID: {run['run_id']}",
        f"Model: {run['model']}",
        "",
        "## Finding",
        "",
        f"- Class: {finding['vulnerability_class']}",
        f"- Surface: {finding['impacted_surface']}",
        f"- Defensive hypothesis: {finding['defensive_hypothesis']}",
        f"- Patch signal: {finding['relevant_patch_signal']}",
    ]
    if finding["changed_files"]:
        lines.extend(
            [
                "- Highest-churn files:",
                *[f"  - {path}" for path in finding["changed_files"]],
            ]
        )
    if finding["research_notes"]:
        lines.extend(
            [
                "- Research notes:",
                *[f"  - {note}" for note in finding["research_notes"]],
            ]
        )

    lines.extend(["", "## Source Acquisition", ""])
    if sources:
        lines.extend(
            [
                f"- Status: {sources['status']}",
                f"- Package: {sources['package'] or 'n/a'}",
                f"- Vulnerable version: {sources['vulnerable_version'] or 'n/a'}",
                f"- Patched version: {sources['patched_version'] or 'n/a'}",
                f"- Vulnerable source root: {sources['vulnerable_root'] or 'n/a'}",
                f"- Patched source root: {sources['patched_root'] or 'n/a'}",
                f"- Diff artifact: {sources['diff_path'] or 'n/a'}",
            ]
        )
        if sources["changed_files"]:
            lines.append("- Changed files:")
            for item in sources["changed_files"][:10]:
                marker = f" ({item['patch_signal']})" if item.get("patch_signal") else ""
                lines.append(
                    f"  - {item['path']}: +{item['additions']} / -{item['deletions']}{marker}"
                )
        if sources["notes"]:
            lines.append("- Notes:")
            lines.extend(f"  - {note}" for note in sources["notes"])

    lines.extend(["", "## Harness", ""])
    if harness:
        lines.extend(
            [
                f"- Status: {harness['status']}",
                f"- Runtime: {harness['runtime']}",
                f"- Isolation: {harness['isolation']}",
                f"- Workspace: {harness['workspace']}",
            ]
        )
        if harness["dockerfiles"]:
            lines.append("- Dockerfiles:")
            lines.extend(f"  - {path}" for path in harness["dockerfiles"])
        if harness["helper_scripts"]:
            lines.append("- Helper artifacts:")
            lines.extend(f"  - {path}" for path in harness["helper_scripts"])
        if harness["notes"]:
            lines.append("- Notes:")
            lines.extend(f"  - {note}" for note in harness["notes"])

    lines.extend(["", "## Exploiter", ""])
    if exploiter:
        lines.extend(
            [
                f"- Status: {exploiter['status']}",
                f"- Implemented: {'yes' if exploiter['implemented'] else 'no'}",
                f"- Message: {exploiter['message']}",
                f"- Artifact: {exploiter['artifact'] or 'n/a'}",
                f"- Next step: {exploiter['next_step']}",
            ]
        )

    lines.extend(["", "## Validation Plan", ""])
    lines.extend(
        [
            f"- Runtime: {data['plan']['runtime']}",
            f"- Isolation: {data['plan']['isolation']}",
        ]
    )
    for check in data["plan"]["checks"]:
        lines.extend(
            [
                f"- Check: {check['name']}",
                f"  Purpose: {check['purpose']}",
                f"  Method: {check['safe_method']}",
                f"  Artifact: {check.get('artifact') or 'n/a'}",
            ]
        )

    lines.extend(["", "## Evidence", ""])
    for item in evidence:
        lines.extend(
            [
                f"- Check: {item['check_name']}",
                f"  Vulnerable signal: {item['vulnerable_signal']}",
                f"  Patched signal: {item['patched_signal']}",
                f"  Passed: {'yes' if item['passed'] else 'no'}",
                f"  Artifact: {item.get('artifact') or 'n/a'}",
            ]
        )

    lines.extend(
        [
            "",
            "## Artifact Outcomes",
            "",
            f"- Real package sources acquired: {'yes' if sources and sources['status'] == 'materialized' else 'no'}",
            f"- Harness scaffold generated: {'yes' if harness and harness['status'] == 'built' else 'no'}",
            f"- Full exploit generated: {'yes' if exploiter and exploiter['implemented'] else 'no'}",
            "- Source patch generated: no",
            "- Fix validation complete: no",
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


def render_pipeline_status(
    report: WorkflowReport,
    events: list[TraceEvent],
) -> dict[str, object]:
    completed = {event.phase: event for event in events}
    stages = []
    for phase in FULL_PIPELINE_PHASES:
        event = completed.get(str(phase["phase"]))
        reached = event is not None
        if event is not None:
            status = event.status
            message = event.message
            artifact = event.artifact
        else:
            status = _not_reached_status(phase)
            message = _not_reached_message(phase)
            artifact = None
        stages.append(
            {
                **phase,
                "reached": reached,
                "status": status,
                "message": message,
                "artifact": artifact,
            }
        )

    notes: list[str] = []
    if report.sources and report.sources.status == "materialized":
        notes.append(
            "Downloaded the published vulnerable and patched package releases and captured a local diff."
        )
    elif report.sources:
        notes.extend(report.sources.notes)
    if report.harness and report.harness.status == "built":
        notes.append("Generated Dockerfiles and helper scripts for offline vulnerable/patched harness builds.")
    elif report.harness:
        notes.extend(report.harness.notes)
    if report.exploiter:
        notes.append(report.exploiter.message)
    notes.append("No source fix generation or fix validation stage is implemented in this run.")

    exploit_generated = bool(report.exploiter and report.exploiter.implemented)
    fix_generated = False
    fix_validated = False
    requested_full_pipeline_completed = exploit_generated and fix_generated and fix_validated

    return {
        "cve_id": report.cve.cve_id,
        "run_id": report.run.run_id,
        "model": report.run.model,
        "overall_status": report.judgement.status,
        "confidence": report.judgement.confidence,
        "furthest_completed_stage": events[-1].phase if events else None,
        "requested_full_pipeline_completed": requested_full_pipeline_completed,
        "exploit_generated": exploit_generated,
        "fix_generated": fix_generated,
        "fix_validated": fix_validated,
        "notes": notes,
        "stages": stages,
    }


def _not_reached_status(phase: dict[str, object]) -> str:
    if phase["implemented"]:
        return "not_reached"
    return "not_implemented"


def _not_reached_message(phase: dict[str, object]) -> str:
    if phase["implemented"]:
        return "Implemented but not reached in this run."
    return "Not implemented in the current CVEHunt pipeline."
