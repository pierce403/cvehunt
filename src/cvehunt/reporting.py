from __future__ import annotations

from dataclasses import asdict

from cvehunt.models import TraceEvent, WorkflowReport


def calculate_run_score(report: WorkflowReport) -> dict[str, object]:
    """Score how far the run progressed toward full exploit+fix proof.

    A score of 100 requires a vulnerable-target PoC trigger, the patched target
    blocking the same behavior, a candidate fix, and fix validation.
    """
    components = [
        {
            "name": "metadata_collected",
            "points": 5,
            "earned": bool(report.cve and report.cve.cve_id),
            "description": "CVE metadata was collected.",
        },
        {
            "name": "source_diff_captured",
            "points": 15,
            "earned": bool(
                report.sources
                and report.sources.status == "materialized"
                and report.sources.diff_path
                and report.sources.changed_files
            ),
            "description": "Vulnerable/patched sources were acquired and diffed.",
        },
        {
            "name": "isolated_harness_built",
            "points": 15,
            "earned": bool(report.harness and report.harness.status == "built"),
            "description": "An isolated vulnerable/patched target harness was generated.",
        },
        {
            "name": "poc_generated",
            "points": 10,
            "earned": bool(report.exploiter and report.exploiter.implemented),
            "description": "A harness-scoped PoC artifact was generated.",
        },
        {
            "name": "poc_triggers_vulnerable_target",
            "points": 20,
            "earned": _outcome_triggered(report, "vulnerable"),
            "description": "The PoC triggered the vulnerable target environment.",
        },
        {
            "name": "patched_target_blocks_poc",
            "points": 10,
            "earned": _outcome_triggered(report, "vulnerable") and _outcome_blocked(report, "patched"),
            "description": "The patched target blocked the same PoC behavior.",
        },
        {
            "name": "candidate_fix_generated",
            "points": 10,
            "earned": bool(report.fix and report.fix.status in {"generated", "validated"}),
            "description": "A candidate remediation patch was generated or promoted.",
        },
        {
            "name": "candidate_fix_validated",
            "points": 15,
            "earned": bool(report.fix and report.fix.status == "validated"),
            "description": "The candidate fix was applied and validated against the PoC.",
        },
    ]
    score = sum(component["points"] for component in components if component["earned"])
    max_score = sum(component["points"] for component in components)
    return {
        "score": score,
        "max_score": max_score,
        "percent": round((score / max_score) * 100, 2) if max_score else 0.0,
        "components": components,
    }


def _outcome_triggered(report: WorkflowReport, variant: str) -> bool:
    if not report.exploiter:
        return False
    return any(item.variant == variant and item.triggered for item in report.exploiter.outcomes)


def _outcome_blocked(report: WorkflowReport, variant: str) -> bool:
    if not report.exploiter:
        return False
    return any(item.variant == variant and not item.triggered for item in report.exploiter.outcomes)


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
        "implemented": True,
    },
    {
        "phase": "Fix Developer",
        "goal": "Generate or apply a candidate source fix and re-validate it.",
        "implemented": True,
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
    fix = data.get("fix")
    judgement = data["judgement"]
    evidence = data["evidence"]
    run_score = calculate_run_score(report)

    lines = [
        f"# CVEHunt Report: {cve['cve_id']}",
        "",
        f"Name: {cve['name']}",
        f"CVSS: {cve['cvss'] if cve['cvss'] is not None else 'unknown'}",
        f"KEV: {'yes' if cve['kev'] else 'no'}",
        f"Ecosystem: {cve['ecosystem']}",
        f"Run ID: {run['run_id']}",
        f"Model: {run['model']}",
        f"Run score: {run_score['score']}/{run_score['max_score']} ({run_score['percent']:.2f}%)",
        "",
        "## Run Score",
        "",
        *[
            (
                f"- [{'x' if component['earned'] else ' '}] "
                f"{component['name']}: {component['points']} point(s) - {component['description']}"
            )
            for component in run_score["components"]
        ],
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

    lines.extend(["", "## Target Environment", ""])
    target_urls = exploiter.get("target_urls", {}) if exploiter else {}
    target_lines = [
        f"- CVE: {cve['cve_id']} ({cve['name']})",
        f"- Ecosystem: {cve['ecosystem']}",
        f"- Vulnerable versions: {', '.join(cve['vulnerable_versions']) or 'n/a'}",
        f"- Patched versions: {', '.join(cve['patched_versions']) or 'n/a'}",
        f"- Harness runtime: {harness['runtime'] if harness else 'n/a'}",
        f"- Harness isolation: {harness['isolation'] if harness else 'n/a'}",
        f"- Source package: {sources['package'] if sources else 'n/a'}",
        f"- Vulnerable source root: {sources['vulnerable_root'] if sources else 'n/a'}",
        f"- Patched source root: {sources['patched_root'] if sources else 'n/a'}",
        f"- Vulnerable tarball SHA-256: {sources['vulnerable_tarball_sha256'] if sources else 'n/a'}",
        f"- Patched tarball SHA-256: {sources['patched_tarball_sha256'] if sources else 'n/a'}",
        f"- PoC vulnerable target: {target_urls.get('vulnerable', 'http://127.0.0.1:4000')}",
        f"- PoC patched target: {target_urls.get('patched', 'http://127.0.0.1:4001')}",
        f"- PoC shim vulnerable target: {target_urls.get('shim_vulnerable', 'n/a')}",
        f"- PoC shim patched target: {target_urls.get('shim_patched', 'n/a')}",
    ]
    if exploiter and exploiter.get("outcomes"):
        target_lines.append("- Captured PoC outcomes:")
        target_lines.extend(
            f"  - {outcome['variant']}: triggered={outcome['triggered']} detail={outcome['detail']}"
            for outcome in exploiter["outcomes"]
        )
    lines.extend(target_lines)

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
        if exploiter.get("poc_path"):
            lines.append(f"- PoC script: {exploiter['poc_path']}")
        if exploiter.get("runner_path"):
            lines.append(f"- Runner script: {exploiter['runner_path']}")

    lines.extend(["", "## Fix Developer", ""])
    if fix:
        lines.extend(
            [
                f"- Status: {fix['status']}",
                f"- Message: {fix['message']}",
                f"- Candidate patch: {fix.get('candidate_patch') or 'n/a'}",
                f"- Rationale: {fix.get('rationale') or 'n/a'}",
            ]
        )
        if fix.get("notes"):
            lines.append("- Notes:")
            lines.extend(f"  - {note}" for note in fix["notes"])
    else:
        lines.append("- Status: not_run")

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
            f"- Source patch generated: {'yes' if fix and fix.get('status') in {'generated', 'validated'} else 'no'}",
            f"- Fix validation complete: {'yes' if fix and fix.get('status') == 'validated' else 'no'}",
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
    if report.fix:
        notes.append(report.fix.message)

    exploit_generated = bool(report.exploiter and report.exploiter.implemented)
    fix_generated = bool(report.fix and report.fix.status in {"generated", "validated"})
    fix_validated = bool(report.fix and report.fix.status == "validated")
    run_score = calculate_run_score(report)
    requested_full_pipeline_completed = run_score["score"] == run_score["max_score"]

    return {
        "cve_id": report.cve.cve_id,
        "run_id": report.run.run_id,
        "model": report.run.model,
        "overall_status": report.judgement.status,
        "confidence": report.judgement.confidence,
        "run_score": run_score,
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
