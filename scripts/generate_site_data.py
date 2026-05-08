from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "cves"
OUT = ROOT / "web" / "public" / "data" / "cves.json"
REPO_URL = "https://github.com/pierce403/cvehunt"


def repo_url(path: Path, *, tree: bool = False) -> str:
    kind = "tree" if tree else "blob"
    rel = path.relative_to(ROOT).as_posix()
    return f"{REPO_URL}/{kind}/main/{rel}"


def read_json(path: Path) -> dict[str, object] | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def read_trace(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            events.append(json.loads(line))
    return events


def latest_run_dir(directory: Path) -> Path | None:
    runs = directory / "runs"
    if not runs.exists():
        return None
    directories = [path for path in runs.iterdir() if path.is_dir()]
    return sorted(directories)[-1] if directories else None


def all_run_dirs(directory: Path) -> list[Path]:
    runs = directory / "runs"
    if not runs.exists():
        return []
    return sorted(path for path in runs.iterdir() if path.is_dir())


def run_score_from_report(report: dict[str, object] | None) -> dict[str, object]:
    if not report:
        return {"score": 0, "max_score": 100, "percent": 0.0, "components": []}

    sources = report.get("sources") if isinstance(report.get("sources"), dict) else None
    harness = report.get("harness") if isinstance(report.get("harness"), dict) else None
    exploiter = report.get("exploiter") if isinstance(report.get("exploiter"), dict) else None
    fix = report.get("fix") if isinstance(report.get("fix"), dict) else None
    cve = report.get("cve") if isinstance(report.get("cve"), dict) else None
    outcomes = exploiter.get("outcomes", []) if exploiter else []

    def triggered(variant: str) -> bool:
        return any(item.get("variant") == variant and item.get("triggered") for item in outcomes if isinstance(item, dict))

    def blocked(variant: str) -> bool:
        return any(item.get("variant") == variant and not item.get("triggered") for item in outcomes if isinstance(item, dict))

    components = [
        {"name": "metadata_collected", "points": 5, "earned": bool(cve and cve.get("cve_id"))},
        {"name": "source_diff_captured", "points": 15, "earned": bool(sources and sources.get("status") == "materialized" and sources.get("diff_path") and sources.get("changed_files"))},
        {"name": "isolated_harness_built", "points": 15, "earned": bool(harness and harness.get("status") == "built")},
        {"name": "poc_generated", "points": 10, "earned": bool(exploiter and exploiter.get("implemented"))},
        {"name": "poc_triggers_vulnerable_target", "points": 20, "earned": triggered("vulnerable")},
        {"name": "patched_target_blocks_poc", "points": 10, "earned": triggered("vulnerable") and blocked("patched")},
        {"name": "candidate_fix_generated", "points": 10, "earned": bool(fix and fix.get("status") in {"generated", "validated"})},
        {"name": "candidate_fix_validated", "points": 15, "earned": bool(fix and fix.get("status") == "validated")},
    ]
    score = sum(component["points"] for component in components if component["earned"])
    max_score = sum(component["points"] for component in components)
    return {
        "score": score,
        "max_score": max_score,
        "percent": round((score / max_score) * 100, 2) if max_score else 0.0,
        "components": components,
    }


def summarize_progress(
    report: dict[str, object] | None,
    trace: list[dict[str, object]],
    pipeline_status: dict[str, object] | None,
) -> dict[str, object]:
    if pipeline_status and isinstance(pipeline_status.get("stages"), list):
        stages = list(pipeline_status["stages"])
        completed_phases = [
            str(stage.get("phase", ""))
            for stage in stages
            if stage.get("status") == "completed"
        ]
        reached_phases = [
            str(stage.get("phase", ""))
            for stage in stages
            if stage.get("reached")
        ]
        return {
            "autonomous_status": pipeline_status.get("overall_status", "unknown"),
            "summary": _summary_from_report(report, pipeline_status),
            "run_score": pipeline_status.get("run_score") or run_score_from_report(report),
            "completed_phases": completed_phases,
            "reached_phases": reached_phases,
            "phase_states": stages,
            "exploit_generated": bool(pipeline_status.get("exploit_generated")),
            "patch_generated": bool(pipeline_status.get("fix_generated")),
            "exploit_note": _exploit_note_from_status(pipeline_status),
            "patch_note": _patch_note_from_status(pipeline_status),
        }

    completed_phases = [str(event.get("phase", "")) for event in trace]
    if not report:
        return {
            "autonomous_status": "not_analyzed",
            "summary": "No autonomous workflow has been run for this CVE yet.",
            "run_score": {"score": 0, "max_score": 100, "percent": 0.0, "components": []},
            "completed_phases": completed_phases,
            "reached_phases": completed_phases,
            "phase_states": [],
            "exploit_generated": False,
            "patch_generated": False,
            "exploit_note": "Not attempted.",
            "patch_note": "No patch artifact has been generated.",
        }

    judgement = report.get("judgement", {})
    status = judgement.get("status", "unknown") if isinstance(judgement, dict) else "unknown"
    return {
        "autonomous_status": status,
        "summary": "The workflow completed defensive triage using the legacy fixture-only path.",
        "run_score": run_score_from_report(report),
        "completed_phases": completed_phases,
        "reached_phases": completed_phases,
        "phase_states": [],
        "exploit_generated": False,
        "patch_generated": False,
        "exploit_note": "No full exploit was generated or published.",
        "patch_note": "No source patch was generated.",
    }


def build_item(directory: Path, artifact_dir: Path, run_directory: Path | None) -> dict[str, object] | None:
    cve_path = directory / "cve.json"
    if not cve_path.exists():
        cve_path = artifact_dir / "cve.json"
    cve = read_json(cve_path)
    if not cve:
        return None

    report_path = artifact_dir / "report.json"
    trace_path = artifact_dir / "trace.jsonl"
    report_md_path = artifact_dir / "report.md"
    pipeline_status_path = artifact_dir / "pipeline_status.json"
    contribution_audit_md_path = artifact_dir / "contribution_audit.md"
    contribution_audit_json_path = artifact_dir / "contribution_audit.json"
    isolation_preflight_path = artifact_dir / "isolation-preflight.log"
    model_attempt_metadata_path = artifact_dir / "model_attempt" / "metadata.json"
    model_attempt_response_path = artifact_dir / "model_attempt" / "response.md"
    model_attempt_prompt_path = artifact_dir / "model_attempt" / "prompt.md"
    report = read_json(report_path)
    pipeline_status = read_json(pipeline_status_path)
    trace = read_trace(trace_path)
    progress = summarize_progress(report, trace, pipeline_status)
    artifact_dir_rel = artifact_dir.relative_to(ROOT).as_posix()
    latest_run_rel = run_directory.relative_to(ROOT).as_posix() if run_directory else None
    run_id = None
    if report and isinstance(report.get("run"), dict):
        run_id = report["run"].get("run_id")
    if run_id is None and pipeline_status:
        run_id = pipeline_status.get("run_id")
    if run_id is None and run_directory is not None:
        run_id = run_directory.name

    return {
        "cve": cve,
        "run_id": run_id,
        "report": report,
        "trace": trace,
        "pipeline_status": pipeline_status,
        "progress": progress,
        "run_score": progress["run_score"],
        "artifacts": {
            "workdir": directory.relative_to(ROOT).as_posix(),
            "latest_run": latest_run_rel,
            "workdir_url": repo_url(directory, tree=True),
            "latest_run_url": repo_url(artifact_dir, tree=True),
            "artifact_blob_prefix": f"{REPO_URL}/blob/main/{artifact_dir_rel}",
            "cve_json_url": repo_url(cve_path),
            "trace_url": repo_url(trace_path),
            "report_json_url": repo_url(report_path),
            "report_md_url": repo_url(report_md_path),
            "pipeline_status_url": repo_url(pipeline_status_path),
            "contribution_audit_md_url": repo_url(contribution_audit_md_path),
            "contribution_audit_json_url": repo_url(contribution_audit_json_path),
            "isolation_preflight_url": repo_url(isolation_preflight_path),
            "model_attempt_metadata_url": repo_url(model_attempt_metadata_path),
            "model_attempt_response_url": repo_url(model_attempt_response_path),
            "model_attempt_prompt_url": repo_url(model_attempt_prompt_path),
            "sources_url": repo_url(artifact_dir / "sources", tree=True),
            "source_diff_url": repo_url(artifact_dir / "research" / "source_diff.patch"),
            "harness_readme_url": repo_url(artifact_dir / "harness" / "README.md"),
            "exploiter_stub_url": repo_url(artifact_dir / "exploiter" / "README.md"),
            "sources_exists": (artifact_dir / "sources").exists(),
            "trace_exists": trace_path.exists(),
            "report_exists": report_path.exists(),
            "report_md_exists": report_md_path.exists(),
            "pipeline_status_exists": pipeline_status_path.exists(),
            "contribution_audit_md_exists": contribution_audit_md_path.exists(),
            "contribution_audit_json_exists": contribution_audit_json_path.exists(),
            "isolation_preflight_exists": isolation_preflight_path.exists(),
            "model_attempt_metadata_exists": model_attempt_metadata_path.exists(),
            "model_attempt_response_exists": model_attempt_response_path.exists(),
            "model_attempt_prompt_exists": model_attempt_prompt_path.exists(),
            "source_diff_exists": (artifact_dir / "research" / "source_diff.patch").exists(),
            "harness_readme_exists": (artifact_dir / "harness" / "README.md").exists(),
            "exploiter_stub_exists": (artifact_dir / "exploiter" / "README.md").exists(),
        },
    }


def build() -> dict[str, object]:
    cves = []
    all_runs = []
    for directory in sorted(DATA_DIR.iterdir() if DATA_DIR.exists() else []):
        if not directory.is_dir():
            continue
        run_directory = latest_run_dir(directory)
        artifact_dir = (
            directory
            if (directory / "report.json").exists() or run_directory is None
            else run_directory
        )
        latest_item = build_item(directory, artifact_dir, run_directory)
        if latest_item:
            cves.append(latest_item)
        for run_dir in all_run_dirs(directory):
            run_item = build_item(directory, run_dir, run_dir)
            if run_item and run_item["report"]:
                all_runs.append(run_item)

    all_runs = sorted(
        all_runs,
        key=lambda item: (
            item["run_score"].get("score", 0),
            item["run_score"].get("percent", 0),
            str(item.get("run_id") or ""),
        ),
        reverse=True,
    )
    analyzed = [item for item in cves if item["report"]]
    return {
        "generated_at": "build-time",
        "repo_url": REPO_URL,
        "counts": {
            "tracked": len(cves),
            "analyzed": len(analyzed),
            "not_analyzed": len(cves) - len(analyzed),
            "high": sum(1 for item in cves if (item["cve"].get("cvss") or 0) >= 7),
            "runs": len(all_runs),
        },
        "cves": cves,
        "runs": all_runs,
    }


def _summary_from_report(
    report: dict[str, object] | None,
    pipeline_status: dict[str, object],
) -> str:
    if not report:
        return "No autonomous workflow has been run for this CVE yet."
    notes = pipeline_status.get("notes")
    if isinstance(notes, list) and notes:
        return str(notes[0])
    return "The workflow captured a repository-backed autonomous run."


def _exploit_note_from_status(pipeline_status: dict[str, object]) -> str:
    if pipeline_status.get("exploit_generated"):
        return "A proof-of-concept artifact was recorded."
    stages = pipeline_status.get("stages")
    if isinstance(stages, list):
        for stage in stages:
            if stage.get("phase") == "Exploiter":
                return str(stage.get("message", "Exploit stage did not complete."))
    return "Exploit stage did not complete."


def _patch_note_from_status(pipeline_status: dict[str, object]) -> str:
    if pipeline_status.get("fix_generated"):
        return "A source patch artifact was recorded."
    return "No source fix generation or fix validation stage completed in this run."


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(build(), indent=2), encoding="utf-8")
    print(OUT)


if __name__ == "__main__":
    main()
