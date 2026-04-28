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
        "completed_phases": completed_phases,
        "reached_phases": completed_phases,
        "phase_states": [],
        "exploit_generated": False,
        "patch_generated": False,
        "exploit_note": "No full exploit was generated or published.",
        "patch_note": "No source patch was generated.",
    }


def build() -> dict[str, object]:
    cves = []
    for directory in sorted(DATA_DIR.iterdir() if DATA_DIR.exists() else []):
        if not directory.is_dir():
            continue
        run_directory = latest_run_dir(directory)
        artifact_dir = (
            directory
            if (directory / "report.json").exists() or run_directory is None
            else run_directory
        )
        cve_path = directory / "cve.json"
        if not cve_path.exists() and run_directory is not None:
            cve_path = run_directory / "cve.json"
        cve = read_json(cve_path)
        if not cve:
            continue
        report_path = artifact_dir / "report.json"
        trace_path = artifact_dir / "trace.jsonl"
        report_md_path = artifact_dir / "report.md"
        pipeline_status_path = artifact_dir / "pipeline_status.json"
        report = read_json(report_path)
        pipeline_status = read_json(pipeline_status_path)
        trace = read_trace(trace_path)
        artifact_dir_rel = artifact_dir.relative_to(ROOT).as_posix()
        latest_run_rel = run_directory.relative_to(ROOT).as_posix() if run_directory else None
        cves.append(
            {
                "cve": cve,
                "report": report,
                "trace": trace,
                "pipeline_status": pipeline_status,
                "progress": summarize_progress(report, trace, pipeline_status),
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
                    "sources_url": repo_url(artifact_dir / "sources", tree=True),
                    "source_diff_url": repo_url(artifact_dir / "research" / "source_diff.patch"),
                    "harness_readme_url": repo_url(artifact_dir / "harness" / "README.md"),
                    "exploiter_stub_url": repo_url(artifact_dir / "exploiter" / "README.md"),
                    "sources_exists": (artifact_dir / "sources").exists(),
                    "trace_exists": trace_path.exists(),
                    "report_exists": report_path.exists(),
                    "report_md_exists": report_md_path.exists(),
                    "pipeline_status_exists": pipeline_status_path.exists(),
                    "source_diff_exists": (artifact_dir / "research" / "source_diff.patch").exists(),
                    "harness_readme_exists": (artifact_dir / "harness" / "README.md").exists(),
                    "exploiter_stub_exists": (artifact_dir / "exploiter" / "README.md").exists(),
                },
            }
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
        },
        "cves": cves,
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
