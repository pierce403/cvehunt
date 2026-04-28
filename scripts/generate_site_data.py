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


def summarize_progress(report: dict[str, object] | None, trace: list[dict[str, object]]) -> dict[str, object]:
    completed_phases = [str(event.get("phase", "")) for event in trace]
    if not report:
        return {
            "autonomous_status": "not_analyzed",
            "summary": "No autonomous workflow has been run for this CVE yet.",
            "completed_phases": completed_phases,
            "exploit_generated": False,
            "patch_generated": False,
            "exploit_note": "Not attempted. CVEHunt is a defensive pipeline and does not generate exploit code or payloads.",
            "patch_note": "No patch artifact has been generated. Only remediation guidance is available after analysis.",
        }

    judgement = report.get("judgement", {})
    status = judgement.get("status", "unknown") if isinstance(judgement, dict) else "unknown"
    return {
        "autonomous_status": status,
        "summary": "The workflow completed defensive triage using safe local fixtures.",
        "completed_phases": completed_phases,
        "exploit_generated": False,
        "patch_generated": False,
        "exploit_note": "No full exploit was generated or published. The run stopped at safe differential evidence.",
        "patch_note": "No source patch was generated. The report contains patch-version and remediation guidance only.",
    }


def build() -> dict[str, object]:
    cves = []
    for directory in sorted(DATA_DIR.iterdir() if DATA_DIR.exists() else []):
        if not directory.is_dir():
            continue
        cve_path = directory / "cve.json"
        cve = read_json(cve_path)
        if not cve:
            continue
        report_path = directory / "report.json"
        trace_path = directory / "trace.jsonl"
        report_md_path = directory / "report.md"
        pipeline_status_path = directory / "pipeline_status.json"
        report = read_json(report_path)
        pipeline_status = read_json(pipeline_status_path)
        trace = read_trace(trace_path)
        cves.append(
            {
                "cve": cve,
                "report": report,
                "trace": trace,
                "pipeline_status": pipeline_status,
                "progress": summarize_progress(report, trace),
                "artifacts": {
                    "workdir": directory.relative_to(ROOT).as_posix(),
                    "workdir_url": repo_url(directory, tree=True),
                    "cve_json_url": repo_url(cve_path),
                    "trace_url": repo_url(trace_path),
                    "report_json_url": repo_url(report_path),
                    "report_md_url": repo_url(report_md_path),
                    "pipeline_status_url": repo_url(pipeline_status_path),
                    "trace_exists": trace_path.exists(),
                    "report_exists": report_path.exists(),
                    "report_md_exists": report_md_path.exists(),
                    "pipeline_status_exists": pipeline_status_path.exists(),
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


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(build(), indent=2), encoding="utf-8")
    print(OUT)


if __name__ == "__main__":
    main()
