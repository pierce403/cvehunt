from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Iterable

from cvehunt.models import CveRecord, TraceEvent, WorkflowReport
from cvehunt.reporting import render_markdown, render_pipeline_status


class WorkdirStore:
    def __init__(self, root: Path | str = ".") -> None:
        self.root = Path(root)
        self.cves_dir = self.root / "cves"

    def ensure(self) -> None:
        self.cves_dir.mkdir(parents=True, exist_ok=True)

    def cve_dir(self, cve_id: str) -> Path:
        return self.cves_dir / cve_id.upper()

    def write_cve(self, record: CveRecord) -> Path:
        directory = self.cve_dir(record.cve_id)
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "cve.json"
        path.write_text(json.dumps(asdict(record), indent=2), encoding="utf-8")
        return path

    def read_cve(self, cve_id: str) -> CveRecord | None:
        path = self.cve_dir(cve_id) / "cve.json"
        if not path.exists():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return CveRecord(**data)

    def append_trace(self, cve_id: str, event: TraceEvent) -> None:
        directory = self.cve_dir(cve_id)
        directory.mkdir(parents=True, exist_ok=True)
        with (directory / "trace.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event.to_dict()) + "\n")

    def write_trace(self, cve_id: str, events: Iterable[TraceEvent]) -> Path:
        directory = self.cve_dir(cve_id)
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "trace.jsonl"
        with path.open("w", encoding="utf-8") as handle:
            for event in events:
                handle.write(json.dumps(event.to_dict()) + "\n")
        return path

    def write_report(self, report: WorkflowReport, events: list[TraceEvent]) -> Path:
        directory = self.cve_dir(report.cve.cve_id)
        directory.mkdir(parents=True, exist_ok=True)
        self.write_cve(report.cve)
        self.write_trace(report.cve.cve_id, events)
        report_path = directory / "report.json"
        report_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        (directory / "report.md").write_text(render_markdown(report), encoding="utf-8")
        (directory / "pipeline_status.json").write_text(
            json.dumps(render_pipeline_status(report, events), indent=2),
            encoding="utf-8",
        )
        return report_path

    def list_reports(self) -> list[dict[str, object]]:
        if not self.cves_dir.exists():
            return []
        rows: list[dict[str, object]] = []
        for directory in sorted(self.cves_dir.iterdir()):
            if not directory.is_dir():
                continue
            cve_path = directory / "cve.json"
            report_path = directory / "report.json"
            pipeline_status_path = directory / "pipeline_status.json"
            if not cve_path.exists():
                continue
            cve = json.loads(cve_path.read_text(encoding="utf-8"))
            report = None
            if report_path.exists():
                report = json.loads(report_path.read_text(encoding="utf-8"))
            pipeline_status = None
            if pipeline_status_path.exists():
                pipeline_status = json.loads(
                    pipeline_status_path.read_text(encoding="utf-8")
                )
            rows.append(
                {
                    "cve": cve,
                    "report": report,
                    "pipeline_status": pipeline_status,
                    "workdir": str(directory),
                    "trace": str(directory / "trace.jsonl"),
                }
            )
        return rows
