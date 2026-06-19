from __future__ import annotations

import json
import shutil
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

    def runs_dir(self, cve_id: str) -> Path:
        return self.cve_dir(cve_id) / "runs"

    def run_dir(self, cve_id: str, run_id: str) -> Path:
        return self.runs_dir(cve_id) / run_id

    def write_cve(self, record: CveRecord) -> Path:
        directory = self.cve_dir(record.cve_id)
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "cve.json"
        path.write_text(json.dumps(asdict(record), indent=2), encoding="utf-8")
        return path

    def read_cve(self, cve_id: str) -> CveRecord | None:
        path = self.cve_dir(cve_id) / "cve.json"
        if not path.exists():
            latest = self.latest_run_dir(cve_id)
            if latest is not None:
                path = latest / "cve.json"
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

    def write_report(
        self,
        report: WorkflowReport,
        events: list[TraceEvent],
        artifact_root: Path | None = None,
    ) -> Path:
        directory = self.cve_dir(report.cve.cve_id)
        directory.mkdir(parents=True, exist_ok=True)
        run_directory = self.run_dir(report.cve.cve_id, report.run.run_id)
        same_artifact_root = (
            artifact_root is not None
            and artifact_root.exists()
            and artifact_root.resolve() == run_directory.resolve()
        )
        run_directory.mkdir(parents=True, exist_ok=same_artifact_root)
        pipeline_status = render_pipeline_status(report, events)
        report_path = self._write_run_artifacts(
            run_directory,
            report,
            events,
            pipeline_status,
            artifact_root=artifact_root,
        )
        if pipeline_status["requested_full_pipeline_completed"]:
            self._promote_successful_run(run_directory, directory)
        return report_path

    def latest_run_dir(self, cve_id: str) -> Path | None:
        runs = self.runs_dir(cve_id)
        if not runs.exists():
            return None
        directories = [path for path in runs.iterdir() if path.is_dir()]
        return sorted(directories)[-1] if directories else None

    def list_reports(self) -> list[dict[str, object]]:
        if not self.cves_dir.exists():
            return []
        rows: list[dict[str, object]] = []
        for directory in sorted(self.cves_dir.iterdir()):
            if not directory.is_dir():
                continue
            cve_path = directory / "cve.json"
            run_directory = self.latest_run_dir(directory.name)
            artifact_dir = (
                directory
                if (directory / "report.json").exists() or run_directory is None
                else run_directory
            )
            if not cve_path.exists() and run_directory is not None:
                cve_path = run_directory / "cve.json"
            report_path = artifact_dir / "report.json"
            pipeline_status_path = artifact_dir / "pipeline_status.json"
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
                    "latest_run": str(run_directory) if run_directory else None,
                    "trace": str(artifact_dir / "trace.jsonl"),
                }
            )
        return rows

    def _write_run_artifacts(
        self,
        directory: Path,
        report: WorkflowReport,
        events: list[TraceEvent],
        pipeline_status: dict[str, object],
        artifact_root: Path | None = None,
    ) -> Path:
        if artifact_root is not None and artifact_root.exists():
            if artifact_root.resolve() != directory.resolve():
                self._copy_tree(artifact_root, directory)
        (directory / "cve.json").write_text(
            json.dumps(asdict(report.cve), indent=2),
            encoding="utf-8",
        )
        with (directory / "trace.jsonl").open("w", encoding="utf-8") as handle:
            for event in events:
                handle.write(json.dumps(event.to_dict()) + "\n")
        report_path = directory / "report.json"
        report_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        (directory / "report.md").write_text(render_markdown(report), encoding="utf-8")
        (directory / "pipeline_status.json").write_text(
            json.dumps(pipeline_status, indent=2),
            encoding="utf-8",
        )
        return report_path

    def _promote_successful_run(self, run_directory: Path, cve_directory: Path) -> None:
        for name in (
            "cve.json",
            "trace.jsonl",
            "report.json",
            "report.md",
            "pipeline_status.json",
        ):
            shutil.copy2(run_directory / name, cve_directory / name)

    def _copy_tree(self, src: Path, dest: Path) -> None:
        for path in sorted(src.rglob("*")):
            relative = path.relative_to(src)
            target = dest / relative
            if path.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
