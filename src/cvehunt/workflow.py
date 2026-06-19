from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path

from cvehunt.agents import (
    AdversarialLoopAgent,
    CollectorAgent,
    ExploiterAgent,
    FixDeveloperAgent,
    HarnessBuilderAgent,
    HarnessRunnerAgent,
    JudgeAgent,
    ProvisionAgent,
    ResearcherAgent,
    ValidatorAgent,
)
from cvehunt.models import CveRecord, RunMetadata, TraceEvent, WorkflowReport


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


class CveHuntWorkflow:
    def __init__(self, model: str = "unspecified", base_port: int = 4000) -> None:
        self.model = model
        self.base_port = base_port
        self.collector = CollectorAgent()
        self.researcher = ResearcherAgent()
        self.builder = HarnessBuilderAgent()
        self.exploiter = ExploiterAgent()
        self.harness_runner = HarnessRunnerAgent()
        self.provisioner = ProvisionAgent()
        self.adversarial_loop = AdversarialLoopAgent()
        self.fix_developer = FixDeveloperAgent()
        self.validator = ValidatorAgent()
        self.judge = JudgeAgent()
        self.last_artifact_root: Path | None = None

    def run(
        self,
        cve_id: str,
        cve_record: CveRecord | None = None,
    ) -> WorkflowReport:
        report, _events = self.run_with_trace(cve_id, cve_record)
        return report

    @staticmethod
    def _timed(fn, *args, **kwargs):
        """Run a stage callable and return (result, started_at, completed_at, duration_ms)."""
        started_iso = _now_iso()
        start = time.perf_counter()
        result = fn(*args, **kwargs)
        duration_ms = int((time.perf_counter() - start) * 1000)
        completed_iso = _now_iso()
        return result, started_iso, completed_iso, duration_ms

    def _timed_event(
        self, *, phase, fn, message_fn, artifact_fn=None, status_fn=None
    ) -> tuple[object, TraceEvent]:
        """Run a stage (via a thunk `fn`) and emit a TraceEvent with timing."""
        result, started_iso, completed_iso, duration_ms = self._timed(fn)
        event = self._event(
            phase=phase,
            message=message_fn(result),
            artifact=artifact_fn(result) if artifact_fn else None,
            status=status_fn(result) if status_fn else "completed",
            started_at=started_iso,
            completed_at=completed_iso,
            duration_ms=duration_ms,
        )
        return result, event

    def _event(
        self,
        *,
        phase: str,
        message: str,
        artifact: str | None = None,
        status: str = "completed",
        started_at: str = "",
        completed_at: str = "",
        duration_ms: int = 0,
        token_usage: dict[str, int] | None = None,
    ) -> TraceEvent:
        return TraceEvent(
            phase=phase,
            message=message,
            artifact=artifact,
            status=status,
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=duration_ms,
            token_usage=token_usage,
        )

    def run_with_trace(
        self,
        cve_id: str,
        cve_record: CveRecord | None = None,
        artifact_root: Path | None = None,
        run_id: str | None = None,
        execute_poc: bool = False,
        residual_rounds: int = 0,
    ) -> tuple[WorkflowReport, list[TraceEvent]]:
        events: list[TraceEvent] = []
        run = (
            RunMetadata(model=self.model)
            if run_id is None
            else RunMetadata(run_id=run_id, model=self.model)
        )
        self.last_artifact_root = artifact_root or (
            Path("cves") / cve_id.upper() / "runs" / run.run_id
        )
        self.last_artifact_root.mkdir(parents=True, exist_ok=True)

        cve, ev = self._timed_event(
            phase="Collector",
            fn=lambda: cve_record or self.collector.collect(cve_id),
            message_fn=lambda r: f"Collected metadata for {r.cve_id}",
            artifact_fn=lambda r: "cve.json",
        )
        events.append(ev)
        (finding, sources), ev = self._timed_event(
            phase="Researcher",
            fn=lambda: self.researcher.research(cve, self.last_artifact_root),
            message_fn=lambda r: (
                f"Classified as {r[0].vulnerability_class}; "
                f"surface: {r[0].impacted_surface}"
            ),
            artifact_fn=lambda r: r[1].diff_path or None,
        )
        events.append(ev)
        (harness, plan), ev = self._timed_event(
            phase="Harness Builder",
            fn=lambda: self.builder.build(
                cve, finding, sources, self.last_artifact_root, base_port=self.base_port
            ),
            message_fn=lambda r: (
                f"{r[0].status} with {len(r[0].dockerfiles)} Dockerfile(s) "
                f"and {len(r[1].checks)} validation check(s)"
            ),
            artifact_fn=lambda r: (r[0].helper_scripts[-1] if r[0].helper_scripts else None),
        )
        events.append(ev)
        exploiter, ev = self._timed_event(
            phase="Exploiter",
            fn=lambda: self.exploiter.run(
                cve, finding, harness, self.last_artifact_root, base_port=self.base_port
            ),
            message_fn=lambda r: r.message,
            artifact_fn=lambda r: r.artifact,
            status_fn=lambda r: r.status,
        )
        events.append(ev)
        provision = None
        negotiation = None
        if execute_poc:
            exploiter, ev = self._timed_event(
                phase="Harness Runner",
                fn=lambda: self.harness_runner.run(cve, harness, exploiter, self.last_artifact_root),
                message_fn=lambda r: r.message,
                artifact_fn=lambda r: "exploiter/outcome.json",
                status_fn=lambda r: r.status,
            )
            events.append(ev)
            provision, ev = self._timed_event(
                phase="Provision",
                fn=lambda: self.provisioner.run(
                    cve, harness, finding, self.last_artifact_root, base_port=self.base_port
                ),
                message_fn=lambda r: r.note,
                artifact_fn=lambda r: r.json_path,
                status_fn=lambda r: r.status,
            )
            events.append(ev)
            negotiation, ev = self._timed_event(
                phase="Adversarial Loop",
                fn=lambda: self.adversarial_loop.run(
                    cve, finding, harness, exploiter, provision, self.last_artifact_root,
                    base_port=self.base_port, residual_rounds_budget=residual_rounds,
                ),
                message_fn=lambda r: r.rationale,
                artifact_fn=lambda r: r.verdict_path,
                status_fn=lambda r: r.verdict,
            )
            events.append(ev)
        fix, ev = self._timed_event(
            phase="Fix Developer",
            fn=lambda: self.fix_developer.develop(cve, sources, finding, self.last_artifact_root),
            message_fn=lambda r: r.message,
            artifact_fn=lambda r: r.candidate_patch,
            status_fn=lambda r: r.status,
        )
        events.append(ev)
        evidence, ev = self._timed_event(
            phase="Validator",
            fn=lambda: self.validator.validate(
                cve, plan, sources, harness, exploiter, fix, provision, negotiation
            ),
            message_fn=lambda r: (
                f"Collected {sum(1 for item in r if item.passed)} "
                f"passing evidence item(s) out of {len(r)}"
            ),
        )
        events.append(ev)
        judgement, ev = self._timed_event(
            phase="Judge",
            fn=lambda: self.judge.judge(
                cve, finding, sources, harness, exploiter, fix, evidence, provision, negotiation
            ),
            message_fn=lambda r: f"Assigned {r.status} with {r.confidence:.2f} confidence",
            artifact_fn=lambda r: "report.json",
        )
        events.append(ev)
        report = WorkflowReport(
            run=run,
            cve=cve,
            finding=finding,
            sources=sources,
            harness=harness,
            exploiter=exploiter,
            fix=fix,
            plan=plan,
            evidence=evidence,
            judgement=judgement,
            provision=provision,
            negotiation=negotiation,
        )
        return report, events
