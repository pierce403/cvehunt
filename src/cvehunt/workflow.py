from __future__ import annotations

from cvehunt.agents import (
    CollectorAgent,
    EnvironmentPlannerAgent,
    JudgeAgent,
    ResearcherAgent,
    ValidatorAgent,
)
from cvehunt.models import WorkflowReport
from cvehunt.models import CveRecord, TraceEvent


class CveHuntWorkflow:
    def __init__(self) -> None:
        self.collector = CollectorAgent()
        self.researcher = ResearcherAgent()
        self.planner = EnvironmentPlannerAgent()
        self.validator = ValidatorAgent()
        self.judge = JudgeAgent()

    def run(
        self,
        cve_id: str,
        cve_record: CveRecord | None = None,
    ) -> WorkflowReport:
        report, _events = self.run_with_trace(cve_id, cve_record)
        return report

    def run_with_trace(
        self,
        cve_id: str,
        cve_record: CveRecord | None = None,
    ) -> tuple[WorkflowReport, list[TraceEvent]]:
        events: list[TraceEvent] = []
        cve = cve_record or self.collector.collect(cve_id)
        events.append(
            TraceEvent(
                phase="Collector",
                message=f"Collected metadata for {cve.cve_id}",
                artifact="cve.json",
            )
        )
        finding = self.researcher.research(cve)
        events.append(
            TraceEvent(
                phase="Researcher",
                message=(
                    f"Classified as {finding.vulnerability_class}; "
                    f"surface: {finding.impacted_surface}"
                ),
            )
        )
        plan = self.planner.plan(cve, finding)
        events.append(
            TraceEvent(
                phase="Environment Planner",
                message=f"Created {len(plan.checks)} offline validation check(s)",
            )
        )
        evidence = self.validator.validate(cve, plan)
        events.append(
            TraceEvent(
                phase="Validator",
                message=(
                    f"Collected {sum(1 for item in evidence if item.passed)} "
                    f"passing evidence item(s) out of {len(evidence)}"
                ),
            )
        )
        judgement = self.judge.judge(cve, finding, evidence)
        events.append(
            TraceEvent(
                phase="Judge",
                message=(
                    f"Assigned {judgement.status} with "
                    f"{judgement.confidence:.2f} confidence"
                ),
                artifact="report.json",
            )
        )
        report = WorkflowReport(
            cve=cve,
            finding=finding,
            plan=plan,
            evidence=evidence,
            judgement=judgement,
        )
        return report, events
