from __future__ import annotations

from openmoak.agents import (
    CollectorAgent,
    EnvironmentPlannerAgent,
    JudgeAgent,
    ResearcherAgent,
    ValidatorAgent,
)
from openmoak.models import WorkflowReport


class OpenMoakWorkflow:
    def __init__(self) -> None:
        self.collector = CollectorAgent()
        self.researcher = ResearcherAgent()
        self.planner = EnvironmentPlannerAgent()
        self.validator = ValidatorAgent()
        self.judge = JudgeAgent()

    def run(self, cve_id: str) -> WorkflowReport:
        cve = self.collector.collect(cve_id)
        finding = self.researcher.research(cve)
        plan = self.planner.plan(cve, finding)
        evidence = self.validator.validate(cve, plan)
        judgement = self.judge.judge(cve, finding, evidence)
        return WorkflowReport(
            cve=cve,
            finding=finding,
            plan=plan,
            evidence=evidence,
            judgement=judgement,
        )

