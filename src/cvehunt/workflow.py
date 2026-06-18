from __future__ import annotations

import tempfile
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
from cvehunt.models import WorkflowReport
from cvehunt.models import CveRecord, RunMetadata, TraceEvent


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

    def run_with_trace(
        self,
        cve_id: str,
        cve_record: CveRecord | None = None,
        artifact_root: Path | None = None,
        execute_poc: bool = False,
        residual_rounds: int = 0,
    ) -> tuple[WorkflowReport, list[TraceEvent]]:
        events: list[TraceEvent] = []
        self.last_artifact_root = artifact_root or Path(
            tempfile.mkdtemp(prefix=f"cvehunt-{cve_id.lower()}-")
        )
        cve = cve_record or self.collector.collect(cve_id)
        events.append(
            TraceEvent(
                phase="Collector",
                message=f"Collected metadata for {cve.cve_id}",
                artifact="cve.json",
            )
        )
        finding, sources = self.researcher.research(cve, self.last_artifact_root)
        events.append(
            TraceEvent(
                phase="Researcher",
                message=(
                    f"Classified as {finding.vulnerability_class}; "
                    f"surface: {finding.impacted_surface}"
                ),
                artifact=sources.diff_path or None,
            )
        )
        harness, plan = self.builder.build(cve, finding, sources, self.last_artifact_root, base_port=self.base_port)
        events.append(
            TraceEvent(
                phase="Harness Builder",
                message=(
                    f"{harness.status} with {len(harness.dockerfiles)} Dockerfile(s) "
                    f"and {len(plan.checks)} validation check(s)"
                ),
                artifact=(harness.helper_scripts[-1] if harness.helper_scripts else None),
            )
        )
        exploiter = self.exploiter.run(cve, finding, harness, self.last_artifact_root, base_port=self.base_port)
        provision = None
        negotiation = None
        if execute_poc:
            exploiter = self.harness_runner.run(
                cve, harness, exploiter, self.last_artifact_root
            )
            provision = self.provisioner.run(
                cve, harness, finding, self.last_artifact_root, base_port=self.base_port
            )
            events.append(
                TraceEvent(
                    phase="Provision",
                    message=provision.note,
                    artifact=provision.json_path,
                    status=provision.status,
                )
            )
        events.append(
            TraceEvent(
                phase="Exploiter",
                message=exploiter.message,
                artifact=exploiter.artifact,
                status=exploiter.status,
            )
        )
        if execute_poc:
            negotiation = self.adversarial_loop.run(
                cve, finding, harness, exploiter, provision, self.last_artifact_root,
                base_port=self.base_port, residual_rounds_budget=residual_rounds,
            )
            events.append(
                TraceEvent(
                    phase="Adversarial Loop",
                    message=negotiation.rationale,
                    artifact=negotiation.verdict_path,
                    status=negotiation.verdict,
                )
            )
        fix = self.fix_developer.develop(cve, sources, finding, self.last_artifact_root)
        events.append(
            TraceEvent(
                phase="Fix Developer",
                message=fix.message,
                artifact=fix.candidate_patch,
                status=fix.status,
            )
        )
        evidence = self.validator.validate(
            cve, plan, sources, harness, exploiter, fix, provision, negotiation
        )
        events.append(
            TraceEvent(
                phase="Validator",
                message=(
                    f"Collected {sum(1 for item in evidence if item.passed)} "
                    f"passing evidence item(s) out of {len(evidence)}"
                ),
            )
        )
        judgement = self.judge.judge(
            cve, finding, sources, harness, exploiter, fix, evidence, provision, negotiation
        )
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
            run=RunMetadata(model=self.model),
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
