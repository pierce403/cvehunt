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
        self._agent_notes: list[dict[str, object]] = []

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
        self._agent_notes = []

        cve, ev = self._timed_event(
            phase="Collector",
            fn=lambda: cve_record or self.collector.collect(cve_id),
            message_fn=lambda r: f"Collected metadata for {r.cve_id}",
            artifact_fn=lambda r: "cve.json",
        )
        events.append(ev)
        self._record_agent_notes(
            slug="collector",
            phase="Collector",
            agent="CollectorAgent",
            goal="Collect CVE metadata, source coordinates, version hints, references, and CWE/KEV context.",
            status=ev.status,
            summary=ev.message,
            discovered=[
                f"metadata_source={getattr(cve, 'metadata_source', 'unspecified')}",
                f"name={cve.name}",
                f"ecosystem={cve.ecosystem}",
                f"vulnerable_versions={', '.join(cve.vulnerable_versions) or 'none'}",
                f"patched_versions={', '.join(cve.patched_versions) or 'none'}",
                f"references={len(getattr(cve, 'references', []))}",
                f"cwes={', '.join(getattr(cve, 'cwes', [])) or 'none'}",
            ],
            tried=[
                "Looked for a local fixture first.",
                "If no fixture existed and CVEHUNT_OFFLINE was not set, attempted live CVE metadata collection.",
            ],
            blockers=(
                ["No fixture or live metadata record identified this CVE beyond its ID."]
                if cve.ecosystem == "unknown"
                else []
            ),
            artifacts=["cve.json"],
            next_steps=["Researcher should classify the vulnerability and acquire real source or artifact coordinates."],
        )
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
        self._record_agent_notes(
            slug="researcher",
            phase="Researcher",
            agent="ResearcherAgent",
            goal="Turn CVE metadata into a vulnerability hypothesis, affected surface, source acquisition, and patch signal.",
            status=ev.status,
            summary=ev.message,
            discovered=[
                f"vulnerability_class={finding.vulnerability_class}",
                f"impacted_surface={finding.impacted_surface}",
                f"source_status={sources.status}",
                f"source_ecosystem={sources.ecosystem}",
                f"package={sources.package or 'unknown'}",
                f"changed_files={len(sources.changed_files)}",
                *sources.notes,
            ],
            tried=[
                "Classified the CVE summary and references into a vulnerability class.",
                f"Attempted source acquisition for ecosystem {sources.ecosystem}.",
            ],
            blockers=(
                [f"Source acquisition did not materialize vulnerable/patched trees: {sources.status}."]
                if sources.status != "materialized"
                else []
            ),
            artifacts=[item for item in [sources.diff_path] if item],
            next_steps=["Harness Builder should select an isolation backend and emit a concrete target setup contract."],
        )
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
        self._record_agent_notes(
            slug="harness-builder",
            phase="Harness Builder",
            agent="HarnessBuilderAgent",
            goal="Create the isolated vulnerable/patched target setup contract and runnable harness scaffolding when possible.",
            status=ev.status,
            summary=ev.message,
            discovered=[
                f"harness_status={harness.status}",
                f"runtime={harness.runtime}",
                f"isolation={harness.isolation}",
                f"dockerfiles={len(harness.dockerfiles)}",
                f"helper_scripts={len(harness.helper_scripts)}",
                *harness.notes,
            ],
            tried=[
                "Selected a backend based on source availability, ecosystem, vulnerability class, and target boundary.",
                "Wrote target-environment.json, SETUP.md, and run-targets.sh so later agents do not guess setup.",
            ],
            blockers=[note for note in harness.notes if note.lower().startswith("missing required artifact")],
            artifacts=[*harness.dockerfiles, *harness.helper_scripts],
            next_steps=["Exploiter should only proceed against a materialized and servable target."],
        )
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
        self._record_exploiter_notes(exploiter, ev, slug="exploiter", phase="Exploiter", runner=False)
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
            self._record_exploiter_notes(
                exploiter,
                ev,
                slug="harness-runner",
                phase="Harness Runner",
                runner=True,
            )
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
            self._record_agent_notes(
                slug="provision",
                phase="Provision",
                agent="ProvisionAgent",
                goal="Build/start the target setup and prove the vulnerable and patched surfaces are servable before exploitation is credited.",
                status=ev.status,
                summary=ev.message,
                discovered=[
                    f"provision_status={provision.status}",
                    f"target_count={len(provision.targets)}",
                    *[
                        f"{target.name}: ready={target.ready}, servable={target.servable}, url={target.url}, detail={target.detail}"
                        for target in provision.targets
                    ],
                ],
                tried=[
                    "Delegated target setup/probing to the generated harness runner.",
                    "Recorded readiness and instrumentation health in provision/provision.json.",
                ],
                blockers=(
                    [provision.note]
                    if provision.status not in {"servable", "partially_servable"} and provision.note
                    else []
                ),
                artifacts=[item for item in [provision.json_path, provision.log_path] if item],
                next_steps=["Adversarial Loop should run only against targets recorded as servable."],
            )
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
            self._record_agent_notes(
                slug="adversarial-loop",
                phase="Adversarial Loop",
                agent="AdversarialLoopAgent",
                goal="Run bounded exploit, defense, and residual rounds against the servable harness.",
                status=ev.status,
                summary=ev.message,
                discovered=[
                    f"executed={negotiation.executed}",
                    f"verdict={negotiation.verdict}",
                    f"rounds_total={negotiation.rounds_total}",
                    f"exploit_rounds={negotiation.exploit_rounds}",
                    f"defense_rounds={negotiation.defense_rounds}",
                    f"residual_rounds={negotiation.residual_rounds}",
                    f"escalation_achieved={negotiation.escalation_achieved}",
                    f"patch_effective={negotiation.patch_effective}",
                    f"residual_bypass={negotiation.residual_bypass}",
                ],
                tried=[
                    "Compared vulnerable and patched target outcomes using recorded exploit primitives.",
                    "Recorded exploit/defense/residual round files when rounds were available.",
                ],
                blockers=(
                    [negotiation.rationale]
                    if negotiation.verdict in {"blocked_needs_artifact", "not_executed", "target_not_servable"}
                    and negotiation.rationale
                    else []
                ),
                artifacts=[item for item in [negotiation.log_path, negotiation.verdict_path] if item],
                next_steps=["Fix Developer and Judge should rely on behavioral outcomes, not artifact existence."],
            )
        else:
            self._record_skipped_execution_notes()
        fix, ev = self._timed_event(
            phase="Fix Developer",
            fn=lambda: self.fix_developer.develop(cve, sources, finding, self.last_artifact_root),
            message_fn=lambda r: r.message,
            artifact_fn=lambda r: r.candidate_patch,
            status_fn=lambda r: r.status,
        )
        events.append(ev)
        self._record_agent_notes(
            slug="fix-developer",
            phase="Fix Developer",
            agent="FixDeveloperAgent",
            goal="Generate, promote, or validate a candidate remediation from real vulnerable-to-patched evidence.",
            status=ev.status,
            summary=ev.message,
            discovered=[
                f"fix_status={fix.status}",
                f"candidate_patch={fix.candidate_patch or 'none'}",
                f"rationale={fix.rationale or 'none'}",
                *fix.notes,
            ],
            tried=[
                "Looked for a materialized upstream diff to promote into a candidate fix.",
                "Validated candidate application when a vulnerable source tree and patch were available.",
            ],
            blockers=(
                [fix.message]
                if fix.status in {"not_applicable", "rejected", "not_implemented"}
                else []
            ),
            artifacts=[item for item in [fix.candidate_patch, fix.rationale, "fix/validation.json"] if item],
            next_steps=["Validator should compare behavioral outcomes and fix validation artifacts."],
        )
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
        passed = [item.check_name for item in evidence if item.passed]
        failed = [item.check_name for item in evidence if not item.passed]
        self._record_agent_notes(
            slug="validator",
            phase="Validator",
            agent="ValidatorAgent",
            goal="Collect evidence that the vulnerable target escalated and the patched/fixed target blocked the same behavior.",
            status=ev.status,
            summary=ev.message,
            discovered=[
                f"evidence_total={len(evidence)}",
                f"evidence_passed={len(passed)}",
                f"passed_checks={', '.join(passed) or 'none'}",
                f"failed_checks={', '.join(failed) or 'none'}",
            ],
            tried=[
                "Checked structural setup evidence separately from behavioral proof.",
                "Compared vulnerable, patched, and candidate-fix signals when available.",
            ],
            blockers=failed,
            artifacts=[item.artifact for item in evidence if item.artifact],
            next_steps=["Judge should assign status/confidence from behavioral evidence and residual risk."],
        )
        judgement, ev = self._timed_event(
            phase="Judge",
            fn=lambda: self.judge.judge(
                cve, finding, sources, harness, exploiter, fix, evidence, provision, negotiation
            ),
            message_fn=lambda r: f"Assigned {r.status} with {r.confidence:.2f} confidence",
            artifact_fn=lambda r: "report.json",
        )
        events.append(ev)
        self._record_agent_notes(
            slug="judge",
            phase="Judge",
            agent="JudgeAgent",
            goal="Produce the final explainable exploitability/remediation judgement from evidence and safety boundaries.",
            status=ev.status,
            summary=ev.message,
            discovered=[
                f"judgement_status={judgement.status}",
                f"confidence={judgement.confidence:.2f}",
                f"rationale={judgement.rationale}",
            ],
            tried=[
                "Reviewed structural evidence, behavioral outcomes, fix validation, and safety boundaries.",
                "Avoided defensive-signal claims unless exploitability and patched blocking were observed.",
            ],
            blockers=judgement.remediation_notes,
            artifacts=["report.json", "report.md", "pipeline_status.json"],
            next_steps=judgement.safety_notes,
        )
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

    def _record_exploiter_notes(
        self,
        exploiter,
        event: TraceEvent,
        *,
        slug: str,
        phase: str,
        runner: bool,
    ) -> None:
        outcomes = [
            f"{outcome.variant}: triggered={outcome.triggered}, detail={outcome.detail}"
            for outcome in exploiter.outcomes
        ]
        self._record_agent_notes(
            slug=slug,
            phase=phase,
            agent="HarnessRunnerAgent" if runner else "ExploiterAgent",
            goal=(
                "Build/run the generated harness and execute the harness-scoped PoC."
                if runner
                else "Develop a harness-scoped PoC and investigation plan against the real local target."
            ),
            status=event.status,
            summary=event.message,
            discovered=[
                f"exploiter_status={exploiter.status}",
                f"implemented={exploiter.implemented}",
                f"artifact={exploiter.artifact or 'none'}",
                f"target_urls={exploiter.target_urls or {}}",
                *(outcomes or ["outcomes=none"]),
            ],
            tried=(
                [
                    "Attempted to build/start the generated harness and run exploiter/run-poc.sh.",
                    "Recorded per-target observed outcomes when the runner executed.",
                ]
                if runner
                else [
                    "Checked whether the harness was materialized before authoring a PoC.",
                    "Generated investigation and PoC artifacts only when a target contract was runnable.",
                ]
            ),
            blockers=(
                [exploiter.message]
                if exploiter.status in {"not_supported", "stubbed"} and exploiter.message
                else []
            ),
            artifacts=[
                item
                for item in [
                    exploiter.artifact,
                    exploiter.poc_path,
                    exploiter.runner_path,
                    exploiter.investigation_path,
                    exploiter.investigation_json_path,
                ]
                if item
            ],
            next_steps=[exploiter.next_step],
        )

    def _record_skipped_execution_notes(self) -> None:
        for slug, phase, agent, goal in [
            (
                "harness-runner",
                "Harness Runner",
                "HarnessRunnerAgent",
                "Build/run the generated harness and execute the harness-scoped PoC.",
            ),
            (
                "provision",
                "Provision",
                "ProvisionAgent",
                "Build/start the target setup and prove the vulnerable and patched surfaces are servable before exploitation is credited.",
            ),
            (
                "adversarial-loop",
                "Adversarial Loop",
                "AdversarialLoopAgent",
                "Run bounded exploit, defense, and residual rounds against the servable harness.",
            ),
        ]:
            self._record_agent_notes(
                slug=slug,
                phase=phase,
                agent=agent,
                goal=goal,
                status="skipped",
                summary="Target execution was not requested for this run.",
                discovered=["No runtime outcomes were collected because --execute-poc was not set."],
                tried=["Skipped by workflow configuration."],
                blockers=["Run with --execute-poc after target setup artifacts are satisfiable."],
                artifacts=[],
                next_steps=["Enable target execution when a runnable harness is available."],
            )

    def _record_agent_notes(
        self,
        *,
        slug: str,
        phase: str,
        agent: str,
        goal: str,
        status: str,
        summary: str,
        discovered: list[str],
        tried: list[str],
        blockers: list[str],
        artifacts: list[str],
        next_steps: list[str],
    ) -> None:
        if self.last_artifact_root is None:
            return
        note = {
            "slug": slug,
            "phase": phase,
            "agent": agent,
            "goal": goal,
            "status": status,
            "summary": summary,
            "discovered": _clean_items(discovered),
            "tried": _clean_items(tried),
            "blockers": _clean_items(blockers),
            "artifacts": _clean_items(artifacts),
            "next_steps": _clean_items(next_steps),
        }
        self._agent_notes.append(note)
        phase_dir = self.last_artifact_root / "agent-notes" / slug
        phase_dir.mkdir(parents=True, exist_ok=True)
        (phase_dir / "NOTES.md").write_text(
            _render_agent_note(note),
            encoding="utf-8",
        )
        (self.last_artifact_root / "NOTES.md").write_text(
            _render_notes_index(self._agent_notes),
            encoding="utf-8",
        )


def _clean_items(items: list[object]) -> list[str]:
    cleaned: list[str] = []
    seen: set[str] = set()
    for item in items:
        if item is None:
            continue
        text = str(item).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        cleaned.append(text)
    return cleaned


def _render_agent_note(note: dict[str, object]) -> str:
    lines = [
        f"# {note['phase']} Notes",
        "",
        f"- Agent: {note['agent']}",
        f"- Status: {note['status']}",
        f"- Goal: {note['goal']}",
        f"- Summary: {note['summary']}",
        "",
    ]
    for title, key, fallback in [
        ("Things Discovered", "discovered", "Nothing concrete recorded."),
        ("Things Tried", "tried", "No attempts recorded."),
        ("Things That Did Not Work / Blockers", "blockers", "No blockers recorded."),
        ("Artifacts", "artifacts", "No artifacts recorded."),
        ("Next Steps", "next_steps", "No next steps recorded."),
    ]:
        lines.extend([f"## {title}", ""])
        values = note.get(key)
        if isinstance(values, list) and values:
            lines.extend(f"- {value}" for value in values)
        else:
            lines.append(f"- {fallback}")
        lines.append("")
    return "\n".join(lines)


def _render_notes_index(notes: list[dict[str, object]]) -> str:
    lines = [
        "# CVEHunt Run Notes",
        "",
        "These notes are written as each pipeline agent finishes. They are meant to",
        "show what each agent was trying to do, what it learned, what it attempted,",
        "and what blocked or shaped the next phase.",
        "",
        "## Agent Summary",
        "",
    ]
    for note in notes:
        phase = str(note["phase"])
        slug = str(note["slug"])
        lines.extend(
            [
                f"### {phase}",
                "",
                f"- Agent: {note['agent']}",
                f"- Status: {note['status']}",
                f"- Summary: {note['summary']}",
                f"- Notes: `agent-notes/{slug}/NOTES.md`",
                "",
            ]
        )
    return "\n".join(lines)
