from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Literal


def utc_run_id() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H-%M-%SZ")


ExploitabilityStatus = Literal[
    "not_supported",
    "needs_human_review",
    "defensive_signal_observed",
    "insufficient_evidence",
    "exploit_reproduced",
    "patch_verified",
    "residual_bypass_found",
    "target_not_servable",
    "blocked_needs_artifact",
    "backend_unavailable",
]


@dataclass(frozen=True)
class CveRecord:
    cve_id: str
    name: str
    summary: str
    cvss: float | None
    disclosed: str
    ecosystem: str
    vulnerable_versions: list[str]
    patched_versions: list[str]
    kev: bool = False
    known_exploitation_window: str | None = None
    safe_fixture: dict[str, str] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    cwes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ResearchFinding:
    impacted_surface: str
    vulnerability_class: str
    defensive_hypothesis: str
    relevant_patch_signal: str
    changed_files: list[str] = field(default_factory=list)
    research_notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ChangedFile:
    path: str
    additions: int
    deletions: int
    patch_signal: str | None = None


SourceStatus = Literal["materialized", "not_supported", "failed", "blocked_needs_artifact"]


@dataclass(frozen=True)
class SourceBundle:
    status: SourceStatus
    ecosystem: str
    package: str | None
    vulnerable_version: str | None
    patched_version: str | None
    vulnerable_tarball_url: str | None
    patched_tarball_url: str | None
    vulnerable_tarball_sha256: str | None
    patched_tarball_sha256: str | None
    vulnerable_root: str | None
    patched_root: str | None
    diff_path: str | None
    changed_files: list[ChangedFile] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ValidationCheck:
    name: str
    purpose: str
    safe_method: str
    expected_vulnerable_signal: str
    expected_patched_signal: str
    artifact: str | None = None


@dataclass(frozen=True)
class ValidationPlan:
    runtime: str
    isolation: str
    checks: list[ValidationCheck]
    forbidden_outputs: list[str]


HarnessStatus = Literal[
    "built",
    "not_supported",
    "failed",
    "blocked_needs_artifact",
    "backend_unavailable",
]


@dataclass(frozen=True)
class HarnessArtifact:
    status: HarnessStatus
    runtime: str
    isolation: str
    workspace: str
    dockerfiles: list[str] = field(default_factory=list)
    helper_scripts: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


ExploiterStatus = Literal[
    "stubbed",
    "not_supported",
    "scaffolded",
    "executed",
]


@dataclass(frozen=True)
class ExploitOutcome:
    variant: Literal["vulnerable", "patched"]
    triggered: bool
    detail: str


ProvisionStatus = Literal[
    "not_executed",
    "servable",
    "partially_servable",
    "not_servable",
    "skipped",
    "blocked_needs_artifact",
    "backend_unavailable",
]


@dataclass(frozen=True)
class TargetHealth:
    """Per-target provisioning health observation.

    A target is `servable` only when its readiness endpoint answers and an
    instrumented probe of the vulnerable surface returns a recognizable
    response shape. A `console.log`-and-exit stub container is `not_servable`.
    """

    name: str
    url: str
    ready: bool
    servable: bool
    detail: str


@dataclass(frozen=True)
class ProvisionArtifact:
    status: ProvisionStatus
    targets: list[TargetHealth] = field(default_factory=list)
    note: str = ""
    log_path: str | None = None
    json_path: str | None = None


@dataclass(frozen=True)
class NegotiationRound:
    """One observed attempt in the adversarial exploit/defend loop."""

    role: Literal["exploiter", "defender"]
    phase: Literal["exploit", "defense", "residual"]
    round: int
    attempt: str
    request: str
    response: str
    observation: str
    escalated: bool
    blocked: bool
    rationale: str


@dataclass(frozen=True)
class NegotiationLog:
    """Summary of the bounded adversarial loop that proves/disproves the bug."""

    executed: bool
    escalation_achieved: bool
    patch_effective: bool
    residual_bypass: bool
    rounds: list[NegotiationRound] = field(default_factory=list)
    rounds_total: int = 0
    exploit_rounds: int = 0
    defense_rounds: int = 0
    residual_rounds: int = 0
    verdict: str = "not_executed"
    rationale: str = ""
    log_path: str | None = None
    verdict_path: str | None = None


@dataclass(frozen=True)
class ExploiterArtifact:
    implemented: bool
    status: ExploiterStatus
    message: str
    artifact: str | None
    next_step: str
    poc_path: str | None = None
    runner_path: str | None = None
    investigation_path: str | None = None
    investigation_json_path: str | None = None
    target_urls: dict[str, str] = field(default_factory=dict)
    outcomes: list[ExploitOutcome] = field(default_factory=list)


FixStatus = Literal[
    "not_implemented",
    "not_applicable",
    "generated",
    "validated",
    "rejected",
]


@dataclass(frozen=True)
class FixArtifact:
    status: FixStatus
    message: str
    candidate_patch: str | None = None
    rationale: str | None = None
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Evidence:
    check_name: str
    vulnerable_signal: str
    patched_signal: str
    passed: bool
    artifact: str | None = None


@dataclass(frozen=True)
class Judgement:
    status: ExploitabilityStatus
    confidence: float
    rationale: str
    remediation_notes: list[str]
    safety_notes: list[str]


@dataclass(frozen=True)
class RunMetadata:
    run_id: str = field(default_factory=utc_run_id)
    model: str = "unspecified"


@dataclass(frozen=True)
class WorkflowReport:
    run: RunMetadata
    cve: CveRecord
    finding: ResearchFinding
    sources: SourceBundle | None
    harness: HarnessArtifact | None
    exploiter: ExploiterArtifact | None
    fix: FixArtifact | None
    plan: ValidationPlan
    evidence: list[Evidence]
    judgement: Judgement
    provision: ProvisionArtifact | None = None
    negotiation: NegotiationLog | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class TraceEvent:
    phase: str
    message: str
    artifact: str | None = None
    status: str = "completed"
    timestamp: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat(timespec="seconds")
    )
    # Per-stage timing (populated by CveHuntWorkflow so the dashboard can
    # show exactly when each stage started, how long it took, and — for the
    # model-backed stages downstream of contribute.sh — how many tokens it
    # consumed).
    started_at: str = ""
    completed_at: str = ""
    duration_ms: int = 0
    token_usage: dict[str, int] | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
