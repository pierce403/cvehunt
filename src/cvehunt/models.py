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


@dataclass(frozen=True)
class ResearchFinding:
    impacted_surface: str
    vulnerability_class: str
    defensive_hypothesis: str
    relevant_patch_signal: str


@dataclass(frozen=True)
class ValidationCheck:
    name: str
    purpose: str
    safe_method: str
    expected_vulnerable_signal: str
    expected_patched_signal: str


@dataclass(frozen=True)
class ValidationPlan:
    runtime: str
    isolation: str
    checks: list[ValidationCheck]
    forbidden_outputs: list[str]


@dataclass(frozen=True)
class Evidence:
    check_name: str
    vulnerable_signal: str
    patched_signal: str
    passed: bool


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
    plan: ValidationPlan
    evidence: list[Evidence]
    judgement: Judgement

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class TraceEvent:
    phase: str
    message: str
    artifact: str | None = None
    timestamp: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat(timespec="seconds")
    )

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
