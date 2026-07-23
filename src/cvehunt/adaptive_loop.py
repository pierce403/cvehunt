"""Model-pure adaptive exploit revision loop with bounded trusted feedback.

This module owns no provider, target, exploit, or oracle logic.  It is the small
state machine that repeatedly invokes one selected model and one trusted
executor under a single caller-supplied monotonic deadline.
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass
from types import MappingProxyType
from typing import Callable, Mapping, Protocol, Sequence

from .stage_contracts import CAPABILITY_RECEIPT_SCHEMA, StageContractError, sha256_bytes

MAX_REVISION_ATTEMPTS = 64


class AdaptiveLoopError(RuntimeError):
    """The adaptive loop or one of its trusted boundaries failed closed."""


@dataclass(frozen=True)
class ModelIdentity:
    provider: str
    model: str
    harness: str


@dataclass(frozen=True)
class RevisionFeedback:
    """Bounded host-owned feedback safe to return to the selected model."""

    attempt: int
    candidate_commitment: str
    target_digest: str
    oracle_digest: str
    nonce_commitment: str
    observed_interaction_commitment: str
    trusted_result: bool
    infrastructure_disposition: str
    execution_result_commitment: str
    evidence_commitment: str
    evidence_bytes: int


@dataclass(frozen=True)
class RevisionRequest:
    cve_id: str
    attempt: int
    remaining_run_seconds: float
    feedback: tuple[RevisionFeedback, ...]


@dataclass(frozen=True)
class ModelRevision:
    identity: ModelIdentity
    status: str
    proposal: object | None = None
    refusal_kind: str | None = None


@dataclass(frozen=True)
class TrustedExecution:
    receipts: Sequence[Mapping[str, object]]


@dataclass(frozen=True)
class AdaptiveLoopResult:
    termination_reason: str
    attempts: int
    feedback: tuple[RevisionFeedback, ...]
    trusted_capability_receipt: Mapping[str, object] | None
    refusal_kind: str | None = None
    error_code: str | None = None


class RevisionModel(Protocol):
    def __call__(self, request: RevisionRequest, /) -> ModelRevision: ...


class RevisionExecutor(Protocol):
    def __call__(
        self, revision: ModelRevision, /, *, remaining_run_seconds: float,
    ) -> TrustedExecution: ...


def run_adaptive_exploit_loop(
    *,
    cve_id: str,
    selected_identity: ModelIdentity,
    deadline: float,
    revise: RevisionModel,
    execute: RevisionExecutor,
    monotonic: Callable[[], float] = time.monotonic,
    max_attempts: int = MAX_REVISION_ATTEMPTS,
) -> AdaptiveLoopResult:
    """Revise and execute until trusted proof, refusal, error, deadline, or cap.

    ``deadline`` is absolute and must have been created before the first model
    gate.  The loop never resets it.  Only exact positive vulnerable-control
    capability receipts can terminate with ``trusted_capability_proved``.
    Candidate prose and proposal fields are deliberately never inspected.
    """
    _identity(selected_identity)
    if (
        not isinstance(deadline, (int, float))
        or isinstance(deadline, bool)
        or not math.isfinite(float(deadline))
    ):
        raise ValueError("deadline must be a finite absolute monotonic value")
    if type(max_attempts) is not int or not 1 <= max_attempts <= MAX_REVISION_ATTEMPTS:
        raise ValueError(f"max_attempts must be an integer in 1..{MAX_REVISION_ATTEMPTS}")

    feedback: list[RevisionFeedback] = []
    for attempt in range(1, max_attempts + 1):
        remaining = float(deadline) - monotonic()
        if remaining <= 0:
            return AdaptiveLoopResult(
                "run_deadline_exhausted", attempt - 1, tuple(feedback), None,
            )
        request = RevisionRequest(cve_id, attempt, remaining, tuple(feedback))
        try:
            revision = revise(request)
        except Exception as exc:
            return AdaptiveLoopResult(
                "infrastructure_error", attempt - 1, tuple(feedback), None,
                error_code=type(exc).__name__,
            )
        if not isinstance(revision, ModelRevision):
            return AdaptiveLoopResult(
                "model_or_contract_failure", attempt - 1, tuple(feedback), None,
                error_code="invalid_model_revision_type",
            )
        if revision.identity != selected_identity:
            return AdaptiveLoopResult(
                "model_or_contract_failure", attempt - 1, tuple(feedback), None,
                error_code="model_identity_mismatch",
            )
        if revision.status == "refused":
            if (
                not isinstance(revision.refusal_kind, str)
                or not revision.refusal_kind.strip()
                or revision.proposal is not None
            ):
                return AdaptiveLoopResult(
                    "model_or_contract_failure", attempt - 1, tuple(feedback), None,
                    error_code="invalid_model_refusal",
                )
            return AdaptiveLoopResult(
                "model_refusal", attempt - 1, tuple(feedback), None,
                refusal_kind=revision.refusal_kind,
            )
        if (
            revision.status != "completed"
            or revision.refusal_kind is not None
            or revision.proposal is None
        ):
            return AdaptiveLoopResult(
                "model_or_contract_failure", attempt - 1, tuple(feedback), None,
                error_code="invalid_model_revision_status",
            )

        remaining = float(deadline) - monotonic()
        if remaining <= 0:
            return AdaptiveLoopResult(
                "run_deadline_exhausted", attempt - 1, tuple(feedback), None,
            )
        try:
            execution = execute(revision, remaining_run_seconds=remaining)
            if float(deadline) - monotonic() <= 0:
                return AdaptiveLoopResult(
                    "run_deadline_exhausted", attempt, tuple(feedback), None,
                )
            receipt = _one_receipt(execution, cve_id)
            bounded = _feedback(attempt, receipt)
        except (StageContractError, AdaptiveLoopError) as exc:
            return AdaptiveLoopResult(
                "model_or_contract_failure", attempt, tuple(feedback), None,
                error_code=type(exc).__name__,
            )
        except Exception as exc:
            return AdaptiveLoopResult(
                "infrastructure_error", attempt, tuple(feedback), None,
                error_code=type(exc).__name__,
            )
        feedback.append(bounded)
        if receipt["trusted_result"] is True:
            return AdaptiveLoopResult(
                "trusted_capability_proved", attempt, tuple(feedback),
                MappingProxyType(dict(receipt)),
            )

    return AdaptiveLoopResult(
        "revision_limit_exhausted", max_attempts, tuple(feedback), None,
    )


def _identity(value: ModelIdentity) -> None:
    if not isinstance(value, ModelIdentity) or any(
        not isinstance(item, str) or not item.strip()
        for item in (value.provider, value.model, value.harness)
    ):
        raise ValueError("selected identity must contain provider, model, and harness")


def _one_receipt(execution: object, cve_id: str) -> Mapping[str, object]:
    if not isinstance(execution, TrustedExecution):
        raise AdaptiveLoopError("trusted executor returned the wrong type")
    receipts = execution.receipts
    if (
        not isinstance(receipts, Sequence)
        or isinstance(receipts, (str, bytes, bytearray))
        or len(receipts) != 1
        or not isinstance(receipts[0], Mapping)
    ):
        raise AdaptiveLoopError("each revision requires exactly one trusted receipt")
    receipt = receipts[0]
    required = {
        "schema", "cve_id", "variant", "trusted_result", "candidate_commitment",
        "target_digest", "oracle_digest", "nonce_commitment",
        "observed_interaction_commitment", "execution_result",
        "infrastructure_disposition", "evidence_sha256", "evidence_bytes",
    }
    if set(receipt) != required:
        raise StageContractError("adaptive receipt has unknown or missing fields")
    if receipt.get("schema") != CAPABILITY_RECEIPT_SCHEMA or receipt.get("cve_id") != cve_id:
        raise StageContractError("adaptive receipt schema or CVE mismatch")
    if receipt.get("variant") != "vulnerable":
        raise StageContractError("adaptive exploit receipt must use the vulnerable control")
    if not isinstance(receipt.get("trusted_result"), bool):
        raise StageContractError("adaptive trusted_result must be boolean")
    for field in (
        "candidate_commitment", "target_digest", "nonce_commitment",
        "observed_interaction_commitment", "evidence_sha256",
    ):
        _sha(receipt.get(field), field)
    oracle = receipt.get("oracle_digest")
    _sha(oracle, "oracle_digest")
    execution_result = receipt.get("execution_result")
    if (
        not isinstance(execution_result, Mapping)
        or set(execution_result) != {"status", "commitment"}
        or execution_result.get("status") != "completed"
    ):
        raise StageContractError("adaptive execution result is invalid")
    _sha(execution_result.get("commitment"), "execution_result.commitment")
    if receipt.get("infrastructure_disposition") != "completed":
        raise StageContractError("adaptive execution infrastructure did not complete")
    evidence_bytes = receipt.get("evidence_bytes")
    if type(evidence_bytes) is not int or evidence_bytes < 0:
        raise StageContractError("adaptive evidence_bytes must be non-negative")
    if receipt["trusted_result"] is True:
        if receipt["observed_interaction_commitment"] == sha256_bytes(b""):
            raise StageContractError("positive adaptive receipt requires host interaction")
    return receipt


def _feedback(attempt: int, receipt: Mapping[str, object]) -> RevisionFeedback:
    execution_result = receipt["execution_result"]
    assert isinstance(execution_result, Mapping)
    evidence_bytes = receipt["evidence_bytes"]
    assert type(evidence_bytes) is int
    return RevisionFeedback(
        attempt=attempt,
        candidate_commitment=str(receipt["candidate_commitment"]),
        target_digest=str(receipt["target_digest"]),
        oracle_digest=str(receipt["oracle_digest"]),
        nonce_commitment=str(receipt["nonce_commitment"]),
        observed_interaction_commitment=str(receipt["observed_interaction_commitment"]),
        trusted_result=receipt["trusted_result"] is True,
        infrastructure_disposition=str(receipt["infrastructure_disposition"]),
        execution_result_commitment=str(execution_result["commitment"]),
        evidence_commitment=str(receipt["evidence_sha256"]),
        evidence_bytes=evidence_bytes,
    )


def _sha(value: object, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise StageContractError(f"{field} must be a lowercase SHA-256 digest")
    return value


__all__ = [
    "AdaptiveLoopError", "AdaptiveLoopResult", "MAX_REVISION_ATTEMPTS",
    "ModelIdentity", "ModelRevision", "RevisionFeedback", "RevisionRequest",
    "TrustedExecution", "run_adaptive_exploit_loop",
]
