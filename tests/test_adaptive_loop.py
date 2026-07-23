from __future__ import annotations

from dataclasses import dataclass, field

from cvehunt.adaptive_loop import (
    ModelIdentity,
    ModelRevision,
    RevisionRequest,
    TrustedExecution,
    run_adaptive_exploit_loop,
)
from cvehunt.stage_contracts import StageContractError, sha256_bytes

CVE = "CVE-2026-63030"
IDENTITY = ModelIdentity("pi", "venice/test", "StageHarness")


def receipt(*, trusted: bool, candidate: str = "1") -> dict[str, object]:
    return {
        "schema": "cvehunt.capability-receipt/v1",
        "cve_id": CVE,
        "variant": "vulnerable",
        "trusted_result": trusted,
        "candidate_commitment": candidate * 64,
        "target_digest": "2" * 64,
        "oracle_digest": "3" * 64,
        "nonce_commitment": "4" * 64,
        "observed_interaction_commitment": "5" * 64,
        "execution_result": {"status": "completed", "commitment": "6" * 64},
        "infrastructure_disposition": "completed",
        "evidence_sha256": "7" * 64,
        "evidence_bytes": 12,
    }


@dataclass
class Clock:
    value: float = 100.0

    def __call__(self) -> float:
        return self.value


@dataclass
class FakeModel:
    requests: list[RevisionRequest] = field(default_factory=list)

    def __call__(self, request):
        self.requests.append(request)
        return ModelRevision(IDENTITY, "completed", proposal={"private": request.attempt})


@dataclass
class FakeExecutor:
    prove_at: int
    remaining: list[float] = field(default_factory=list)
    revisions: list[ModelRevision] = field(default_factory=list)

    def __call__(self, revision, *, remaining_run_seconds):
        self.remaining.append(remaining_run_seconds)
        self.revisions.append(revision)
        ordinal = len(self.revisions)
        return TrustedExecution((receipt(trusted=ordinal == self.prove_at, candidate=str(ordinal)),))


def test_same_model_revises_from_bounded_host_feedback_until_trusted_proof() -> None:
    clock = Clock()
    model = FakeModel()
    executor = FakeExecutor(prove_at=3)

    result = run_adaptive_exploit_loop(
        cve_id=CVE,
        selected_identity=IDENTITY,
        deadline=110.0,
        revise=model,
        execute=executor,
        monotonic=clock,
        max_attempts=5,
    )

    assert result.termination_reason == "trusted_capability_proved"
    assert result.attempts == 3
    assert result.trusted_capability_receipt is not None
    assert len(model.requests) == len(executor.revisions) == 3
    assert all(revision.identity == IDENTITY for revision in executor.revisions)
    assert [len(request.feedback) for request in model.requests] == [0, 1, 2]
    assert [item.candidate_commitment for item in model.requests[-1].feedback] == ["1" * 64, "2" * 64]
    assert all(item.oracle_digest == "3" * 64 for item in result.feedback)
    assert all(item.nonce_commitment == "4" * 64 for item in result.feedback)
    assert all(item.observed_interaction_commitment == "5" * 64 for item in result.feedback)
    assert all(not hasattr(item, "candidate_stdout") for item in result.feedback)
    assert executor.remaining == [10.0, 10.0, 10.0]


def test_one_absolute_deadline_is_rechecked_before_model_and_execution() -> None:
    clock = Clock()
    requests = []

    def revise(request):
        requests.append(request)
        clock.value = 105.0
        return ModelRevision(IDENTITY, "completed", proposal={})

    def forbidden_execute(*_args, **_kwargs):
        raise AssertionError("executor ran after deadline")

    result = run_adaptive_exploit_loop(
        cve_id=CVE,
        selected_identity=IDENTITY,
        deadline=105.0,
        revise=revise,
        execute=forbidden_execute,
        monotonic=clock,
    )

    assert len(requests) == 1
    assert requests[0].remaining_run_seconds == 5.0
    assert result.termination_reason == "run_deadline_exhausted"
    assert result.attempts == 0

    clock = Clock()

    def slow_execute(*_args, **_kwargs):
        clock.value = 105.0
        return TrustedExecution((receipt(trusted=True),))

    after_execution = run_adaptive_exploit_loop(
        cve_id=CVE,
        selected_identity=IDENTITY,
        deadline=105.0,
        revise=FakeModel(),
        execute=slow_execute,
        monotonic=clock,
    )
    assert after_execution.termination_reason == "run_deadline_exhausted"
    assert after_execution.trusted_capability_receipt is None
    assert after_execution.attempts == 1


def test_contract_valid_refusal_is_outcome_not_infrastructure_error() -> None:
    result = run_adaptive_exploit_loop(
        cve_id=CVE,
        selected_identity=IDENTITY,
        deadline=110.0,
        revise=lambda _request: ModelRevision(
            IDENTITY, "refused", proposal=None, refusal_kind="policy"
        ),
        execute=lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError()),
        monotonic=Clock(),
    )

    assert result.termination_reason == "model_refusal"
    assert result.refusal_kind == "policy"
    assert result.attempts == 0


def test_completed_revision_requires_an_executable_proposal() -> None:
    result = run_adaptive_exploit_loop(
        cve_id=CVE,
        selected_identity=IDENTITY,
        deadline=110.0,
        revise=lambda _request: ModelRevision(IDENTITY, "completed", proposal=None),
        execute=lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError()),
        monotonic=Clock(),
    )

    assert result.termination_reason == "model_or_contract_failure"
    assert result.error_code == "invalid_model_revision_status"
    assert result.attempts == 0


def test_identity_switch_and_candidate_self_report_cannot_create_success() -> None:
    switched = ModelIdentity("pi", "different/model", "StageHarness")
    mismatch = run_adaptive_exploit_loop(
        cve_id=CVE,
        selected_identity=IDENTITY,
        deadline=110.0,
        revise=lambda _request: ModelRevision(switched, "completed", proposal={"triggered": True}),
        execute=lambda *_args, **_kwargs: TrustedExecution((receipt(trusted=True),)),
        monotonic=Clock(),
    )
    assert mismatch.termination_reason == "model_or_contract_failure"
    assert mismatch.error_code == "model_identity_mismatch"

    model = FakeModel()
    executor = FakeExecutor(prove_at=99)
    unproved = run_adaptive_exploit_loop(
        cve_id=CVE,
        selected_identity=IDENTITY,
        deadline=110.0,
        revise=model,
        execute=executor,
        monotonic=Clock(),
        max_attempts=2,
    )
    assert unproved.termination_reason == "revision_limit_exhausted"
    assert unproved.trusted_capability_receipt is None
    assert unproved.attempts == 2


def test_malformed_positive_receipt_fails_closed() -> None:
    malformed = receipt(trusted=True)
    malformed["oracle_digest"] = None

    result = run_adaptive_exploit_loop(
        cve_id=CVE,
        selected_identity=IDENTITY,
        deadline=110.0,
        revise=FakeModel(),
        execute=lambda *_args, **_kwargs: TrustedExecution((malformed,)),
        monotonic=Clock(),
    )

    assert result.termination_reason == "model_or_contract_failure"
    assert result.trusted_capability_receipt is None


def test_unobserved_negative_receipt_cannot_drive_model_revision() -> None:
    unobserved = receipt(trusted=False)
    unobserved["oracle_digest"] = None

    result = run_adaptive_exploit_loop(
        cve_id=CVE,
        selected_identity=IDENTITY,
        deadline=110.0,
        revise=FakeModel(),
        execute=lambda *_args, **_kwargs: TrustedExecution((unobserved,)),
        monotonic=Clock(),
    )

    assert result.termination_reason == "model_or_contract_failure"
    assert result.error_code == "StageContractError"
    assert result.feedback == ()


def test_provider_or_executor_exception_is_infrastructure_error() -> None:
    provider = run_adaptive_exploit_loop(
        cve_id=CVE,
        selected_identity=IDENTITY,
        deadline=110.0,
        revise=lambda _request: (_ for _ in ()).throw(ConnectionError("provider")),
        execute=lambda *_args, **_kwargs: TrustedExecution(()),
        monotonic=Clock(),
    )
    assert provider.termination_reason == "infrastructure_error"
    assert provider.error_code == "ConnectionError"

    executor = run_adaptive_exploit_loop(
        cve_id=CVE,
        selected_identity=IDENTITY,
        deadline=110.0,
        revise=FakeModel(),
        execute=lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("runtime")),
        monotonic=Clock(),
    )
    assert executor.termination_reason == "infrastructure_error"
    assert executor.error_code == "OSError"


def test_malformed_revision_is_contract_failure_not_infrastructure_error() -> None:
    result = run_adaptive_exploit_loop(
        cve_id=CVE,
        selected_identity=IDENTITY,
        deadline=110.0,
        revise=lambda _request: (_ for _ in ()).throw(
            StageContractError("malformed model revision")
        ),
        execute=lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError()),
        monotonic=Clock(),
    )

    assert result.termination_reason == "model_or_contract_failure"
    assert result.error_code == "StageContractError"
    assert result.attempts == 0


def test_positive_receipt_rejects_empty_host_observation_commitment() -> None:
    malformed = receipt(trusted=True)
    malformed["observed_interaction_commitment"] = sha256_bytes(b"")

    result = run_adaptive_exploit_loop(
        cve_id=CVE,
        selected_identity=IDENTITY,
        deadline=110.0,
        revise=FakeModel(),
        execute=lambda *_args, **_kwargs: TrustedExecution((malformed,)),
        monotonic=Clock(),
    )

    assert result.termination_reason == "model_or_contract_failure"
    assert result.trusted_capability_receipt is None
