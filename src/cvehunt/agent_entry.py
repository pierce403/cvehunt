"""Fail-closed production entry point for the model-backed agent pipeline.

All attacker-controlled identities and local prerequisites are validated before a
run directory is created.  Exceptions from this module intentionally carry only
stable error codes: credential values and trusted local paths must never reach
CLI output.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping

from .agent_pipeline import DIMENSIONED_RESULT_SCHEMA, AgentPipeline, PipelineResult
from .benchmark_adapters import (
    CVE63030CapabilityOracle,
    CVE63030TargetIdentityValidator,
    CVE_63030,
)
from .evaluation_contract import (
    DEFAULT_RUN_TIMEOUT_SECONDS,
    EVALUATION_CONTRACT_SCHEMA,
    evaluation_contract_sha256,
)
from .models import utc_run_id
from .pipeline_runtime import (
    CommandResult,
    CommandRunner,
    ContainerExecutor,
    HiddenOracleScorer,
    SubprocessCommandRunner,
)
from .stage_contracts import CAPABILITY_RECEIPT_SCHEMA, MODEL_STAGES, OUTCOMES, STAGES
from .stage_harness import StageHarness

RUNTIME_POLICY_SCHEMA = "cvehunt.runtime-policy/v1"
SUMMARY_SCHEMA = "cvehunt.agent-run-summary/v1"
LEDGER_SCHEMA = "cvehunt.pipeline-ledger/v1"
PUBLIC_SCHEMA = "cvehunt.public-pipeline/v1"
PUBLIC_EXPORT_MANIFEST_SCHEMA = "cvehunt.public-export-manifest/v1"
PUBLIC_TOP_LEVEL_FIELDS = (
    "schema", "run_id", "cve_id", "model", "evaluation_contract", "result", "stages",
)
PUBLIC_STAGE_FIELDS = (
    "stage", "status", "outcome", "authorship", "duration_ms",
    "input_tokens", "output_tokens", "refusal", "error_code",
)
PUBLIC_RESULT_FIELDS = (
    "schema", "implementation_status", "headline_eligible", "termination_reason",
    "run_boundary", "target", "attempts", "primary_exploit",
    "defensive_remediation", "safety_refusal", "infrastructure",
)
_MAX_JSON = 1024 * 1024
_CVE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,19}$")
_RUN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._/-]*(?::[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}$")
_ENV = re.compile(r"^[A-Z][A-Z0-9_]*$")
_SHA = re.compile(r"^[0-9a-f]{64}$")


class AgentEntryError(RuntimeError):
    """A safe, stable production-entry failure.

    ``code`` is suitable for public output.  Deliberately do not attach the
    underlying exception or a path-bearing message to this exception.
    """

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class RuntimePolicy:
    allowed_base_images: tuple[str, ...]
    python_runner_image: str


@dataclass(frozen=True)
class PiCredential:
    environment_name: str
    value: str


@dataclass(frozen=True)
class AgentRunConfig:
    data_dir: Path
    cve_id: str
    run_id: str
    provider: str
    model: str
    runtime_policy: Path
    research_policy: Path
    oracle: Path
    pi_models: Path
    pi_auth: Path
    timeout_seconds: float = float(DEFAULT_RUN_TIMEOUT_SECONDS)
    target_policy: Path | None = None


@dataclass
class AgentDependencies:
    """Injectable trusted adapters; defaults are the production implementations."""

    command_runner: CommandRunner | None = None
    harness_factory: Callable[..., StageHarness] = StageHarness
    executor_factory: Callable[..., object] = ContainerExecutor
    scorer_factory: Callable[..., object] = HiddenOracleScorer
    pipeline_factory: Callable[..., AgentPipeline] = AgentPipeline
    expected_root_uid: int = 0
    current_uid: int | None = None
    docker_binary: str = "docker"


def validate_identity(cve_id: object, run_id: object) -> tuple[str, str]:
    if not isinstance(cve_id, str) or not _CVE.fullmatch(cve_id):
        raise AgentEntryError("invalid_cve_id")
    if (
        not isinstance(run_id, str)
        or run_id in {".", ".."}
        or not _RUN.fullmatch(run_id)
    ):
        raise AgentEntryError("invalid_run_id")
    return cve_id, run_id


def _read_file(
    path: Path,
    *,
    limit: int,
    owner_uid: int | None = None,
    exact_mode: int | None = None,
    forbid_group_world_write: bool = False,
) -> bytes:
    """Race-resistant bounded read of a single-link regular file."""
    try:
        info = Path(path).lstat()
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise AgentEntryError("unsafe_file")
        if info.st_size > limit:
            raise AgentEntryError("oversized_file")
        if owner_uid is not None and info.st_uid != owner_uid:
            raise AgentEntryError("unsafe_file_owner")
        if exact_mode is not None and mode != exact_mode:
            raise AgentEntryError("unsafe_file_mode")
        if forbid_group_world_write and mode & 0o022:
            raise AgentEntryError("unsafe_file_mode")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except AgentEntryError:
        raise
    except OSError:
        raise AgentEntryError("file_unavailable") from None
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)
        ):
            raise AgentEntryError("file_changed")
        data = bytearray()
        while True:
            block = os.read(fd, min(64 * 1024, limit - len(data) + 1))
            if not block:
                break
            data.extend(block)
            if len(data) > limit:
                raise AgentEntryError("oversized_file")
        if len(data) != info.st_size:
            raise AgentEntryError("file_changed")
        return bytes(data)
    except OSError:
        raise AgentEntryError("file_unavailable") from None
    finally:
        os.close(fd)


def _json(raw: bytes, code: str) -> object:
    try:
        return json.loads(
            raw,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise AgentEntryError(code) from None


def load_target(path: Path, cve_id: str) -> Mapping[str, object]:
    value = _json(_read_file(path, limit=_MAX_JSON), "invalid_target_json")
    if not isinstance(value, dict) or value.get("cve_id") != cve_id:
        raise AgentEntryError("target_identity_mismatch")
    return value


def load_runtime_policy(path: Path, *, expected_uid: int = 0) -> RuntimePolicy:
    raw = _read_file(
        path, limit=64 * 1024, owner_uid=expected_uid,
        forbid_group_world_write=True,
    )
    value = _json(raw, "invalid_runtime_policy")
    if not isinstance(value, dict) or set(value) != {
        "schema", "allowed_base_images", "python_runner_image"
    } or value.get("schema") != RUNTIME_POLICY_SCHEMA:
        raise AgentEntryError("invalid_runtime_policy")
    images = value.get("allowed_base_images")
    runner = value.get("python_runner_image")
    if (
        not isinstance(images, list)
        or not images
        or any(not isinstance(item, str) or not _IMAGE.fullmatch(item) for item in images)
        or len(set(images)) != len(images)
        or not isinstance(runner, str)
        or not _IMAGE.fullmatch(runner)
    ):
        raise AgentEntryError("invalid_runtime_policy")
    return RuntimePolicy(tuple(images), runner)


def load_pi_credential(
    auth_path: Path,
    models_path: Path,
    model: str,
    *,
    current_uid: int | None = None,
) -> PiCredential:
    uid = os.getuid() if current_uid is None else current_uid
    auth = _json(
        _read_file(auth_path, limit=64 * 1024, owner_uid=uid, exact_mode=0o600),
        "invalid_pi_auth",
    )
    models = _json(
        _read_file(models_path, limit=_MAX_JSON, owner_uid=uid, exact_mode=0o600),
        "invalid_pi_models",
    )
    provider_name, separator, model_id = model.partition("/")
    if not separator or not provider_name or not model_id or not isinstance(auth, dict):
        raise AgentEntryError("invalid_model_selection")
    entry = auth.get(provider_name)
    if (
        not isinstance(entry, dict)
        or set(entry) != {"type", "key"}
        or entry.get("type") != "api_key"
        or not isinstance(entry.get("key"), str)
        or not entry["key"].strip()
    ):
        raise AgentEntryError("invalid_pi_auth")
    if not isinstance(models, dict):
        raise AgentEntryError("invalid_pi_models")
    providers = models.get("providers")
    provider = providers.get(provider_name) if isinstance(providers, dict) else None
    configured_models = provider.get("models") if isinstance(provider, dict) else None
    environment_name = provider.get("apiKey") if isinstance(provider, dict) else None
    if (
        not isinstance(environment_name, str)
        or not _ENV.fullmatch(environment_name)
        or not isinstance(configured_models, list)
        or not any(
            isinstance(item, dict) and item.get("id") == model_id
            for item in configured_models
        )
    ):
        raise AgentEntryError("invalid_model_selection")
    return PiCredential(environment_name, entry["key"])


def validate_oracle(
    path: Path, cve_id: str, runs_root: Path, *, current_uid: int | None = None,
) -> None:
    try:
        resolved = Path(path).resolve(strict=True)
        run_resolved = Path(runs_root).resolve(strict=False)
    except OSError:
        raise AgentEntryError("invalid_hidden_oracle") from None
    if resolved.is_relative_to(run_resolved):
        raise AgentEntryError("invalid_hidden_oracle_location")
    uid = os.getuid() if current_uid is None else current_uid
    value = _json(
        _read_file(path, limit=64 * 1024, owner_uid=uid, exact_mode=0o600),
        "invalid_hidden_oracle",
    )
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "cve_id", "max_score", "rules"}
        or value.get("schema") != "cvehunt.hidden-score/v1"
        or value.get("cve_id") != cve_id
        or not isinstance(value.get("rules"), list)
        or not value["rules"]
        or not isinstance(value.get("max_score"), (int, float))
        or isinstance(value.get("max_score"), bool)
        or not math.isfinite(float(value["max_score"]))
        or value["max_score"] <= 0
    ):
        raise AgentEntryError("invalid_hidden_oracle")
    seen: set[str] = set()
    weight_total = 0.0
    for raw_rule in value["rules"]:
        if not isinstance(raw_rule, dict):
            raise AgentEntryError("invalid_hidden_oracle")
        operator = raw_rule.get("operator")
        expected_keys = {"id", "stage", "path", "operator", "weight"}
        if operator == "equals":
            expected_keys.add("expected")
        if set(raw_rule) != expected_keys:
            raise AgentEntryError("invalid_hidden_oracle")
        rule_id = raw_rule.get("id")
        rule_path = raw_rule.get("path")
        weight = raw_rule.get("weight")
        if (
            not isinstance(rule_id, str)
            or not _RUN.fullmatch(rule_id)
            or rule_id in seen
            or raw_rule.get("stage") not in STAGES
            or not isinstance(rule_path, list)
            or not rule_path
            or any(
                not isinstance(item, str) or not item or len(item) > 128 or item.startswith("__")
                for item in rule_path
            )
            or operator not in {"equals", "truthy", "falsey", "present"}
            or not isinstance(weight, (int, float))
            or isinstance(weight, bool)
            or not math.isfinite(float(weight))
            or weight <= 0
        ):
            raise AgentEntryError("invalid_hidden_oracle")
        seen.add(rule_id)
        weight_total += float(weight)
    if weight_total > float(value["max_score"]):
        raise AgentEntryError("invalid_hidden_oracle")


def preflight_docker(
    policy: RuntimePolicy,
    runner: CommandRunner,
    *,
    docker_binary: str = "docker",
) -> None:
    if docker_binary != "docker":
        raise AgentEntryError("invalid_docker_binary")

    def invoke(argv: tuple[str, ...]) -> CommandResult:
        try:
            result = runner.run(
                argv, timeout_seconds=30.0, max_output_bytes=64 * 1024,
                input_data=None,
            )
        except Exception:
            raise AgentEntryError("docker_preflight_failed") from None
        if (
            not isinstance(result, CommandResult)
            or result.argv != argv
            or result.returncode != 0
            or result.timed_out
            or result.stdout_truncated
            or result.stderr_truncated
        ):
            raise AgentEntryError("docker_preflight_failed")
        return result

    info = invoke(("docker", "info", "--format", "{{json .SecurityOptions}}"))
    try:
        options = json.loads(info.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise AgentEntryError("docker_preflight_failed") from None
    if not isinstance(options, list) or not any(
        isinstance(item, str) and (item == "rootless" or "name=rootless" in item)
        for item in options
    ):
        raise AgentEntryError("docker_not_rootless")
    for image in sorted(set(policy.allowed_base_images) | {policy.python_runner_image}):
        invoke(("docker", "image", "inspect", "--format", "{{.Id}}", image))


def _digest(path: Path, limit: int = _MAX_JSON) -> str:
    return hashlib.sha256(_read_file(path, limit=limit)).hexdigest()


def validate_publishable_result(
    result: PipelineResult,
    *,
    run_id: str,
    cve_id: str,
) -> str:
    """Return ``completed`` or ``refused`` only for a publishable ledger."""
    ledger = _json(_read_file(result.ledger_path, limit=_MAX_JSON), "invalid_pipeline_ledger")
    public = _json(_read_file(result.public_path, limit=_MAX_JSON), "invalid_public_pipeline")
    ledger_keys = {
        "schema", "run_id", "cve_id", "model_identity", "evaluation_contract", "result", "stages",
    }
    public_keys = {"schema", "run_id", "cve_id", "model", "evaluation_contract", "result", "stages"}
    ledger_contract = ledger.get("evaluation_contract") if isinstance(ledger, dict) else None
    public_contract = public.get("evaluation_contract") if isinstance(public, dict) else None
    run_timeout = ledger_contract.get("run_timeout_seconds") if isinstance(ledger_contract, dict) else None
    expected_contract = {
        "schema": EVALUATION_CONTRACT_SCHEMA,
        "sha256": evaluation_contract_sha256(),
        "run_timeout_seconds": run_timeout,
    }
    if (
        not isinstance(ledger, dict)
        or set(ledger) != ledger_keys
        or ledger.get("schema") != LEDGER_SCHEMA
        or ledger.get("run_id") != run_id
        or ledger.get("cve_id") != cve_id
        or ledger.get("evaluation_contract") != expected_contract
        or public_contract != expected_contract
        or not isinstance(run_timeout, (int, float))
        or isinstance(run_timeout, bool)
        or not 0 < float(run_timeout) <= DEFAULT_RUN_TIMEOUT_SECONDS
        or not isinstance(ledger.get("stages"), list)
        or len(ledger["stages"]) != len(STAGES)
        or not isinstance(public, dict)
        or set(public) != public_keys
        or public.get("schema") != PUBLIC_SCHEMA
        or public.get("run_id") != run_id
        or public.get("cve_id") != cve_id
        or public.get("result") != ledger.get("result")
        or not isinstance(public.get("stages"), list)
        or len(public["stages"]) != len(STAGES)
        or _digest(result.ledger_path) != result.ledger_sha256
    ):
        raise AgentEntryError("invalid_pipeline_ledger")
    _validate_dimensioned_result(
        ledger.get("result"), run_timeout, expected_cve_id=cve_id,
    )
    refusal_at: int | None = None
    for index, (stage, entry) in enumerate(zip(STAGES, ledger["stages"], strict=True)):
        projection = public["stages"][index]
        if (
            not isinstance(entry, dict)
            or entry.get("stage") != stage
            or not isinstance(projection, dict)
            or projection.get("stage") != stage
            or projection.get("status") != entry.get("status")
            or projection.get("outcome") != entry.get("outcome")
            or projection.get("authorship") != entry.get("authorship")
            or projection.get("refusal") != entry.get("refusal")
            or projection.get("error_code") != entry.get("error_code")
        ):
            raise AgentEntryError("invalid_pipeline_ledger")
        status = entry.get("status")
        if refusal_at is None and status == "completed":
            expected_authorship = "model" if stage in MODEL_STAGES else "deterministic"
            if (
                entry.get("error_code") is not None
                or entry.get("refusal") is not False
                or entry.get("authorship") != expected_authorship
                or not _SHA.fullmatch(str(entry.get("envelope_sha256", "")))
                or not _SHA.fullmatch(str(entry.get("handoff_sha256", "")))
            ):
                raise AgentEntryError("invalid_pipeline_ledger")
            envelope = result.ledger_path.parent / "envelopes" / f"{stage}.json"
            handoff = result.ledger_path.parent / "handoffs" / f"{stage}.json"
            if _digest(envelope) != entry["envelope_sha256"] or _digest(handoff) != entry["handoff_sha256"]:
                raise AgentEntryError("invalid_pipeline_ledger")
            continue
        if refusal_at is None and status == "refused" and stage in MODEL_STAGES:
            if (
                entry.get("error_code") is not None
                or entry.get("refusal") is not True
                or not isinstance(entry.get("refusal_kind"), str)
                or not entry["refusal_kind"]
                or not isinstance(entry.get("substantive_artifacts_produced"), bool)
                or not _SHA.fullmatch(str(entry.get("envelope_sha256", "")))
                or entry.get("handoff_sha256") is not None
            ):
                raise AgentEntryError("invalid_pipeline_ledger")
            envelope = result.ledger_path.parent / "envelopes" / f"{stage}.json"
            if _digest(envelope) != entry["envelope_sha256"]:
                raise AgentEntryError("invalid_pipeline_ledger")
            refusal_at = index
            continue
        if refusal_at is not None and status == "not_run":
            if (
                entry.get("error_code") != "blocked_by_predecessor"
                or entry.get("envelope_sha256") is not None
                or entry.get("handoff_sha256") is not None
                or entry.get("refusal") is not False
            ):
                raise AgentEntryError("invalid_pipeline_ledger")
            continue
        raise AgentEntryError("pipeline_failed")
    if refusal_at is None:
        if not result.completed or result.failed_stage is not None:
            raise AgentEntryError("pipeline_failed")
        return "completed"
    if result.completed or result.failed_stage != STAGES[refusal_at]:
        raise AgentEntryError("pipeline_failed")
    return "refused"


def _validate_dimensioned_result(
    value: object, run_timeout: object, *, expected_cve_id: str | None = None,
) -> None:
    """Validate independent dimensions without allowing self-report success."""
    if not isinstance(value, dict) or set(value) != set(PUBLIC_RESULT_FIELDS):
        raise AgentEntryError("invalid_pipeline_ledger")
    boundary = value.get("run_boundary")
    target = value.get("target")
    primary = value.get("primary_exploit")
    remediation = value.get("defensive_remediation")
    refusal = value.get("safety_refusal")
    infrastructure = value.get("infrastructure")
    if (
        value.get("schema") != DIMENSIONED_RESULT_SCHEMA
        or value.get("implementation_status") != "pre_conformance"
        or value.get("headline_eligible") is not False
        or value.get("termination_reason") not in {
            "run_deadline_exhausted", "model_refusal", "infrastructure_error",
            "model_or_contract_failure", "trusted_capability_not_proved",
            "trusted_capability_proved", "revision_limit_exhausted",
        }
        or not isinstance(boundary, dict)
        or set(boundary) != {"kind", "limit_seconds", "elapsed_seconds", "deadline_exhausted"}
        or boundary.get("kind") != "wall_clock"
        or boundary.get("limit_seconds") != run_timeout
        or not isinstance(boundary.get("elapsed_seconds"), (int, float))
        or isinstance(boundary.get("elapsed_seconds"), bool)
        or not math.isfinite(float(boundary["elapsed_seconds"]))
        or boundary["elapsed_seconds"] < 0
        or not isinstance(boundary.get("deadline_exhausted"), bool)
        or not isinstance(target, dict)
        or set(target) != {"realism_status", "identity_commitment"}
        or target.get("realism_status") != "model_claim_unverified"
        or (
            target.get("identity_commitment") is not None
            and not _SHA.fullmatch(str(target.get("identity_commitment")))
        )
        or not isinstance(primary, dict)
        or set(primary) != {"status", "trusted_capability_receipts", "time_to_proof_seconds"}
        or not isinstance(remediation, dict)
        or set(remediation) != {"status", "fix_commitment", "validation_receipts"}
        or not isinstance(refusal, dict)
        or set(refusal) != {"status"}
        or refusal.get("status") not in {"refused", "not_observed"}
        or not isinstance(infrastructure, dict)
        or set(infrastructure) != {"disposition"}
        or infrastructure.get("disposition") not in {"error", "no_error_observed"}
    ):
        raise AgentEntryError("invalid_pipeline_ledger")
    attempts = value.get("attempts")
    if not isinstance(attempts, list) or len(attempts) > 256:
        raise AgentEntryError("invalid_pipeline_ledger")
    for attempt in attempts:
        if (
            not isinstance(attempt, dict)
            or set(attempt) != {
                "stage", "ordinal", "schema", "cve_id", "variant",
                "candidate_commitment", "target_digest", "oracle_digest",
                "nonce_commitment", "observed_interaction_commitment",
                "execution_result", "infrastructure_disposition",
                "evidence_sha256", "evidence_bytes", "trusted_result",
            }
            or attempt.get("stage") not in {
                "provision_execution", "adversarial_execution", "fix_execution",
            }
            or type(attempt.get("ordinal")) is not int
            or attempt["ordinal"] <= 0
            or attempt.get("schema") != CAPABILITY_RECEIPT_SCHEMA
            or not isinstance(attempt.get("cve_id"), str)
            or (
                expected_cve_id is not None
                and attempt.get("cve_id") != expected_cve_id
            )
            or not isinstance(attempt.get("variant"), str)
            or not _SHA.fullmatch(str(attempt.get("candidate_commitment", "")))
            or not _SHA.fullmatch(str(attempt.get("target_digest", "")))
            or (
                attempt.get("oracle_digest") is not None
                and not _SHA.fullmatch(str(attempt.get("oracle_digest")))
            )
            or not _SHA.fullmatch(str(attempt.get("nonce_commitment", "")))
            or not _SHA.fullmatch(str(attempt.get("observed_interaction_commitment", "")))
            or not _SHA.fullmatch(str(attempt.get("evidence_sha256", "")))
            or type(attempt.get("evidence_bytes")) is not int
            or attempt["evidence_bytes"] < 0
            or not isinstance(attempt.get("trusted_result"), bool)
            or attempt.get("infrastructure_disposition") != "completed"
            or not isinstance(attempt.get("execution_result"), dict)
            or set(attempt["execution_result"]) != {"status", "commitment"}
            or attempt["execution_result"].get("status") != "completed"
            or not _SHA.fullmatch(str(attempt["execution_result"].get("commitment", "")))
        ):
            raise AgentEntryError("invalid_pipeline_ledger")
    primary_receipts = primary.get("trusted_capability_receipts")
    if not isinstance(primary_receipts, list) or any(
        not isinstance(receipt, dict)
        or receipt not in attempts
        or receipt.get("stage") not in {"provision_execution", "adversarial_execution"}
        or receipt.get("variant") != "vulnerable"
        or receipt.get("trusted_result") is not True
        or receipt.get("oracle_digest") is None
        for receipt in primary_receipts
    ):
        raise AgentEntryError("invalid_pipeline_ledger")
    proved = bool(primary_receipts)
    proof_time = primary.get("time_to_proof_seconds")
    if (
        primary.get("status") != ("proved" if proved else "not_proved")
        or (proved and (
            not isinstance(proof_time, (int, float))
            or isinstance(proof_time, bool)
            or not math.isfinite(float(proof_time))
            or proof_time < 0
        ))
        or (not proved and proof_time is not None)
        or (proved and value.get("termination_reason") != "trusted_capability_proved")
        or (not proved and value.get("termination_reason") == "trusted_capability_proved")
    ):
        raise AgentEntryError("invalid_pipeline_ledger")
    remediation_receipts = remediation.get("validation_receipts")
    primary_commitments = {item["candidate_commitment"] for item in primary_receipts}
    fix_attempts = [item for item in attempts if item["stage"] == "fix_execution"]
    if isinstance(remediation_receipts, list) and remediation_receipts:
        expected_remediation_status = (
            "validation_failed"
            if any(isinstance(item, dict) and item.get("trusted_result") is True for item in remediation_receipts)
            else "validated_effective"
        )
    else:
        expected_remediation_status = "inconclusive" if fix_attempts else "not_attempted"
    if (
        remediation.get("status") != expected_remediation_status
        or (
            remediation.get("fix_commitment") is not None
            and not _SHA.fullmatch(str(remediation.get("fix_commitment")))
        )
        or not isinstance(remediation_receipts, list)
        or any(
            not isinstance(receipt, dict)
            or receipt not in attempts
            or receipt.get("stage") != "fix_execution"
            or receipt.get("variant") != "fixed"
            or receipt.get("candidate_commitment") not in primary_commitments
            or receipt.get("oracle_digest") is None
            for receipt in remediation_receipts
        )
    ):
        raise AgentEntryError("invalid_pipeline_ledger")


def validate_public_export_bundle(
    manifest: object,
    public: object,
    public_bytes: bytes,
    *,
    expected_cve_id: str | None = None,
    expected_run_id: str | None = None,
) -> None:
    """Validate the complete declassification scope and dimensioned projection."""
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema", "run_id", "cve_id", "disposition",
        "evaluation_contract_sha256", "headline_eligible", "exports",
    }:
        raise AgentEntryError("invalid_public_export_manifest")
    cve_id = manifest.get("cve_id")
    run_id = manifest.get("run_id")
    if (
        manifest.get("schema") != PUBLIC_EXPORT_MANIFEST_SCHEMA
        or not isinstance(cve_id, str)
        or not _CVE.fullmatch(cve_id)
        or not isinstance(run_id, str)
        or not _RUN.fullmatch(run_id)
        or (expected_cve_id is not None and cve_id != expected_cve_id)
        or (expected_run_id is not None and run_id != expected_run_id)
        or manifest.get("disposition") not in {"completed", "refused"}
        or manifest.get("headline_eligible") is not False
        or manifest.get("evaluation_contract_sha256") != evaluation_contract_sha256()
    ):
        raise AgentEntryError("invalid_public_export_manifest")
    exports = manifest.get("exports")
    if not isinstance(exports, list) or len(exports) != 1:
        raise AgentEntryError("invalid_public_export_manifest")
    export = exports[0]
    if not isinstance(export, dict) or set(export) != {
        "artifact_id", "relative_path", "sha256", "bytes", "classification",
        "top_level_fields", "stage_fields", "result_fields",
    }:
        raise AgentEntryError("invalid_public_export_manifest")
    if (
        export.get("artifact_id") != "public-pipeline"
        or export.get("relative_path") != "public-pipeline.json"
        or export.get("classification") != "public_summary"
        or export.get("sha256") != hashlib.sha256(public_bytes).hexdigest()
        or export.get("bytes") != len(public_bytes)
        or export.get("top_level_fields") != list(PUBLIC_TOP_LEVEL_FIELDS)
        or export.get("stage_fields") != list(PUBLIC_STAGE_FIELDS)
        or export.get("result_fields") != list(PUBLIC_RESULT_FIELDS)
    ):
        raise AgentEntryError("invalid_public_export_manifest")
    if not isinstance(public, dict) or set(public) != set(PUBLIC_TOP_LEVEL_FIELDS):
        raise AgentEntryError("invalid_public_pipeline")
    model = public.get("model")
    if (
        not isinstance(model, dict)
        or set(model) != {"provider", "model", "harness"}
        or any(
            not isinstance(model.get(field), str)
            or not model[field].strip()
            or len(model[field].encode("utf-8")) > 512
            or any(ord(character) < 32 for character in model[field])
            for field in ("provider", "model", "harness")
        )
    ):
        raise AgentEntryError("invalid_public_pipeline")
    contract = public.get("evaluation_contract")
    timeout = contract.get("run_timeout_seconds") if isinstance(contract, dict) else None
    if (
        public.get("schema") != PUBLIC_SCHEMA
        or public.get("cve_id") != cve_id
        or public.get("run_id") != run_id
        or contract != {
            "schema": EVALUATION_CONTRACT_SCHEMA,
            "sha256": evaluation_contract_sha256(),
            "run_timeout_seconds": timeout,
        }
        or not isinstance(timeout, (int, float))
        or isinstance(timeout, bool)
        or not 0 < float(timeout) <= DEFAULT_RUN_TIMEOUT_SECONDS
    ):
        raise AgentEntryError("invalid_public_pipeline")
    stages = public.get("stages")
    if (
        not isinstance(stages, list)
        or len(stages) != len(STAGES)
        or any(
            not isinstance(item, dict)
            or set(item) != set(PUBLIC_STAGE_FIELDS)
            or item.get("stage") != stage
            or item.get("status") not in {
                "completed", "refused", "not_run", "timeout", "provider_error",
                "harness_error", "execution_error", "transport_refusal", "invalid_output",
            }
            or not isinstance(item.get("outcome"), str)
            or item.get("outcome") not in OUTCOMES
            or (
                item.get("status") not in {"completed", "refused"}
                and item.get("outcome") != "none"
            )
            or (
                item.get("status") == "refused"
                and item.get("outcome") not in {"none", "partial"}
            )
            or item.get("authorship") not in {"model", "deterministic", None}
            or not isinstance(item.get("refusal"), bool)
            or (
                item.get("duration_ms") is not None
                and (
                    not isinstance(item.get("duration_ms"), (int, float))
                    or isinstance(item.get("duration_ms"), bool)
                    or not math.isfinite(float(item["duration_ms"]))
                    or item["duration_ms"] < 0
                )
            )
            or any(
                item.get(field) is not None
                and (
                    type(item.get(field)) is not int
                    or item[field] < 0
                )
                for field in ("input_tokens", "output_tokens")
            )
            or (
                item.get("error_code") is not None
                and (
                    not isinstance(item.get("error_code"), str)
                    or not _RUN.fullmatch(item["error_code"])
                )
            )
            for stage, item in zip(STAGES, stages, strict=True)
        )
    ):
        raise AgentEntryError("invalid_public_pipeline")
    refusal_index: int | None = None
    for index, (stage, item) in enumerate(zip(STAGES, stages, strict=True)):
        status = item["status"]
        if refusal_index is None and status == "completed":
            expected_authorship = "model" if stage in MODEL_STAGES else "deterministic"
            if (
                item["authorship"] != expected_authorship
                or item["refusal"] is not False
                or item["error_code"] is not None
            ):
                raise AgentEntryError("invalid_public_pipeline")
            continue
        if refusal_index is None and status == "refused" and stage in MODEL_STAGES:
            if (
                item["authorship"] != "model"
                or item["refusal"] is not True
                or item["error_code"] is not None
            ):
                raise AgentEntryError("invalid_public_pipeline")
            refusal_index = index
            continue
        if refusal_index is not None and status == "not_run":
            if (
                item["authorship"] is not None
                or item["refusal"] is not False
                or item["error_code"] != "blocked_by_predecessor"
            ):
                raise AgentEntryError("invalid_public_pipeline")
            continue
        raise AgentEntryError("invalid_public_pipeline")
    expected_disposition = "refused" if refusal_index is not None else "completed"
    if manifest.get("disposition") != expected_disposition:
        raise AgentEntryError("invalid_public_export_manifest")
    _validate_dimensioned_result(
        public.get("result"), timeout, expected_cve_id=cve_id,
    )


def write_public_export_manifest(
    result: PipelineResult, *, run_id: str, cve_id: str, disposition: str,
) -> Path:
    """Bind the one declassified projection and its exact field-level scope."""
    public = _json(_read_file(result.public_path, limit=_MAX_JSON), "invalid_public_pipeline")
    if not isinstance(public, dict):
        raise AgentEntryError("invalid_public_pipeline")
    stages = public.get("stages")
    if not isinstance(stages, list) or any(
        not isinstance(item, dict) or item.get("stage") != stage
        for stage, item in zip(STAGES, stages, strict=True)
    ):
        raise AgentEntryError("invalid_public_pipeline")
    manifest = {
        "schema": PUBLIC_EXPORT_MANIFEST_SCHEMA,
        "run_id": run_id,
        "cve_id": cve_id,
        "disposition": disposition,
        "evaluation_contract_sha256": evaluation_contract_sha256(),
        "headline_eligible": False,
        "exports": [{
            "artifact_id": "public-pipeline",
            "relative_path": "public-pipeline.json",
            "sha256": _digest(result.public_path),
            "bytes": len(_read_file(result.public_path, limit=_MAX_JSON)),
            "classification": "public_summary",
            "top_level_fields": [*PUBLIC_TOP_LEVEL_FIELDS],
            "stage_fields": [*PUBLIC_STAGE_FIELDS],
            "result_fields": [*PUBLIC_RESULT_FIELDS],
        }],
    }
    encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    destination = result.public_path.parent / "public-export-manifest.json"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(destination, flags, 0o400)
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        raise AgentEntryError("public_export_manifest_failed") from None
    persisted = _json(
        _read_file(destination, limit=_MAX_JSON), "invalid_public_export_manifest",
    )
    if persisted != manifest:
        raise AgentEntryError("invalid_public_export_manifest")
    validate_public_export_bundle(
        persisted,
        _json(
            _read_file(result.public_path, limit=_MAX_JSON), "invalid_public_pipeline",
        ),
        _read_file(result.public_path, limit=_MAX_JSON),
        expected_cve_id=cve_id,
        expected_run_id=run_id,
    )
    return destination


def _verify_private_directory(fd: int, owner_uid: int) -> None:
    info = os.fstat(fd)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != owner_uid
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise AgentEntryError("unsafe_data_root")


def _open_directory(path: Path, owner_uid: int, *, dir_fd: int | None = None) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, dir_fd=dir_fd)
    except (OSError, TypeError):
        raise AgentEntryError("unsafe_data_root") from None
    try:
        _verify_private_directory(fd, owner_uid)
    except Exception:
        os.close(fd)
        raise
    return fd


@contextmanager
def _open_storage_hierarchy(
    data_dir: Path, cve_id: str, owner_uid: int
) -> Iterator[tuple[Path, int, int | None]]:
    """Open each storage component without following links or trusting path resolution."""
    data_root = Path(os.path.abspath(os.fspath(data_dir)))
    root_fd = _open_directory(data_root, owner_uid)
    cves_fd: int | None = None
    cve_fd: int | None = None
    runs_fd: int | None = None
    try:
        cves_fd = _open_directory(Path("cves"), owner_uid, dir_fd=root_fd)
        cve_fd = _open_directory(Path(cve_id), owner_uid, dir_fd=cves_fd)
        try:
            runs_fd = _open_directory(Path("runs"), owner_uid, dir_fd=cve_fd)
        except AgentEntryError:
            try:
                os.stat("runs", dir_fd=cve_fd, follow_symlinks=False)
            except FileNotFoundError:
                runs_fd = None
            else:
                raise
        yield data_root, cve_fd, runs_fd
    finally:
        if runs_fd is not None:
            os.close(runs_fd)
        if cve_fd is not None:
            os.close(cve_fd)
        if cves_fd is not None:
            os.close(cves_fd)
        os.close(root_fd)


def _reserve_run_directory(cve_fd: int, runs_fd: int | None, run_id: str, owner_uid: int) -> None:
    """Atomically reserve the run relative to verified directory descriptors."""
    opened_here = runs_fd is None
    if runs_fd is None:
        try:
            os.mkdir("runs", mode=0o700, dir_fd=cve_fd)
        except FileExistsError:
            raise AgentEntryError("unsafe_data_root") from None
        runs_fd = _open_directory(Path("runs"), owner_uid, dir_fd=cve_fd)
    try:
        try:
            os.mkdir(run_id, mode=0o700, dir_fd=runs_fd)
        except FileExistsError:
            raise AgentEntryError("run_already_exists") from None
        except OSError:
            raise AgentEntryError("unsafe_data_root") from None
        run_fd = _open_directory(Path(run_id), owner_uid, dir_fd=runs_fd)
        os.close(run_fd)
    finally:
        if opened_here:
            os.close(runs_fd)


def _assert_run_available(runs_fd: int | None, run_id: str) -> None:
    """Reject every existing directory entry before constructing external adapters."""
    if runs_fd is None:
        return
    try:
        os.stat(run_id, dir_fd=runs_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError:
        raise AgentEntryError("unsafe_data_root") from None
    raise AgentEntryError("run_already_exists")


def run_agent(config: AgentRunConfig, dependencies: AgentDependencies | None = None) -> dict[str, object]:
    deps = dependencies or AgentDependencies()
    cve_id, run_id = validate_identity(config.cve_id, config.run_id)
    current_uid = os.getuid() if deps.current_uid is None else deps.current_uid
    with _open_storage_hierarchy(config.data_dir, cve_id, current_uid) as storage:
        data_root, cve_fd, runs_fd = storage
        return _run_agent_verified(
            config, deps, cve_id, run_id, data_root, cve_fd, runs_fd, current_uid
        )


def _run_agent_verified(
    config: AgentRunConfig,
    deps: AgentDependencies,
    cve_id: str,
    run_id: str,
    data_root: Path,
    cve_fd: int,
    runs_fd: int | None,
    current_uid: int,
) -> dict[str, object]:
    _assert_run_available(runs_fd, run_id)
    if config.provider.lower() != "pi":
        # StageHarness is authoritative for provider isolation (including Codex).
        try:
            deps.harness_factory(Path(config.data_dir) / ".agent-preflight").preflight(
                provider=config.provider, model=config.model, research=True
            )
        except Exception:
            raise AgentEntryError("provider_preflight_failed") from None
        raise AgentEntryError("provider_preflight_failed")
    if (
        not isinstance(config.timeout_seconds, (int, float))
        or isinstance(config.timeout_seconds, bool)
        or config.timeout_seconds <= 0
        or config.timeout_seconds > DEFAULT_RUN_TIMEOUT_SECONDS
    ):
        raise AgentEntryError("invalid_timeout")

    cve_root = data_root / "cves" / cve_id
    runs_root = cve_root / "runs"
    target_path = cve_root / "cve.json"
    load_target(target_path, cve_id)
    policy = load_runtime_policy(config.runtime_policy, expected_uid=deps.expected_root_uid)
    credential = load_pi_credential(
        config.pi_auth, config.pi_models, config.model,
        current_uid=deps.current_uid,
    )
    validate_oracle(config.oracle, cve_id, runs_root, current_uid=deps.current_uid)
    capability_oracle = None
    target_identity_validator = None
    if cve_id == CVE_63030:
        if config.target_policy is None:
            raise AgentEntryError("target_policy_required")
        try:
            target_identity_validator = CVE63030TargetIdentityValidator(
                config.target_policy, expected_uid=current_uid,
            )
            capability_oracle = CVE63030CapabilityOracle()
        except Exception:
            raise AgentEntryError("invalid_target_policy") from None
    try:
        scorer = deps.scorer_factory(config.oracle)
    except Exception:
        raise AgentEntryError("invalid_hidden_oracle") from None

    harness_kwargs = {
        "provider_environment": {credential.environment_name: credential.value},
        "pi_models_source": config.pi_models,
        "research_policy_file": config.research_policy,
    }
    try:
        preflight_harness = deps.harness_factory(data_root / ".agent-preflight", **harness_kwargs)
        preflight_harness.preflight(provider=config.provider, model=config.model, research=True)
    except Exception:
        raise AgentEntryError("provider_preflight_failed") from None

    runner = deps.command_runner or SubprocessCommandRunner()
    preflight_docker(policy, runner, docker_binary=deps.docker_binary)

    def harness_factory(stage_root: Path) -> StageHarness:
        return deps.harness_factory(stage_root, **harness_kwargs)

    try:
        executor = deps.executor_factory(
            allowed_base_images=policy.allowed_base_images,
            python_runner_image=policy.python_runner_image,
            runner=runner,
            docker_binary=deps.docker_binary,
            # Match StageHarness's bounded artifact envelope so the model can
            # carry both official WordPress release archives into the trusted
            # provenance validator. ContainerExecutor still reads every file
            # with no-follow, per-file, and aggregate limits before Docker.
            max_artifact_bytes=32 * 1024 * 1024,
            max_total_context_bytes=128 * 1024 * 1024,
            capability_oracle=capability_oracle,
            target_identity_validator=target_identity_validator,
        )
        pipeline = deps.pipeline_factory(
            runs_root,
            harness_factory=harness_factory,
            executor=executor,
            scorer=scorer,
            provider=config.provider,
            model=config.model,
            allowed_base_images=policy.allowed_base_images,
            timeout_seconds=float(config.timeout_seconds),
            precreated_run=True,
            enforce_callback_process_boundary=True,
            adaptive_exploit=True,
        )
        # Reserve only after credential, provider, target, oracle, Docker, and
        # adapter preflights succeed. No paid model call or container execution
        # occurs before this point.
        _reserve_run_directory(cve_fd, runs_fd, run_id, current_uid)
        with tempfile.TemporaryDirectory(prefix="cvehunt-target-") as temporary:
            minimal_target = Path(temporary) / "target.json"
            minimal_target.write_text(
                json.dumps(
                    {"schema": "cvehunt.target/v1", "cve_id": cve_id},
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                encoding="utf-8",
            )
            minimal_target.chmod(0o400)
            result = pipeline.run(
                run_id=run_id, cve_id=cve_id, target_contract=minimal_target,
            )
    except AgentEntryError:
        raise
    except Exception:
        raise AgentEntryError("pipeline_runtime_failure") from None

    disposition = validate_publishable_result(result, run_id=run_id, cve_id=cve_id)
    export_manifest = write_public_export_manifest(
        result, run_id=run_id, cve_id=cve_id, disposition=disposition,
    )
    try:
        ledger_relative = result.ledger_path.resolve().relative_to(data_root).as_posix()
        public_relative = result.public_path.resolve().relative_to(data_root).as_posix()
        export_relative = export_manifest.resolve().relative_to(data_root).as_posix()
    except ValueError:
        raise AgentEntryError("invalid_result_location") from None
    return {
        "schema": SUMMARY_SCHEMA,
        "status": disposition,
        "cve_id": cve_id,
        "run_id": run_id,
        "provider": config.provider.lower(),
        "model": config.model,
        "ledger": {"path": ledger_relative, "sha256": _digest(result.ledger_path)},
        "public": {"path": public_relative, "sha256": _digest(result.public_path)},
        "export_manifest": {
            "path": export_relative, "sha256": _digest(export_manifest),
        },
    }


def config_from_args(args: Any) -> AgentRunConfig:
    cve_id = args.cve_id
    run_id = args.run_id or utc_run_id()
    oracle = args.oracle or (Path.home() / ".config" / "cvehunt" / "oracles" / f"{cve_id}.json")
    target_policy = args.target_policy or (
        Path.home() / ".config" / "cvehunt" / "targets" / f"{cve_id}.json"
    )
    return AgentRunConfig(
        Path(args.data_dir).expanduser(), cve_id, run_id, args.provider, args.model,
        Path(args.runtime_policy).expanduser(), Path(args.research_policy).expanduser(),
        Path(oracle).expanduser(), Path(args.pi_models).expanduser(),
        Path(args.pi_auth).expanduser(), args.timeout, Path(target_policy).expanduser(),
    )


__all__ = [
    "AgentDependencies", "AgentEntryError", "AgentRunConfig", "PiCredential",
    "RuntimePolicy", "config_from_args", "load_pi_credential", "load_runtime_policy",
    "load_target", "preflight_docker", "run_agent", "validate_identity",
    "validate_oracle", "validate_public_export_bundle", "validate_publishable_result",
    "write_public_export_manifest",
]
