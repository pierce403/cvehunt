"""Fail-closed contracts for model-authored CVEHunt pipeline stages.

This module validates attribution and artifact integrity. It never manufactures
substantive stage output, executes model-authored code, or exposes hidden-oracle
material to a model/public projection.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA = "cvehunt.stage-artifact/v1"
HANDOFF_SCHEMA = "cvehunt.stage-handoff/v1"
CAPABILITY_RECEIPT_SCHEMA = "cvehunt.capability-receipt/v1"

MODEL_STAGES = (
    "collector",
    "researcher",
    "harness_builder",
    "exploiter",
    "adversarial_loop",
    "fix_developer",
    "validator",
    "judge",
)
DETERMINISTIC_STAGES = ("provision_execution", "adversarial_execution", "fix_execution", "official_score")
SEPARATE_STAGES = ("refusal_evaluation",)
STAGES = (
    "collector",
    "researcher",
    "harness_builder",
    "exploiter",
    "provision_execution",
    "adversarial_loop",
    "adversarial_execution",
    "fix_developer",
    "fix_execution",
    "validator",
    "judge",
    "official_score",
)

PREDECESSOR = {
    "collector": None,
    "researcher": "collector",
    "harness_builder": "researcher",
    "exploiter": "harness_builder",
    "provision_execution": "exploiter",
    "adversarial_loop": "provision_execution",
    "adversarial_execution": "adversarial_loop",
    "fix_developer": "adversarial_execution",
    "fix_execution": "fix_developer",
    "validator": "fix_execution",
    "judge": "validator",
    "official_score": "judge",
    "refusal_evaluation": None,
}

STATUSES = {
    "completed",
    "refused",
    "blocked_missing_input",
    "invalid_output",
    "policy_violation",
    "timeout",
    "provider_error",
    "harness_error",
    "execution_error",
    "cancelled",
    "not_run",
}
OUTCOMES = {"success", "partial", "negative_result", "inconclusive", "not_applicable", "none"}
CLASSIFICATIONS = {"model_input", "public_summary", "public_artifact", "local_audit", "hidden_oracle"}
PUBLIC_CLASSIFICATIONS = {"public_summary", "public_artifact"}
PRIVATE_CLASSIFICATIONS = {"local_audit", "hidden_oracle"}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")

REQUIRED_PAYLOAD_KEYS = {
    "collector": {"query", "record", "claims", "gaps"},
    "researcher": {"research_question", "hypotheses", "source_acquisition", "sources_consulted", "gaps"},
    "harness_builder": {"target_class", "backend", "variants", "services", "commands", "safety", "container_plan"},
    "exploiter": {"hypothesis_ids", "candidate", "derivation", "runtime_requirements"},
    "provision_execution": {"execution_id", "executor", "builds", "targets", "candidate_runs", "cleanup"},
    "adversarial_loop": {"round_budget", "rounds", "rounds_executed", "stop_reason", "adversarial_plan"},
    "adversarial_execution": {"execution_id", "executor", "builds", "targets", "adversarial_runs", "cleanup"},
    "fix_developer": {"root_cause", "patch", "security_invariant", "expected_behavior", "limitations", "fix_plan"},
    "fix_execution": {"execution_id", "executor", "build", "target", "candidate_runs", "fix_commitment", "cleanup"},
    "validator": {"validation_plan", "evidence_assessment", "coverage", "conclusion"},
    "judge": {"decision", "confidence", "claims", "stage_assessments", "limitations"},
    "official_score": {
        "score", "max_score", "eligible", "oracle_commitment", "scoring_input_commitment",
    },
    "refusal_evaluation": {"task", "decision", "response_sha256", "response_bytes", "raw_response_published"},
}


class StageContractError(ValueError):
    """A stage envelope, artifact, or handoff violated the benchmark contract."""


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _mapping(value: object, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StageContractError(f"{field} must be an object")
    return value


def _sequence(value: object, field: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise StageContractError(f"{field} must be an array")
    return value


def _nonempty(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise StageContractError(f"{field} must be a non-empty string")
    return value


def _sha(value: object, field: str) -> str:
    text = _nonempty(value, field)
    if not SHA256_RE.fullmatch(text):
        raise StageContractError(f"{field} must be a lowercase SHA-256 digest")
    return text


def _relative_path(value: object, field: str) -> PurePosixPath:
    text = _nonempty(value, field)
    path = PurePosixPath(text)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise StageContractError(f"{field} must be a contained relative path")
    return path


def _safe_file(root: Path, logical_path: object, expected_bytes: object, expected_sha: object, *, max_file_bytes: int) -> Path:
    relative = _relative_path(logical_path, "artifact.logical_path")
    target = root.joinpath(*relative.parts)
    if not target.is_relative_to(root):
        raise StageContractError("artifact path escapes its root")
    cursor = root
    for part in relative.parts:
        cursor = cursor / part
        try:
            info = cursor.lstat()
        except OSError as exc:
            raise StageContractError(f"artifact is missing: {relative}") from exc
        if stat.S_ISLNK(info.st_mode):
            raise StageContractError(f"artifact symlink rejected: {relative}")
    info = target.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise StageContractError(f"artifact is not a regular file: {relative}")
    if info.st_nlink != 1:
        raise StageContractError(f"artifact hardlink rejected: {relative}")
    if not isinstance(expected_bytes, int) or isinstance(expected_bytes, bool) or expected_bytes < 0:
        raise StageContractError("artifact.bytes must be a non-negative integer")
    if info.st_size != expected_bytes:
        raise StageContractError(f"artifact byte count mismatch: {relative}")
    if info.st_size > max_file_bytes:
        raise StageContractError(f"artifact exceeds size limit: {relative}")
    digest = hashlib.sha256()
    fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_ino != info.st_ino or opened.st_dev != info.st_dev or opened.st_nlink != 1:
            raise StageContractError(f"artifact changed during validation: {relative}")
        while block := os.read(fd, 1024 * 1024):
            digest.update(block)
    finally:
        os.close(fd)
    if digest.hexdigest() != _sha(expected_sha, "artifact.sha256"):
        raise StageContractError(f"artifact hash mismatch: {relative}")
    return target


def _validate_trusted_receipts(value: object, field: str, expected_cve_id: str) -> None:
    expected = {
        "schema", "cve_id", "variant", "trusted_result", "candidate_commitment",
        "target_digest", "oracle_digest", "nonce_commitment",
        "observed_interaction_commitment", "execution_result",
        "infrastructure_disposition", "evidence_sha256", "evidence_bytes",
    }
    for index, raw in enumerate(_sequence(value, field)):
        receipt = _mapping(raw, f"{field}[{index}]")
        if set(receipt) != expected:
            raise StageContractError(f"{field}[{index}] has unknown or missing fields")
        if receipt.get("schema") != CAPABILITY_RECEIPT_SCHEMA:
            raise StageContractError(f"{field}[{index}].schema is invalid")
        if receipt.get("cve_id") != expected_cve_id:
            raise StageContractError(f"{field}[{index}].cve_id mismatch")
        _nonempty(receipt.get("variant"), f"{field}[{index}].variant")
        if not isinstance(receipt.get("trusted_result"), bool):
            raise StageContractError(f"{field}[{index}].trusted_result must be boolean")
        _sha(receipt.get("candidate_commitment"), f"{field}[{index}].candidate_commitment")
        _sha(receipt.get("target_digest"), f"{field}[{index}].target_digest")
        oracle_digest = receipt.get("oracle_digest")
        if oracle_digest is not None:
            _sha(oracle_digest, f"{field}[{index}].oracle_digest")
        if receipt.get("trusted_result") is True and oracle_digest is None:
            raise StageContractError(f"{field}[{index}] positive result requires oracle digest")
        _sha(receipt.get("nonce_commitment"), f"{field}[{index}].nonce_commitment")
        interaction = _sha(
            receipt.get("observed_interaction_commitment"),
            f"{field}[{index}].observed_interaction_commitment",
        )
        if receipt.get("trusted_result") is True and interaction == sha256_bytes(b""):
            raise StageContractError(f"{field}[{index}] positive result requires observed interaction")
        execution_result = _mapping(
            receipt.get("execution_result"), f"{field}[{index}].execution_result",
        )
        if set(execution_result) != {"status", "commitment"}:
            raise StageContractError(f"{field}[{index}].execution_result has wrong fields")
        if execution_result.get("status") != "completed":
            raise StageContractError(f"{field}[{index}].execution_result status is invalid")
        _sha(execution_result.get("commitment"), f"{field}[{index}].execution_result.commitment")
        if receipt.get("infrastructure_disposition") != "completed":
            raise StageContractError(f"{field}[{index}].infrastructure_disposition is invalid")
        _sha(receipt.get("evidence_sha256"), f"{field}[{index}].evidence_sha256")
        evidence_bytes = receipt.get("evidence_bytes")
        if type(evidence_bytes) is not int or evidence_bytes < 0:
            raise StageContractError(f"{field}[{index}].evidence_bytes must be non-negative integer")


def _validate_completed_payload(
    stage: str, payload: Mapping[str, Any], expected_cve_id: str,
) -> None:
    expected = REQUIRED_PAYLOAD_KEYS[stage]
    if set(payload) != expected:
        missing = expected - set(payload)
        unknown = set(payload) - expected
        details = []
        if missing:
            details.append(f"missing: {', '.join(sorted(missing))}")
        if unknown:
            details.append(f"unknown: {', '.join(sorted(unknown))}")
        raise StageContractError(f"stage payload has wrong fields ({'; '.join(details)})")
    if stage in {"provision_execution", "fix_execution"}:
        _validate_trusted_receipts(
            payload["candidate_runs"], "payload.candidate_runs", expected_cve_id,
        )
    elif stage == "adversarial_execution":
        _validate_trusted_receipts(
            payload["adversarial_runs"], "payload.adversarial_runs", expected_cve_id,
        )
    elif stage == "official_score":
        for field in ("oracle_commitment", "scoring_input_commitment"):
            _sha(payload[field], f"payload.{field}")
        for field in ("score", "max_score"):
            value = payload[field]
            if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
                raise StageContractError(f"payload.{field} must be non-negative number")
        if not isinstance(payload["eligible"], bool):
            raise StageContractError("payload.eligible must be boolean")


def validate_envelope(
    envelope: Mapping[str, Any],
    artifact_root: Path,
    *,
    expected_run_id: str,
    expected_cve_id: str,
    expected_stage: str,
    expected_harness: str | None = None,
    expected_model: str | None = None,
    predecessor_handoff_sha256: str | None = None,
    max_file_bytes: int = 16 * 1024 * 1024,
    max_total_bytes: int = 64 * 1024 * 1024,
) -> dict[str, Any]:
    """Validate a stage envelope and return a detached normalized copy."""
    data = json.loads(json.dumps(envelope))
    if data.get("schema") != SCHEMA:
        raise StageContractError(f"schema must be {SCHEMA}")
    if data.get("run_id") != expected_run_id:
        raise StageContractError("run identity mismatch")
    if data.get("cve_id") != expected_cve_id or not CVE_RE.fullmatch(expected_cve_id):
        raise StageContractError("CVE identity mismatch")
    if expected_stage not in PREDECESSOR or data.get("stage") != expected_stage:
        raise StageContractError("stage identity mismatch")
    _nonempty(data.get("invocation_id"), "invocation_id")

    authorship = _mapping(data.get("authorship"), "authorship")
    expected_kind = "model" if expected_stage in MODEL_STAGES or expected_stage == "refusal_evaluation" else "deterministic"
    if authorship.get("kind") != expected_kind:
        raise StageContractError(f"{expected_stage} requires {expected_kind} authorship")
    if expected_kind == "model":
        harness = _nonempty(authorship.get("harness"), "authorship.harness")
        model = _nonempty(authorship.get("model"), "authorship.model")
        if expected_harness is not None and harness != expected_harness:
            raise StageContractError("harness authorship mismatch")
        if expected_model is not None and model != expected_model:
            raise StageContractError("model authorship mismatch")
    _sha(authorship.get("prompt_template_sha256"), "authorship.prompt_template_sha256")
    _sha(authorship.get("tool_policy_sha256"), "authorship.tool_policy_sha256")

    parent = data.get("parent_handoff_sha256")
    required_parent = PREDECESSOR[expected_stage] is not None
    if required_parent:
        if predecessor_handoff_sha256 is None:
            raise StageContractError("validated predecessor handoff is required")
        if _sha(parent, "parent_handoff_sha256") != predecessor_handoff_sha256:
            raise StageContractError("predecessor handoff mismatch")
    elif parent is not None:
        raise StageContractError("root/separate stage must not claim a predecessor")

    status = data.get("status")
    outcome = data.get("outcome")
    if status not in STATUSES:
        raise StageContractError("invalid stage status")
    if outcome not in OUTCOMES:
        raise StageContractError("invalid stage outcome")
    refusal = data.get("refusal")
    if status == "refused":
        refusal_data = _mapping(refusal, "refusal")
        if set(refusal_data) != {
            "kind", "model_statement_sha256", "substantive_artifacts_produced",
        }:
            raise StageContractError("refusal has unknown or missing fields")
        _nonempty(refusal_data.get("kind"), "refusal.kind")
        _sha(refusal_data.get("model_statement_sha256"), "refusal.model_statement_sha256")
        if not isinstance(refusal_data.get("substantive_artifacts_produced"), bool):
            raise StageContractError("refusal.substantive_artifacts_produced must be boolean")
        if outcome not in {"none", "partial"}:
            raise StageContractError("refusal outcome must be none or partial")
    elif refusal is not None:
        raise StageContractError("only status=refused may include refusal")
    if status not in {"completed", "refused"} and outcome != "none":
        raise StageContractError("non-completed stage outcome must be none")
    errors = _sequence(data.get("errors"), "errors")
    for index, error in enumerate(errors):
        item = _mapping(error, f"errors[{index}]")
        _nonempty(item.get("code"), f"errors[{index}].code")
        _nonempty(item.get("source"), f"errors[{index}].source")
        _nonempty(item.get("message"), f"errors[{index}].message")
        if not isinstance(item.get("retryable"), bool):
            raise StageContractError(f"errors[{index}].retryable must be boolean")

    metrics = _mapping(data.get("metrics"), "metrics")
    for field in ("wall_ms", "model_ms", "tool_ms", "tool_calls", "network_requests"):
        value = metrics.get(field)
        if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
            raise StageContractError(f"metrics.{field} must be non-negative")
    for field in ("input_tokens", "output_tokens", "cached_input_tokens"):
        value = metrics.get(field)
        if value is not None and (not isinstance(value, int) or isinstance(value, bool) or value < 0):
            raise StageContractError(f"metrics.{field} must be null or a non-negative integer")

    provenance = _mapping(data.get("provenance"), "provenance")
    _sha(provenance.get("input_manifest_sha256"), "provenance.input_manifest_sha256")
    _sha(provenance.get("output_manifest_sha256"), "provenance.output_manifest_sha256")
    if provenance.get("prior_run_access") is not False or provenance.get("external_poc_access") is not False:
        raise StageContractError("prior-run or external-PoC access makes the stage ineligible")

    inputs = _sequence(data.get("inputs"), "inputs")
    input_ids: set[str] = set()
    for index, raw_input in enumerate(inputs):
        item = _mapping(raw_input, f"inputs[{index}]")
        artifact_id = _nonempty(item.get("artifact_id"), f"inputs[{index}].artifact_id")
        if artifact_id in input_ids:
            raise StageContractError("duplicate input artifact ID")
        input_ids.add(artifact_id)
        _sha(item.get("sha256"), f"inputs[{index}].sha256")
        if item.get("classification") != "model_input":
            raise StageContractError("model input may contain only model_input-classified artifacts")

    artifacts = _sequence(data.get("artifacts"), "artifacts")
    artifact_ids: set[str] = set()
    logical_paths: set[str] = set()
    total_bytes = 0
    for index, raw_artifact in enumerate(artifacts):
        item = _mapping(raw_artifact, f"artifacts[{index}]")
        artifact_id = _nonempty(item.get("artifact_id"), f"artifacts[{index}].artifact_id")
        if artifact_id in artifact_ids or artifact_id in input_ids:
            raise StageContractError("duplicate artifact ID")
        artifact_ids.add(artifact_id)
        classification = item.get("classification")
        if classification not in CLASSIFICATIONS:
            raise StageContractError("invalid artifact classification")
        if item.get("authored_by") != data["invocation_id"]:
            raise StageContractError("artifact authorship mismatch")
        if expected_kind == "model" and classification != "model_input":
            raise StageContractError("model output cannot self-declassify")
        logical_path = _relative_path(item.get("logical_path"), "artifact.logical_path").as_posix()
        if logical_path in logical_paths:
            raise StageContractError("duplicate artifact logical path")
        logical_paths.add(logical_path)
        _safe_file(artifact_root.resolve(), logical_path, item.get("bytes"), item.get("sha256"), max_file_bytes=max_file_bytes)
        total_bytes += item["bytes"]
        if total_bytes > max_total_bytes:
            raise StageContractError("stage artifacts exceed total size limit")

    payload = _mapping(data.get("payload"), "payload")
    if status == "completed":
        _validate_completed_payload(expected_stage, payload, expected_cve_id)
    return data


def write_handoff(envelope: Mapping[str, Any], destination: Path) -> tuple[Path, str]:
    """Atomically write an immutable handoff for a previously validated envelope."""
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise StageContractError(f"handoff already exists: {destination}")
    artifact_records = []
    for item in _sequence(envelope.get("artifacts"), "artifacts"):
        record = _mapping(item, "artifact")
        if record.get("classification") in PRIVATE_CLASSIFICATIONS:
            continue
        artifact_records.append({key: record[key] for key in ("artifact_id", "logical_path", "sha256", "bytes", "classification")})
    body = {
        "schema": HANDOFF_SCHEMA,
        "run_id": envelope["run_id"],
        "cve_id": envelope["cve_id"],
        "stage": envelope["stage"],
        "invocation_id": envelope["invocation_id"],
        "envelope_sha256": sha256_bytes(canonical_json(envelope)),
        "artifacts": artifact_records,
    }
    encoded = canonical_json(body)
    digest = sha256_bytes(encoded)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o444)
        os.link(temporary, destination)
        temporary.unlink()
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return destination, digest


def read_handoff(
    path: Path, *, expected_run_id: str, expected_cve_id: str, expected_stage: str,
    max_bytes: int = 1024 * 1024,
) -> tuple[dict[str, Any], str]:
    path = Path(path)
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) & 0o222 or info.st_size > max_bytes
    ):
        raise StageContractError("handoff must be a bounded read-only single-link regular file")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)
            or opened.st_size != info.st_size
        ):
            raise StageContractError("handoff changed while being opened")
        raw = bytearray()
        while block := os.read(fd, min(1024 * 1024, max_bytes - len(raw) + 1)):
            raw.extend(block)
            if len(raw) > max_bytes:
                raise StageContractError("handoff exceeds size limit")
        final = os.fstat(fd)
        if final.st_size != len(raw) or (final.st_dev, final.st_ino) != (info.st_dev, info.st_ino):
            raise StageContractError("handoff changed while being read")
    finally:
        os.close(fd)
    try:
        data = json.loads(bytes(raw), parse_constant=lambda value: (_ for _ in ()).throw(
            StageContractError(f"non-finite handoff JSON number: {value}")
        ))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise StageContractError("handoff is not valid JSON") from exc
    if not isinstance(data, dict) or set(data) != {
        "schema", "run_id", "cve_id", "stage", "invocation_id", "envelope_sha256", "artifacts",
    }:
        raise StageContractError("handoff has unknown or missing fields")
    if data.get("schema") != HANDOFF_SCHEMA or data.get("run_id") != expected_run_id or data.get("cve_id") != expected_cve_id or data.get("stage") != expected_stage:
        raise StageContractError("handoff identity mismatch")
    _nonempty(data.get("invocation_id"), "handoff.invocation_id")
    _sha(data.get("envelope_sha256"), "handoff.envelope_sha256")
    artifact_ids: set[str] = set()
    logical_paths: set[str] = set()
    for raw_artifact in _sequence(data.get("artifacts"), "handoff.artifacts"):
        item = _mapping(raw_artifact, "handoff.artifact")
        if set(item) != {"artifact_id", "logical_path", "sha256", "bytes", "classification"}:
            raise StageContractError("handoff artifact has unknown or missing fields")
        artifact_id = _nonempty(item.get("artifact_id"), "handoff.artifact_id")
        logical_path = _relative_path(item.get("logical_path"), "handoff.logical_path").as_posix()
        if artifact_id in artifact_ids or logical_path in logical_paths:
            raise StageContractError("handoff contains duplicate artifact identity")
        artifact_ids.add(artifact_id)
        logical_paths.add(logical_path)
        _sha(item.get("sha256"), "handoff.artifact.sha256")
        size = item.get("bytes")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise StageContractError("handoff artifact bytes must be non-negative")
        if item.get("classification") not in PUBLIC_CLASSIFICATIONS | {"model_input"}:
            raise StageContractError("handoff contains private artifact classification")
    encoded = bytes(raw)
    if encoded != canonical_json(data):
        raise StageContractError("handoff JSON must be canonical")
    return data, sha256_bytes(encoded)


def public_projection(envelope: Mapping[str, Any]) -> dict[str, Any]:
    """Return the purpose-built safe projection; never recursively publish a run."""
    artifacts = []
    for item in _sequence(envelope.get("artifacts"), "artifacts"):
        record = _mapping(item, "artifact")
        if record.get("classification") in PUBLIC_CLASSIFICATIONS:
            artifacts.append({key: record[key] for key in ("artifact_id", "sha256", "bytes", "classification")})
    metrics = _mapping(envelope.get("metrics"), "metrics")
    return {
        "schema": "cvehunt.public-stage/v1",
        "run_id": envelope["run_id"],
        "cve_id": envelope["cve_id"],
        "stage": envelope["stage"],
        "status": envelope["status"],
        "outcome": envelope["outcome"],
        "authorship": _mapping(envelope["authorship"], "authorship").get("kind"),
        "duration_ms": metrics.get("wall_ms"),
        "input_tokens": metrics.get("input_tokens"),
        "output_tokens": metrics.get("output_tokens"),
        "artifacts": artifacts,
    }


__all__ = [
    "CAPABILITY_RECEIPT_SCHEMA",
    "CLASSIFICATIONS",
    "DETERMINISTIC_STAGES",
    "HANDOFF_SCHEMA",
    "MODEL_STAGES",
    "PREDECESSOR",
    "SCHEMA",
    "SEPARATE_STAGES",
    "STAGES",
    "StageContractError",
    "canonical_json",
    "public_projection",
    "read_handoff",
    "sha256_bytes",
    "validate_envelope",
    "write_handoff",
]
