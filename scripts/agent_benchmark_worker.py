#!/usr/bin/env python3
"""Fail-closed replacement worker for one pre-conformance agent-run sample.

The worker never reads model artifacts. It invokes exactly one bounded agent-run,
validates the host-owned export manifest, and copies only its allowlisted public
projection plus manifest into the static publication tree. Git operations remain
an explicit operator step after repository-wide verification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
from pathlib import Path
from typing import Mapping

EXPORT_SCHEMA = "cvehunt.public-export-manifest/v1"
PUBLIC_SCHEMA = "cvehunt.public-pipeline/v1"
DIMENSIONED_SCHEMA = "cvehunt.dimensioned-result/v1"
_CVE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,19}$")
_RUN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_MAX_PUBLIC_BYTES = 1024 * 1024


class WorkerError(RuntimeError):
    pass


def _read_regular(path: Path, limit: int = _MAX_PUBLIC_BYTES) -> bytes:
    info = path.lstat()
    if path.is_symlink() or not path.is_file() or info.st_nlink != 1 or info.st_size > limit:
        raise WorkerError("unsafe export file")
    data = path.read_bytes()
    if len(data) != info.st_size:
        raise WorkerError("export changed while reading")
    return data


def _json(path: Path) -> Mapping[str, object]:
    try:
        value = json.loads(
            _read_regular(path),
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise WorkerError("invalid export JSON") from None
    if not isinstance(value, dict):
        raise WorkerError("export JSON must be an object")
    return value


def validate_export_bundle(run_dir: Path, *, cve_id: str, run_id: str) -> tuple[bytes, bytes]:
    manifest_path = run_dir / "public-export-manifest.json"
    public_path = run_dir / "public-pipeline.json"
    manifest_bytes = _read_regular(manifest_path)
    manifest = _json(manifest_path)
    public_bytes = _read_regular(public_path)
    public = _json(public_path)
    expected_manifest_keys = {
        "schema", "run_id", "cve_id", "disposition",
        "evaluation_contract_sha256", "headline_eligible", "exports",
    }
    if (
        set(manifest) != expected_manifest_keys
        or manifest.get("schema") != EXPORT_SCHEMA
        or manifest.get("cve_id") != cve_id
        or manifest.get("run_id") != run_id
        or manifest.get("disposition") not in {"completed", "refused"}
        or manifest.get("headline_eligible") is not False
        or not _SHA.fullmatch(str(manifest.get("evaluation_contract_sha256", "")))
    ):
        raise WorkerError("export manifest identity or policy mismatch")
    exports = manifest.get("exports")
    if not isinstance(exports, list) or len(exports) != 1:
        raise WorkerError("export manifest must declassify exactly one artifact")
    export = exports[0]
    if not isinstance(export, dict) or set(export) != {
        "artifact_id", "relative_path", "sha256", "bytes", "classification",
        "top_level_fields", "stage_fields",
    }:
        raise WorkerError("invalid export declaration")
    if (
        export.get("artifact_id") != "public-pipeline"
        or export.get("relative_path") != "public-pipeline.json"
        or export.get("classification") != "public_summary"
        or export.get("sha256") != hashlib.sha256(public_bytes).hexdigest()
        or export.get("bytes") != len(public_bytes)
    ):
        raise WorkerError("public projection does not match export manifest")
    top_level = export.get("top_level_fields")
    if not isinstance(top_level, list) or set(top_level) != set(public):
        raise WorkerError("public top-level declassification scope mismatch")
    result = public.get("result")
    if (
        public.get("schema") != PUBLIC_SCHEMA
        or public.get("cve_id") != cve_id
        or public.get("run_id") != run_id
        or not isinstance(result, dict)
        or result.get("schema") != DIMENSIONED_SCHEMA
        or result.get("implementation_status") != "pre_conformance"
        or result.get("headline_eligible") is not False
    ):
        raise WorkerError("public projection is not a valid pre-conformance result")
    stage_fields = export.get("stage_fields")
    stages = public.get("stages")
    if not isinstance(stage_fields, list) or not isinstance(stages, list) or any(
        not isinstance(stage, dict) or set(stage) != set(stage_fields) for stage in stages
    ):
        raise WorkerError("stage declassification scope mismatch")
    return public_bytes, manifest_bytes


def publish_export_bundle(
    run_dir: Path, destination_root: Path, *, cve_id: str, run_id: str,
) -> Path:
    public_bytes, manifest_bytes = validate_export_bundle(
        run_dir, cve_id=cve_id, run_id=run_id,
    )
    destination = destination_root / cve_id / run_id
    destination.mkdir(parents=True, mode=0o755, exist_ok=True)
    for name, data in (
        ("agent-run.json", public_bytes),
        ("export-manifest.json", manifest_bytes),
    ):
        target = destination / name
        if target.exists() or target.is_symlink():
            if target.is_symlink() or _read_regular(target) != data:
                raise WorkerError("non-idempotent publication collision")
            continue
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(target, flags, 0o644)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    return destination


def _run_once(argv: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
    process = subprocess.Popen(
        argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, start_new_session=True, close_fds=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise WorkerError("agent-run deadline exhausted") from None
    return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("cve_id")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--runtime-policy", required=True)
    parser.add_argument("--research-policy", required=True)
    parser.add_argument("--oracle", required=True)
    parser.add_argument("--target-policy", required=True)
    parser.add_argument("--pi-models", default="~/.pi/agent/models.json")
    parser.add_argument("--pi-auth", default="~/.pi/agent/auth.json")
    parser.add_argument("--timeout", type=float, default=7200.0)
    parser.add_argument("--publish-root", default="web/public/published")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if not _CVE.fullmatch(args.cve_id) or not _RUN.fullmatch(args.run_id):
        print("invalid worker identity", file=sys.stderr)
        return 2
    if not 0 < args.timeout <= 7200:
        print("invalid worker timeout", file=sys.stderr)
        return 2
    command = [
        "uv", "run", "cvehunt", "--data-dir", str(Path(args.data_dir).expanduser()),
        "agent-run", args.cve_id, "--run-id", args.run_id, "--provider", "pi",
        "--model", args.model, "--runtime-policy", args.runtime_policy,
        "--research-policy", args.research_policy, "--oracle", args.oracle,
        "--target-policy", args.target_policy, "--pi-models", args.pi_models,
        "--pi-auth", args.pi_auth, "--timeout", str(args.timeout), "--json",
    ]
    try:
        completed = _run_once(command, args.timeout + 30.0)
        if completed.returncode != 0:
            raise WorkerError("agent-run failed")
        summary = json.loads(completed.stdout)
        if (
            not isinstance(summary, dict)
            or summary.get("status") not in {"completed", "refused"}
            or summary.get("cve_id") != args.cve_id
            or summary.get("run_id") != args.run_id
        ):
            raise WorkerError("agent-run returned an invalid summary")
        run_dir = Path(args.data_dir).expanduser() / "cves" / args.cve_id / "runs" / args.run_id
        publish_export_bundle(
            run_dir, Path(args.publish_root), cve_id=args.cve_id, run_id=args.run_id,
        )
    except (OSError, ValueError, json.JSONDecodeError, WorkerError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps({
        "status": summary["status"], "cve_id": args.cve_id, "run_id": args.run_id,
        "published": "pre_conformance_public_summary",
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
