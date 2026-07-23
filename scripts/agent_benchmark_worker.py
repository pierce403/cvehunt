#!/usr/bin/env python3
"""Fail-closed replacement worker for one pre-conformance agent-run sample.

The worker never reads model artifacts. It invokes exactly one bounded agent-run,
validates the host-owned export manifest, and copies only its allowlisted public
projection plus manifest into the static publication tree. Git operations remain
an explicit operator step after repository-wide verification.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import signal
import stat
import subprocess
import sys
from pathlib import Path
from typing import Mapping

from cvehunt.agent_entry import AgentEntryError, validate_public_export_bundle

_CVE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,19}$")
_RUN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_MAX_PUBLIC_BYTES = 1024 * 1024


class WorkerError(RuntimeError):
    pass


def _read_regular(path: Path, limit: int = _MAX_PUBLIC_BYTES) -> bytes:
    try:
        info = path.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size > limit
        ):
            raise WorkerError("unsafe export file")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except WorkerError:
        raise
    except OSError:
        raise WorkerError("unsafe export file") from None
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)
        ):
            raise WorkerError("export changed while opening")
        data = bytearray()
        while True:
            block = os.read(fd, min(64 * 1024, limit - len(data) + 1))
            if not block:
                break
            data.extend(block)
            if len(data) > limit:
                raise WorkerError("unsafe export file")
        if len(data) != info.st_size:
            raise WorkerError("export changed while reading")
        return bytes(data)
    except OSError:
        raise WorkerError("unsafe export file") from None
    finally:
        os.close(fd)


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
    try:
        validate_public_export_bundle(
            manifest,
            public,
            public_bytes,
            expected_cve_id=cve_id,
            expected_run_id=run_id,
        )
    except AgentEntryError:
        raise WorkerError("invalid public export bundle") from None
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
