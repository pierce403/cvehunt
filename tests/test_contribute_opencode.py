"""Contract tests for the opencode external-model harness branch in contribute.sh.

`contribute.sh` runs ``main "$@"`` at the very bottom, so it cannot be sourced
as-is without launching the interactive runner. These tests make a sourceable
copy with that final line stripped, source it inside a small bash driver, stub
the few heavy helpers the opencode branch does not itself exercise (prompt
authoring and the progress monitor), put a fake ``opencode`` CLI on ``PATH``,
and drive ``run_model_attempt`` for the ``opencode`` harness.

This exercises the real dispatch added for opencode support:

* ``command.txt`` records the documented invocation shape.
* the ``opencode`` CLI is actually called as
  ``opencode run --model <model> --format json --print-logs --dir <isolated-context> <prompt>``
  where the ``--dir`` is the isolated empty model context (parity with pi/codex),
  not the repo working directory.
* the model transcript is copied to ``response.md`` and flows through the same
  ``<CVEHUNT_FILE>`` extractor as every other harness.
* a missing ``opencode`` binary is reported as ``command_missing`` / exit 127
  without invoking the extractor.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
CONTRIBUTE = REPO_ROOT / "contribute.sh"

MODEL = "vllm/ornith-test"
MODEL_LABEL = f"opencode:{MODEL}"
CVE_ID = "CVE-OPENCODE-TEST"
RUN_ID = "2026-01-01T00-00-00Z"

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None or not CONTRIBUTE.exists(),
    reason="requires bash and contribute.sh",
)


def _sourceable_contribute(dst: Path) -> Path:
    """Copy contribute.sh with the trailing ``main "$@"`` executor removed."""
    lines = CONTRIBUTE.read_text(encoding="utf-8").splitlines()
    for i in range(len(lines) - 1, -1, -1):
        if lines[i].strip():
            assert lines[i].strip() == 'main "$@"', f"unexpected last line: {lines[i]!r}"
            del lines[i]
            break
    dst.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return dst


def _fake_opencode(bin_dir: Path, argv_log: Path, transcript: str) -> None:
    """Install a fake ``opencode`` that logs its argv and prints a transcript."""
    bin_dir.mkdir(parents=True, exist_ok=True)
    transcript_file = bin_dir / "canned-transcript.txt"
    transcript_file.write_text(transcript, encoding="utf-8")
    script = bin_dir / "opencode"
    script.write_text(
        "#!/usr/bin/env bash\n"
        "set -eu\n"
        f"printf '%s\\n' \"$@\" > {json.dumps(str(argv_log))}\n"
        f"cat {json.dumps(str(transcript_file))}\n",
        encoding="utf-8",
    )
    script.chmod(0o755)


def _driver(sourceable: Path) -> str:
    """Bash driver: source the harness, stub heavy helpers, call the function."""
    return (
        "#!/usr/bin/env bash\n"
        f"source {json.dumps(str(sourceable))}\n"
        # The opencode branch does not author the prompt or run the live progress
        # monitor; stub them so the test stays focused on the harness dispatch.
        "write_model_attempt_prompt() { printf 'PROMPT-BODY\\n' > \"$6\"; }\n"
        "start_model_progress_monitor() { :; }\n"
        "stop_model_progress_monitor() { :; }\n"
        'run_model_attempt "$@"\n'
    )


def _workspace(tmp_path: Path) -> tuple[Path, Path]:
    """A cwd with src/ (for the in-branch extractor) and an existing run dir."""
    ws = tmp_path / "ws"
    ws.mkdir()
    os.symlink(REPO_ROOT / "src", ws / "src")
    run_dir = ws / "cves" / CVE_ID / "runs" / RUN_ID
    run_dir.mkdir(parents=True)
    return ws, run_dir / "model_attempt"


def _run(tmp_path: Path, ws: Path, extra_path: str) -> subprocess.CompletedProcess[str]:
    sourceable = _sourceable_contribute(tmp_path / "contribute.sourceable.sh")
    driver = tmp_path / "driver.sh"
    driver.write_text(_driver(sourceable), encoding="utf-8")
    env = dict(os.environ)
    env["PATH"] = f"{extra_path}:/usr/bin:/bin" if extra_path else "/usr/bin:/bin"
    env["CVEHUNT_SKIP_MODEL"] = "0"
    return subprocess.run(
        ["bash", str(driver), CVE_ID, RUN_ID, "opencode", MODEL, MODEL_LABEL],
        cwd=str(ws),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_opencode_branch_invokes_cli_and_extracts(tmp_path: Path) -> None:
    ws, attempt = _workspace(tmp_path)
    bin_dir = tmp_path / "bin"
    argv_log = tmp_path / "opencode_argv.txt"
    transcript = (
        "Analysis complete.\n"
        '<CVEHUNT_FILE path="notes.md">\n'
        "Defensive notes: the patched build adds a hasOwnProperty guard.\n"
        "</CVEHUNT_FILE>\n"
    )
    _fake_opencode(bin_dir, argv_log, transcript)

    proc = _run(tmp_path, ws, str(bin_dir))
    assert proc.returncode == 0, proc.stderr

    # command.txt records the documented invocation shape.
    command = (attempt / "command.txt").read_text(encoding="utf-8")
    assert command.startswith("opencode run --model")
    assert "--format json --print-logs --dir <isolated-empty-context>" in command

    # The opencode CLI was actually called with the expected argv.
    args = argv_log.read_text(encoding="utf-8").splitlines()
    assert args[:7] == ["run", "--model", MODEL, "--format", "json", "--print-logs", "--dir"]
    # opencode runs in the isolated empty model context (parity with pi/codex),
    # NOT the repo working dir -- this keeps transcripts free of host paths.
    assert "cvehunt-model-context" in args[7]
    assert os.path.realpath(args[7]) != os.path.realpath(str(ws))
    assert args[8] == "PROMPT-BODY"  # <prompt> from the stubbed prompt author

    # The raw transcript/response are redacted after extraction (the same policy
    # every harness follows); a redaction notice is left in their place.
    assert not (attempt / "transcript.txt").exists()
    assert not (attempt / "response.md").exists()
    assert (attempt / "redaction_notice.md").exists()

    # opencode output flowed through the shared <CVEHUNT_FILE> extractor before
    # redaction: the notes.md artifact was extracted and recorded.
    extracted = json.loads((attempt / "extracted.json").read_text(encoding="utf-8"))
    assert extracted["state"] == "notes_proposed"
    assert any(r["path"] == "model_attempt/notes.md" for r in extracted["extracted_files"])
    assert (attempt / "notes.md").exists()

    meta = json.loads((attempt / "metadata.json").read_text(encoding="utf-8"))
    assert meta["harness"] == "opencode"
    assert meta["model"] == MODEL
    assert meta["model_label"] == MODEL_LABEL
    assert meta["status"] == "notes_proposed"
    assert meta["exit_code"] == 0


def test_opencode_branch_reports_missing_binary(tmp_path: Path) -> None:
    ws, attempt = _workspace(tmp_path)

    # No opencode anywhere on PATH.
    proc = _run(tmp_path, ws, extra_path="")
    assert proc.returncode == 0, proc.stderr

    assert "opencode command missing" in (attempt / "stderr.txt").read_text(encoding="utf-8")
    # The invocation is never constructed when the binary is absent.
    assert not (attempt / "command.txt").exists()

    meta = json.loads((attempt / "metadata.json").read_text(encoding="utf-8"))
    assert meta["harness"] == "opencode"
    assert meta["status"] == "command_missing"
    assert meta["exit_code"] == 127
