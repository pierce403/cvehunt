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
  where the ``--dir`` is the isolated model context (parity with pi/codex),
  not the repo working directory; a disposable copy of the run directory is
  seeded into it at the prompt-relative path so tool-using models can read
  the persisted artifacts the way the verified PR #8 run did.
* the NDJSON event stream is decoded to plain assistant text (tags are
  JSON-escaped in the raw stream and the shared ``<CVEHUNT_FILE>`` extractor
  can never match them otherwise), per-step token usage is captured, and
  allowlisted artifacts the model wrote with its file tools are lifted out
  of the context before it is deleted.
* a missing ``opencode`` binary is reported as ``command_missing`` / exit 127
  without invoking the extractor.
* a model that stops producing transcript/stderr output is killed by the
  progress monitor's stall detector (matched via the isolated context dir in
  the model's argv) and recorded with status ``stalled``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
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


def _fake_opencode(
    bin_dir: Path,
    argv_log: Path,
    transcript: str,
    context_files: dict[str, str] | None = None,
    block_seconds: int | None = None,
) -> None:
    """Install a fake ``opencode`` that logs its argv and prints a transcript.

    ``context_files`` simulates the model using its file tools: each
    name/content pair is written into the isolated ``--dir`` context before
    the transcript is printed. ``block_seconds`` makes the fake go silent
    (no output at all) for that many seconds, simulating a hung model.
    """
    bin_dir.mkdir(parents=True, exist_ok=True)
    transcript_file = bin_dir / "canned-transcript.txt"
    transcript_file.write_text(transcript, encoding="utf-8")
    lines = [
        "#!/usr/bin/env bash",
        "set -eu",
        f"printf '%s\\n' \"$@\" > {json.dumps(str(argv_log))}",
    ]
    if block_seconds:
        lines.append(f"sleep {block_seconds}")
    if context_files:
        lines.append(
            'dir=""\n'
            'prev=""\n'
            'for a in "$@"; do\n'
            '  if [[ "$prev" == "--dir" ]]; then dir="$a"; fi\n'
            '  prev="$a"\n'
            "done\n"
        )
        for name, content in context_files.items():
            canned = bin_dir / ("canned-" + name.replace("/", "_"))
            canned.write_text(content, encoding="utf-8")
            lines.append(
                f'mkdir -p "$(dirname "$dir/{name}")"\n'
                f'cp {json.dumps(str(canned))} "$dir/{name}"'
            )
    lines.append(f"cat {json.dumps(str(transcript_file))}\n")
    script = bin_dir / "opencode"
    script.write_text("\n".join(lines), encoding="utf-8")
    script.chmod(0o755)


def _driver(sourceable: Path, stub_monitor: bool = True) -> str:
    """Bash driver: source the harness, stub heavy helpers, call the function."""
    monitor_stubs = (
        "start_model_progress_monitor() { :; }\n"
        "stop_model_progress_monitor() { :; }\n"
        if stub_monitor
        else ""
    )
    return (
        "#!/usr/bin/env bash\n"
        f"source {json.dumps(str(sourceable))}\n"
        # The opencode branch does not author the prompt; stub it so the test
        # stays focused on the harness dispatch.
        "write_model_attempt_prompt() { printf 'PROMPT-BODY\\n' > \"$6\"; }\n"
        + monitor_stubs
        + 'run_model_attempt "$@"\n'
    )


def _workspace(tmp_path: Path) -> tuple[Path, Path]:
    """A cwd with src/ (for the in-branch extractor) and an existing run dir."""
    ws = tmp_path / "ws"
    ws.mkdir()
    os.symlink(REPO_ROOT / "src", ws / "src")
    run_dir = ws / "cves" / CVE_ID / "runs" / RUN_ID
    run_dir.mkdir(parents=True)
    return ws, run_dir / "model_attempt"


def _run(
    tmp_path: Path,
    ws: Path,
    extra_path: str,
    stub_monitor: bool = True,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    sourceable = _sourceable_contribute(tmp_path / "contribute.sourceable.sh")
    driver = tmp_path / "driver.sh"
    driver.write_text(_driver(sourceable, stub_monitor=stub_monitor), encoding="utf-8")
    env = dict(os.environ)
    env["PATH"] = f"{extra_path}:/usr/bin:/bin" if extra_path else "/usr/bin:/bin"
    env["CVEHUNT_SKIP_MODEL"] = "0"
    if extra_env:
        env.update(extra_env)
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
    assert "--format json --print-logs --dir <isolated-context-with-run-copy>" in command

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


def _ndjson(*events: dict) -> str:
    return "".join(json.dumps(ev) + "\n" for ev in events)


def test_opencode_stalled_model_is_killed_and_marked(tmp_path: Path) -> None:
    """A model whose transcript and stderr stop growing has hung (observed:
    opencode parked 5h18m on a dead vLLM connection). The progress monitor
    must SIGTERM the run's model processes (matched via the isolated context
    dir in their argv), write stall.marker, and flip the status to
    "stalled" instead of burning the full hard timeout."""
    ws, attempt = _workspace(tmp_path)
    bin_dir = tmp_path / "bin"
    argv_log = tmp_path / "opencode_argv.txt"
    _fake_opencode(bin_dir, argv_log, transcript="", block_seconds=60)

    started = time.monotonic()
    proc = _run(
        tmp_path,
        ws,
        str(bin_dir),
        stub_monitor=False,
        extra_env={
            "CVEHUNT_MODEL_STALL_SECONDS": "3",
            "CVEHUNT_MODEL_PROGRESS_INTERVAL": "3",
        },
    )
    elapsed = time.monotonic() - started
    assert proc.returncode == 0, proc.stderr
    # The stall killer must have terminated the silent fake well before its
    # 60s sleep (and long before any hard timeout).
    assert elapsed < 30, f"stall kill did not fire in time (took {elapsed:.1f}s)"

    marker = json.loads((attempt / "stall.marker").read_text(encoding="utf-8"))
    assert "cvehunt-model-context" in marker["kill_pattern"]
    assert marker["no_growth_seconds"] >= 3

    meta = json.loads((attempt / "metadata.json").read_text(encoding="utf-8"))
    assert meta["status"] == "stalled"


def test_opencode_ndjson_transcript_is_decoded_before_extraction(tmp_path: Path) -> None:
    """Real opencode output is NDJSON: <CVEHUNT_FILE> tags inside text parts
    are JSON-escaped and the shared extractor regex can never match them
    unless the branch decodes the stream to plain assistant text first."""
    ws, attempt = _workspace(tmp_path)
    bin_dir = tmp_path / "bin"
    argv_log = tmp_path / "opencode_argv.txt"
    transcript = _ndjson(
        {"type": "step_start", "part": {"type": "step-start"}},
        {
            "type": "text",
            "part": {
                "type": "text",
                "text": (
                    "Analysis complete.\n"
                    '<CVEHUNT_FILE path="notes.md">\n'
                    "Decoded note from an NDJSON text part.\n"
                    "</CVEHUNT_FILE>\n"
                ),
            },
        },
        {
            "type": "step_finish",
            "part": {
                "type": "step-finish",
                "reason": "stop",
                "tokens": {"total": 1234, "input": 1000, "output": 234, "reasoning": 0, "cache": {"read": 0, "write": 0}},
            },
        },
    )
    _fake_opencode(bin_dir, argv_log, transcript)

    proc = _run(tmp_path, ws, str(bin_dir))
    assert proc.returncode == 0, proc.stderr

    extracted = json.loads((attempt / "extracted.json").read_text(encoding="utf-8"))
    assert extracted["state"] == "notes_proposed", extracted
    assert any(r["path"] == "model_attempt/notes.md" for r in extracted["extracted_files"])
    assert "Decoded note from an NDJSON text part." in (attempt / "notes.md").read_text(encoding="utf-8")

    # Per-step token usage from step_finish events lands in usage.json and
    # is surfaced in metadata token accounting.
    usage = json.loads((attempt / "usage.json").read_text(encoding="utf-8"))
    assert usage["source"] == "opencode_ndjson_step_usage_sum"
    assert usage["totalTokens"] == 1234
    meta = json.loads((attempt / "metadata.json").read_text(encoding="utf-8"))
    assert meta["status"] == "notes_proposed"
    assert meta["token_usage"]["totalTokens"] == 1234


def test_opencode_context_files_written_by_model_are_recovered(tmp_path: Path) -> None:
    """Models with file tools author artifacts by writing them into their
    working directory (the verified Ornith pattern wrote them into the run
    tree). The isolated context is deleted after the run, so allowlisted
    files must be lifted out of it -- seeded run tree first, then context
    root -- and flow through the same <CVEHUNT_FILE> safety checks."""
    ws, attempt = _workspace(tmp_path)
    bin_dir = tmp_path / "bin"
    argv_log = tmp_path / "opencode_argv.txt"
    run_rel = f"cves/{CVE_ID}/runs/{RUN_ID}"
    transcript = _ndjson(
        {"type": "step_start", "part": {"type": "step-start"}},
        {"type": "text", "part": {"type": "text", "text": "All artifacts written to the working directory.\n"}},
        {
            "type": "step_finish",
            "part": {"type": "step-finish", "reason": "stop", "tokens": {"total": 10, "input": 9, "output": 1, "reasoning": 0, "cache": {"read": 0, "write": 0}}},
        },
    )
    _fake_opencode(
        bin_dir,
        argv_log,
        transcript,
        context_files={
            f"{run_rel}/notes.md": "Recovered from the seeded run tree.\n",
            "safety.md": "Recovered from the context root.\n",
        },
    )

    proc = _run(tmp_path, ws, str(bin_dir))
    assert proc.returncode == 0, proc.stderr

    extracted = json.loads((attempt / "extracted.json").read_text(encoding="utf-8"))
    assert extracted["state"] == "notes_proposed", extracted
    paths = {r["path"] for r in extracted["extracted_files"]}
    assert "model_attempt/notes.md" in paths
    assert "model_attempt/safety.md" in paths
    assert "Recovered from the seeded run tree." in (attempt / "notes.md").read_text(encoding="utf-8")
    assert "Recovered from the context root." in (attempt / "safety.md").read_text(encoding="utf-8")
