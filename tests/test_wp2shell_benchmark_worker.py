from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _load_worker():
    path = ROOT / "scripts" / "wp2shell_benchmark_worker.py"
    spec = importlib.util.spec_from_file_location("wp2shell_benchmark_worker", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_legacy_worker_is_retired_before_state_git_provider_or_docker_side_effects(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    worker = _load_worker()

    def forbidden(*_args, **_kwargs):
        raise AssertionError("retired worker attempted an external side effect")

    monkeypatch.setattr(worker.subprocess, "Popen", forbidden)
    monkeypatch.setattr(worker, "read_state", forbidden)

    assert worker.main() == 1
    assert "retired" in capsys.readouterr().err


def test_attempt_claim_is_global_per_utc_hour_and_rotates_on_failure() -> None:
    worker = _load_worker()
    state = worker.default_state()
    now = datetime(2026, 7, 20, 13, 5, tzinfo=UTC)

    first = worker.claim_attempt(state, now)

    assert first["key"] == "5.6-sol"
    assert state["last_attempt_hour"] == "2026-07-20T13:00:00Z"
    assert state["next_index"] == 1
    assert worker.claim_attempt(state, datetime(2026, 7, 20, 13, 59, tzinfo=UTC)) is None

    second = worker.claim_attempt(state, datetime(2026, 7, 20, 14, 0, tzinfo=UTC))
    assert second["key"] == "glm5.2"
    assert state["next_index"] == 2


def test_attempt_claim_fails_closed_after_clock_rollback() -> None:
    worker = _load_worker()
    state = worker.default_state()

    assert worker.claim_attempt(state, datetime(2026, 7, 20, 13, 0, tzinfo=UTC)) is not None
    assert worker.claim_attempt(state, datetime(2026, 7, 20, 14, 0, tzinfo=UTC)) is not None

    assert worker.claim_attempt(state, datetime(2026, 7, 20, 13, 30, tzinfo=UTC)) is None
    assert state["last_attempt_hour"] == "2026-07-20T14:00:00Z"


def test_read_state_rejects_corrupt_json_without_resetting_campaign(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    worker = _load_worker()
    state_path = tmp_path / "worker-state.json"
    corrupt = "{not-json\n"
    state_path.write_text(corrupt, encoding="utf-8")
    monkeypatch.setattr(worker, "STATE", state_path)

    with pytest.raises(worker.StateRecoveryRequired, match="manual recovery required"):
        worker.read_state()

    assert state_path.read_text(encoding="utf-8") == corrupt
    diagnostics = list(tmp_path.glob("worker-state.json.corrupt-*"))
    assert len(diagnostics) == 1
    assert diagnostics[0].read_text(encoding="utf-8") == corrupt


def test_read_state_migrates_existing_schema_one_campaign(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    worker = _load_worker()
    state_path = tmp_path / "worker-state.json"
    state_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "next_index": 2,
                "samples": {"5.6-sol": [{"run_id": "existing"}]},
                "last_result": {"status": "blocked"},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(worker, "STATE", state_path)

    migrated = worker.read_state()

    assert migrated["schema_version"] == 3
    assert migrated["next_index"] == 2
    assert migrated["samples"]["5.6-sol"] == [{"run_id": "existing"}]
    assert migrated["last_attempt_hour"] is None
    assert migrated["pending_push"] is None


@pytest.mark.parametrize(
    "invalid_update",
    [
        {"next_index": "0"},
        {"samples": []},
        {"last_attempt_hour": "not-an-hour"},
        {"pending_push": []},
    ],
)
def test_read_state_rejects_structurally_invalid_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, invalid_update: dict[str, object]
) -> None:
    worker = _load_worker()
    state_path = tmp_path / "worker-state.json"
    state = worker.default_state()
    state.update(invalid_update)
    state_path.write_text(json.dumps(state), encoding="utf-8")
    monkeypatch.setattr(worker, "STATE", state_path)

    with pytest.raises(worker.StateRecoveryRequired, match="manual recovery required"):
        worker.read_state()


def test_attempt_claim_skips_models_with_complete_sample_quota() -> None:
    worker = _load_worker()
    state = worker.default_state()
    state["samples"] = {"5.6-sol": [{"run_id": str(index)} for index in range(worker.TARGET_SAMPLES)]}

    selected = worker.claim_attempt(state, datetime(2026, 7, 20, 15, 0, tzinfo=UTC))

    assert selected["key"] == "glm5.2"


@pytest.mark.parametrize(
    "status",
    [
        None,
        "ok",
        "completed",
        "provider_error",
        "setup_failed",
        "timeout",
        "partial",
        "failed",
        "provenance_violation",
        "out_of_scope",
    ],
)
def test_only_producer_terminal_statuses_are_publishable(status: str | None) -> None:
    worker = _load_worker()
    assert worker.is_publishable_run(0, {"status": status, "exit_code": 0}) is False


@pytest.mark.parametrize(
    "status",
    [
        "poc_and_patch_proposed",
        "poc_proposed",
        "patch_proposed",
        "notes_proposed",
        "refused",
        "no_artifacts",
    ],
)
def test_producer_terminal_statuses_require_zero_outer_and_metadata_exits(status: str) -> None:
    worker = _load_worker()
    assert worker.is_publishable_run(0, {"status": status, "exit_code": 0}) is True
    assert worker.is_publishable_run(1, {"status": status, "exit_code": 0}) is False
    assert worker.is_publishable_run(0, {"status": status, "exit_code": 1}) is False


@pytest.mark.parametrize("metadata_exit", [None, "0", 0.0, False])
def test_metadata_exit_code_must_be_the_integer_zero(metadata_exit: object) -> None:
    worker = _load_worker()
    metadata = {"status": "poc_proposed", "exit_code": metadata_exit}

    assert worker.is_publishable_run(0, metadata) is False


def test_timed_command_terminates_the_complete_process_group(tmp_path: Path) -> None:
    worker = _load_worker()
    marker = tmp_path / "orphan-survived"
    command = [
        "bash",
        "-c",
        f"(sleep 0.4; touch {marker}) & wait",
    ]

    with pytest.raises(worker.CommandTimeout):
        worker.run(command, io.StringIO(), cwd=tmp_path, timeout=0.05)

    time.sleep(0.55)
    assert not marker.exists()


def test_timeout_kills_sigterm_ignoring_descendant_after_leader_exits(tmp_path: Path) -> None:
    worker = _load_worker()
    marker = tmp_path / "hostile-child-survived"
    script = (
        "import os, signal, time\n"
        "pid = os.fork()\n"
        "if pid == 0:\n"
        "    signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "    time.sleep(2.0)\n"
        f"    open({str(marker)!r}, 'w').close()\n"
        "    os._exit(0)\n"
        "signal.signal(signal.SIGTERM, lambda *_: os._exit(0))\n"
        "os.waitpid(pid, 0)\n"
    )

    with pytest.raises(worker.CommandTimeout):
        worker.run(["python3", "-c", script], io.StringIO(), cwd=tmp_path, timeout=0.1)

    time.sleep(1.2)
    assert not marker.exists()


def test_failed_run_is_archived_outside_repository(tmp_path: Path) -> None:
    worker = _load_worker()
    run_dir = tmp_path / "repo" / "cves" / worker.CVE / "runs" / "failed-run"
    run_dir.mkdir(parents=True)
    (run_dir / "evidence.json").write_text("{}", encoding="utf-8")
    archive_root = tmp_path / "local-failures"

    archived = worker.archive_failed_run(run_dir, archive_root)

    assert not run_dir.exists()
    assert archived.parent == archive_root
    assert (archived / "evidence.json").exists()


def test_precommit_recovery_restores_only_generated_publication_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    worker = _load_worker()
    repo = tmp_path / "repo"
    (repo / "docs").mkdir(parents=True)
    (repo / "docs" / "index.html").write_text("before\n", encoding="utf-8")
    (repo / ".gitignore").write_text("cves/*/runs/*/sources/\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    subprocess.run(["git", "add", ".gitignore", "docs/index.html"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "baseline"], cwd=repo, check=True)
    monkeypatch.setattr(worker, "REPO", repo)

    run_dir = repo / "cves" / worker.CVE / "runs" / "candidate"
    (run_dir / "sources").mkdir(parents=True)
    (run_dir / "benchmark_manifest.json").write_text("{}", encoding="utf-8")
    (run_dir / "sources" / "ignored.txt").write_text("local", encoding="utf-8")
    (repo / "docs" / "index.html").write_text("generated\n", encoding="utf-8")
    (repo / "docs" / "new-asset.js").write_text("generated\n", encoding="utf-8")

    worker._stage_publication(run_dir, io.StringIO())
    archived = worker.archive_failed_run(run_dir, tmp_path / "failures")
    worker._restore_uncommitted_publication(run_dir)

    assert (repo / "docs" / "index.html").read_text(encoding="utf-8") == "before\n"
    assert not (repo / "docs" / "new-asset.js").exists()
    assert (archived / "sources" / "ignored.txt").exists()
    status = subprocess.run(
        ["git", "status", "--porcelain=v1"], cwd=repo, text=True, capture_output=True, check=True
    ).stdout
    assert status == ""


def test_staging_includes_only_run_and_docs_changes_and_handles_generated_renames(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    worker = _load_worker()
    repo = tmp_path / "repo"
    run_dir = repo / "cves" / worker.CVE / "runs" / "candidate"
    (repo / "docs" / "assets").mkdir(parents=True)
    run_dir.mkdir(parents=True)
    (repo / ".gitignore").write_text(
        "cves/*/runs/*/sources/\nweb/public/data/\n", encoding="utf-8"
    )
    (repo / "docs" / "assets" / "old.js").write_text("old\n", encoding="utf-8")
    (run_dir / "tracked.json").write_text("before\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    subprocess.run(["git", "add", ".gitignore", "docs", "cves"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "baseline"], cwd=repo, check=True)
    monkeypatch.setattr(worker, "REPO", repo)

    (run_dir / "tracked.json").write_text("after\n", encoding="utf-8")
    (run_dir / "new.json").write_text("new\n", encoding="utf-8")
    (run_dir / "sources").mkdir()
    (run_dir / "sources" / "ignored.txt").write_text("ignored\n", encoding="utf-8")
    (repo / "docs" / "assets" / "old.js").rename(repo / "docs" / "assets" / "new.js")
    ignored_site_data = repo / "web" / "public" / "data" / "cves.json"
    ignored_site_data.parent.mkdir(parents=True)
    ignored_site_data.write_text("ignored\n", encoding="utf-8")

    worker._stage_publication(run_dir, io.StringIO())

    staged = subprocess.run(
        ["git", "diff", "--cached", "--name-status"],
        cwd=repo,
        text=True,
        capture_output=True,
        check=True,
    ).stdout
    assert "cves/CVE-2026-63030/runs/candidate/tracked.json" in staged
    assert "cves/CVE-2026-63030/runs/candidate/new.json" in staged
    assert "docs/assets/old.js" in staged
    assert "docs/assets/new.js" in staged
    assert "sources/ignored.txt" not in staged
    assert "web/public/data/cves.json" not in staged


@pytest.mark.parametrize(
    "private_relative",
    [
        "models/01-collector/log/prompt.md",
        "packets/collector.json",
        "callbacks/05-provision/execution-audit.json",
        "envelopes/collector.json",
        "handoffs/collector.json",
        "objects/exploiter/candidate.py",
        "oracle/score.json",
        "candidates/poc.py",
        "patches/fix.patch",
        "model_attempt/transcript.ndjson",
    ],
)
def test_staging_rejects_private_run_subtrees_before_git_add(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, private_relative: str
) -> None:
    worker = _load_worker()
    repo = tmp_path / "repo"
    run_dir = repo / "cves" / worker.CVE / "runs" / "candidate"
    (repo / "docs").mkdir(parents=True)
    private = run_dir / private_relative
    private.parent.mkdir(parents=True)
    private.write_text("private\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    (repo / "baseline.txt").write_text("baseline\n", encoding="utf-8")
    subprocess.run(["git", "add", "baseline.txt"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "baseline"], cwd=repo, check=True)
    monkeypatch.setattr(worker, "REPO", repo)

    with pytest.raises(RuntimeError, match="private benchmark path"):
        worker._stage_publication(run_dir, io.StringIO())

    staged = subprocess.run(
        ["git", "diff", "--cached", "--name-only"], cwd=repo,
        text=True, capture_output=True, check=True,
    ).stdout
    assert staged == ""


def test_staging_unstages_unexpected_paths_before_failing_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    worker = _load_worker()
    repo = tmp_path / "repo"
    run_dir = repo / "cves" / worker.CVE / "runs" / "candidate"
    (repo / "docs").mkdir(parents=True)
    run_dir.mkdir(parents=True)
    (repo / "baseline.txt").write_text("before\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    subprocess.run(["git", "add", "baseline.txt"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "baseline"], cwd=repo, check=True)
    monkeypatch.setattr(worker, "REPO", repo)

    (repo / "baseline.txt").write_text("unexpected staged edit\n", encoding="utf-8")
    subprocess.run(["git", "add", "baseline.txt"], cwd=repo, check=True)
    (run_dir / "sample.json").write_text("{}\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="unexpected staged paths"):
        worker._stage_publication(run_dir, io.StringIO())

    staged = subprocess.run(
        ["git", "diff", "--cached", "--name-only"],
        cwd=repo,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.splitlines()
    assert staged == ["cves/CVE-2026-63030/runs/candidate/sample.json"]
    assert (repo / "baseline.txt").read_text(encoding="utf-8") == "unexpected staged edit\n"


def _init_worker_git_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    worker = _load_worker()
    repo = tmp_path / "repo"
    remote = tmp_path / "remote.git"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True)
    subprocess.run(["git", "init", "-q", "-b", worker.BRANCH], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    (repo / "baseline.txt").write_text("baseline\n", encoding="utf-8")
    subprocess.run(["git", "add", "baseline.txt"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "baseline"], cwd=repo, check=True)
    subprocess.run(["git", "remote", "add", "fork", str(remote)], cwd=repo, check=True)
    subprocess.run(["git", "push", "-q", "fork", worker.BRANCH], cwd=repo, check=True)
    monkeypatch.setattr(worker, "REPO", repo)
    monkeypatch.setattr(worker, "STATE", tmp_path / "state.json")
    return worker, repo


def test_recovery_adopts_commit_created_before_pending_state_update(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    worker, repo = _init_worker_git_repo(tmp_path, monkeypatch)
    parent = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, text=True, capture_output=True, check=True
    ).stdout.strip()
    sample_path = repo / "cves" / worker.CVE / "runs" / "run-one" / "sample.txt"
    sample_path.parent.mkdir(parents=True)
    sample_path.write_text("sample\n", encoding="utf-8")
    subprocess.run(["git", "add", str(sample_path.relative_to(repo))], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "sample"], cwd=repo, check=True)
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, text=True, capture_output=True, check=True
    ).stdout.strip()
    state = worker.default_state()
    state["pending_push"] = {
        "phase": "commit_intent",
        "parent": parent,
        "commit_message": "sample",
        "model_key": "5.6-sol",
        "sample": {"run_id": "run-one"},
    }

    worker._recover_pending_commit(state, io.StringIO())

    assert state["pending_push"]["phase"] == "committed"
    assert state["pending_push"]["commit"] == head
    assert state["pending_push"]["sample"]["commit"] == head


def test_recovery_rejects_unrelated_commit_after_durable_intent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    worker, repo = _init_worker_git_repo(tmp_path, monkeypatch)
    parent = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, text=True, capture_output=True, check=True
    ).stdout.strip()
    (repo / "unrelated.txt").write_text("unrelated\n", encoding="utf-8")
    subprocess.run(["git", "add", "unrelated.txt"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "unrelated"], cwd=repo, check=True)
    state = worker.default_state()
    state["pending_push"] = {
        "phase": "commit_intent",
        "parent": parent,
        "commit_message": "sample",
        "model_key": "5.6-sol",
        "sample": {"run_id": "run-one"},
    }

    with pytest.raises(RuntimeError, match="unexpected paths"):
        worker._recover_pending_commit(state, io.StringIO())


def test_push_recovery_accounts_remote_accepted_commit_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    worker, repo = _init_worker_git_repo(tmp_path, monkeypatch)
    (repo / "sample.txt").write_text("sample\n", encoding="utf-8")
    subprocess.run(["git", "add", "sample.txt"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "sample"], cwd=repo, check=True)
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, text=True, capture_output=True, check=True
    ).stdout.strip()
    subprocess.run(["git", "push", "-q", "fork", worker.BRANCH], cwd=repo, check=True)
    sample = {"run_id": "run-one", "commit": head}
    state = worker.default_state()
    state["pending_push"] = {
        "phase": "committed",
        "commit": head,
        "model_key": "5.6-sol",
        "sample": sample,
    }

    assert worker._publish_pending_push(state, io.StringIO()) is True
    assert state["pending_push"] is None
    assert state["samples"]["5.6-sol"] == [sample]

    state["pending_push"] = {
        "phase": "committed",
        "commit": head,
        "model_key": "5.6-sol",
        "sample": sample,
    }
    assert worker._publish_pending_push(state, io.StringIO()) is True
    assert state["samples"]["5.6-sol"] == [sample]


def test_push_error_reconciles_remote_that_accepted_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    worker, repo = _init_worker_git_repo(tmp_path, monkeypatch)
    sample_path = repo / "cves" / worker.CVE / "runs" / "run-two" / "sample.txt"
    sample_path.parent.mkdir(parents=True)
    sample_path.write_text("sample\n", encoding="utf-8")
    subprocess.run(["git", "add", str(sample_path.relative_to(repo))], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "sample"], cwd=repo, check=True)
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, text=True, capture_output=True, check=True
    ).stdout.strip()
    state = worker.default_state()
    state["pending_push"] = {
        "phase": "committed",
        "commit": head,
        "model_key": "5.6-sol",
        "sample": {"run_id": "run-two", "commit": head},
    }

    def accepted_but_reported_error(command, log, **kwargs):
        assert command[:2] == ["git", "push"]
        subprocess.run(command, cwd=repo, check=True, stdout=subprocess.DEVNULL)
        return subprocess.CompletedProcess(command, 1)

    monkeypatch.setattr(worker, "run", accepted_but_reported_error)

    assert worker._publish_pending_push(state, io.StringIO()) is True
    assert state["pending_push"] is None
    assert state["samples"]["5.6-sol"] == [{"run_id": "run-two", "commit": head}]
