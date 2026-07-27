#!/usr/bin/env python3
"""Dev-machine launcher for the fail-closed CVEHunt agent-run pipeline.

Production runs anchor trusted policy files to root ownership and require a
rootless Docker daemon. On a single-user development box without root, those
two *host-integrity* gates cannot be satisfied, so this launcher relaxes
exactly — and only — them:

  1. ``AgentDependencies.expected_root_uid`` is set to the invoking user, so
     the runtime policy may be owned by that user instead of uid 0.
  2. ``DevStageHarness`` accepts a research policy owned by the invoking user
     instead of uid 0 (all other checks — single-link regular file, no
     group/world write bits, hostname allowlist shape — are unchanged).
  3. ``ContainerExecutor`` and the entry ``preflight_docker`` are built with
     ``require_rootless=False`` and the explicit administrator opt-out,
     because dev machines typically run the stock rootful Docker daemon.

Every other gate stays exactly as production: pinned digest-only images,
fail-closed provider/oracle/target validation, bounded stage budgets, the
hidden-oracle scorer, container-plan/candidate validation, the nonce-canary
capability oracle, and the public-export manifest validation. Runs produced
this way are dev samples (the public projection records them as
``native_agent_run_preconformance`` with ``headline_eligible: false``), which
is the honest label for comparing model behavior during development.

Usage:
  uv run python scripts/dev_agent_run.py CVE-2026-63030 \
      --run-id 2026-07-27T06-00-00Z-kimi-k3 --model venice/kimi-k3
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from cvehunt.agent_entry import AgentDependencies, AgentRunConfig, run_agent  # noqa: E402
from cvehunt.pipeline_runtime import ContainerExecutor  # noqa: E402
from cvehunt.stage_harness import (  # noqa: E402
    StageHarness,
    StageHarnessError,
    _read_regular_limited,
    _valid_hostname,
)


class DevStageHarness(StageHarness):
    """StageHarness that accepts an invoking-user-owned research policy.

    This mirrors ``StageHarness._validated_research_policy`` exactly except
    the owner check (``st_uid == os.getuid()`` instead of ``0``). All other
    invariants (single-link regular file, no group/world write bits, JSON
    shape, non-empty hostname allowlist) are preserved verbatim. The stage
    tools extension re-validates the same file inside the model process, so
    the matching ``CVEHUNT_STAGE_POLICY_OWNER_UID`` override is injected
    alongside ``CVEHUNT_STAGE_POLICY`` (production leaves it unset and the
    extension keeps requiring root ownership).
    """

    def _environment(self, request, paths):
        env = super()._environment(request, paths)
        if "CVEHUNT_STAGE_POLICY" in env:
            env["CVEHUNT_STAGE_POLICY_OWNER_UID"] = str(os.getuid())
        return env

    def _validated_research_policy(self) -> Path:
        if self.research_policy_file is None:
            raise StageHarnessError("research requires a policy file")
        try:
            info = self.research_policy_file.lstat()
        except OSError as exc:
            raise StageHarnessError(f"cannot inspect research policy: {exc}") from exc
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or info.st_mode & 0o022
        ):
            raise StageHarnessError(
                "research policy must be an invoking-user-owned, non-writable, single-link regular file"
            )
        try:
            policy = json.loads(
                _read_regular_limited(self.research_policy_file, 64 * 1024, reject_hardlink=True)
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise StageHarnessError(f"invalid research policy JSON: {exc}") from exc
        hosts = policy.get("research_hosts") if isinstance(policy, dict) else None
        if not isinstance(hosts, list) or not hosts or any(not _valid_hostname(item) for item in hosts):
            raise StageHarnessError("research policy requires a non-empty research_hosts hostname list")
        return self.research_policy_file


def _dev_executor_factory(**kwargs):
    """ContainerExecutor for a rootful dev Docker daemon (explicit opt-out)."""
    return ContainerExecutor(
        **kwargs,
        require_rootless=False,
        administrator_allow_non_rootless=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("cve_id")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--model", required=True, help="provider/model, e.g. venice/kimi-k3")
    parser.add_argument("--provider", default="pi")
    parser.add_argument("--data-dir", default=str(REPO))
    parser.add_argument("--config-root", default="~/.config/cvehunt")
    parser.add_argument("--timeout", type=float, default=7200.0)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    root = Path(args.config_root).expanduser()
    config = AgentRunConfig(
        data_dir=Path(args.data_dir).resolve(),
        cve_id=args.cve_id,
        run_id=args.run_id,
        provider=args.provider,
        model=args.model,
        runtime_policy=root / "runtime-policy.json",
        research_policy=root / "research-policy.json",
        oracle=root / "oracles" / f"{args.cve_id}.json",
        pi_models=root / "pi-models.json",
        pi_auth=root / "pi-auth.json",
        timeout_seconds=args.timeout,
        target_policy=root / "targets" / f"{args.cve_id}.json",
    )
    deps = AgentDependencies(
        expected_root_uid=os.getuid(),
        harness_factory=DevStageHarness,
        executor_factory=_dev_executor_factory,
        require_rootless_docker=False,
    )
    result = run_agent(config, deps)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"[dev-agent-run] status={result.get('status')} run={result.get('run_id')}")
        for key in ("ledger", "public", "export_manifest"):
            entry = result.get(key) or {}
            print(f"  {key}: {entry.get('path')} sha256={str(entry.get('sha256'))[:16]}…")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
