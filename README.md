# CVEHunt

CVEHunt is a defensive proof-of-concept for an agentic CVE exploitability workflow. It borrows the orchestration shape of systems like MOAK while keeping exploit work scoped to authorized localhost harnesses and remediation proof.

The goal is to model a repository-backed defensive workflow:

1. Collect CVE context.
2. Download supported vulnerable and patched package releases and inspect their diff.
3. Generate an isolated harness scaffold for vulnerable and patched variants.
4. Generate and optionally execute localhost-scoped PoC checks against the harness.
5. Record what evidence was actually captured and where the pipeline stops.
6. Judge exploitability and remediation urgency from the collected artifacts.

## Quick Start

```bash
uv sync --dev
uv run cvehunt run CVE-2025-55182 --model codex:gpt-5.5
uv run cvehunt run CVE-2025-55182 --json
uv run cvehunt run CVE-2025-55182 --persist --model codex:gpt-5.5
uv run cvehunt sync-recent --days 7 --limit 25
uv run cvehunt serve
uv run python -m pytest
pnpm run build
./contribute.sh CVE-2025-55182
```

## Safety Boundary

PoC artifacts in this repository are scoped to the local CVEHunt harness only:

- Service ports are bound to `127.0.0.1` exclusively in the generated `harness/docker-compose.yml`.
- Generated PoC scripts hardcode `http://127.0.0.1:4000` (vulnerable) and `http://127.0.0.1:4001` (patched). There is no environment override.
- `SafetyPolicy.assert_localhost_scoped` rejects any PoC content that would reach a non-loopback host.
- The pipeline does not exfiltrate credentials, target real third-party deployments, or fetch weaponized public exploit code.

The PoC validates the harness, not real services. See `ISOLATION.md` for the target-environment policy: Docker is one backend for userland service CVEs, while kernel, Kubernetes escape, container escape, browser, Windows driver, firmware, and runtime-boundary CVEs default to a QEMU-oriented setup contract. If required media is unavailable, the run records `blocked_needs_artifact` and asks for exact files instead of inventing deployment steps.

## Current Pipeline

The pipeline is an adversarial exploit/defend loop. Artifacts existing are not evidence; only observed behavior counts.

- `CollectorAgent`: loads CVE metadata from fixtures.
- `ResearcherAgent`: derives defensive hypotheses, downloads supported package releases (npm and pypi), writes a real source diff when possible, and otherwise records required target artifacts.
- `HarnessBuilderAgent`: generates Dockerfiles plus a localhost-only `docker-compose.yml` for Docker-safe vulnerable/patched variants, or emits a backend-agnostic `harness/target-environment.json`, `harness/SETUP.md`, and `harness/run-targets.sh` contract for QEMU/manual-artifact targets.
- `ProvisionAgent` (with `--execute-poc`): builds and starts the harness, health-checks each target, and records per-target `servable`/`not_servable` in `provision/provision.json`. The vulnerable surface must be servable before exploit development proceeds.
- `ExploiterAgent`: emits a localhost-scoped PoC (`exploiter/poc.py`) and runner (`exploiter/run-poc.sh`) keyed on the inferred vulnerability class.
- `HarnessRunnerAgent` (with `--execute-poc`): runs the orchestrator and tees `exploiter/outcome.json`.
- `AdversarialLoopAgent` (with `--execute-poc`): runs bounded exploit rounds (try to reproduce the CVE escalation), defense rounds (apply the fix, restart the patched target, re-run the exploit), and residual rounds (try to re-escalate against the patched target). Each round is logged to `negotiation/*.ndjson` and a `negotiation/verdict.json` records `escalation_achieved`, `patch_effective`, `residual_bypass`.
- `FixDeveloperAgent`: promotes the upstream vulnerable→patched diff as `fix/candidate.patch`, applies it to a copied vulnerable source tree, and validates the result against upstream patched files.
- `ValidatorAgent`: records evidence for source acquisition, diff capture, harness/provision health, PoC execution outcomes, and candidate fix. The differential check only passes when a real vulnerable/patched behavioral differential was observed — not from fixture strings.
- `JudgeAgent`: assigns a status and confidence. A run is `defensive_signal_observed` (≥0.90) only when the vulnerable target was escalated, the patched target blocked the same behavior, and no residual bypass was found. With no behavioral outcome the verdict is `needs_human_review` (≤0.50) and is explicitly NOT a defensive signal — even if a harness and fix were scaffolded.

## Dashboard And Workdirs

CVEHunt stores CVE workdirs under the repository-level `cves/` directory by default:

```text
cves/
  CVE-2025-55182/
    cve.json
    runs/
      2026-04-28T14-39-50Z/
        cve.json
        sources/
        research/
        harness/
        exploiter/
        trace.jsonl
        pipeline_status.json
        report.json
        report.md
```

Use `sync-recent` to pull recent CVE metadata from NVD. Run it without `--run` when new CVEs should appear as not analyzed:

```bash
uv run cvehunt sync-recent --days 7 --limit 25
```

Each CVE directory is intended to become the durable working directory for that CVE. The initial implementation writes structured metadata, a full phase trace, and report artifacts.
Persisted runs are written to timestamped `runs/<RUN-ID>/` directories. Root-level report artifacts should only be promoted into `cves/<CVE-ID>/` after a fully successful end-to-end run.

Every persisted run receives a run score out of 100. A score of 100 means the workflow produced a working PoC against the vulnerable target, produced a candidate patch, and proved the patch blocks the same PoC. Partial runs receive lower scores based on source acquisition, harness setup, PoC generation/execution, patch generation, and fix validation. Note: a high score alone (e.g. 70 for a scaffolded-and-diffed run) is NOT the same as `defensive_signal_observed` — the verdict string and confidence are driven by actually observed behavior, not by artifact existence.

The public site is a React/Vite app generated into `docs/` for GitHub Pages:

```bash
pnpm run build
```

The build reads `cves/`, emits `web/public/data/cves.json`, and exposes both the latest CVE state and an all-runs leaderboard sorted by run score before bundling the site. GitHub Actions runs the same build and deploys Pages on commits to `main`.

## Example

```bash
uv run cvehunt run CVE-2025-55182 --model codex:gpt-5.5
```

The command prints a markdown report with the pipeline outcome, source/harness artifacts for supported ecosystems, generated localhost PoC artifacts, and explicit notes about any unimplemented validation stages. Target-specific instrumentation is not baked into repo code; real target setup must be supplied as run-local agent artifacts. Use `--base-port <port>` if the default local ports 4000/4001 are already occupied.

For an interactive contributor run, use `./contribute.sh`. It detects installed agent harness CLIs (`codex`, `gemini`, `claude`, `opencode`, or `pi`), validates model names when the harness exposes a local catalog, runs an isolation preflight (`CVEHUNT_ISOLATION_BACKEND=docker` by default), syncs missing project dependencies when prompted, runs a persisted CVEHunt workflow with local harness execution enabled by default, invokes supported model CLIs afterward, extracts safety-checked model-authored artifacts into `model_attempt/` including optional `target_plan.json` / `target_setup.md`, writes `contribution_audit.{json,md}` plus interaction/output/isolation logs into the run directory, and rebuilds the dashboard data. Environment overrides are also available as flags, for example `./contribute.sh --cve CVE-2025-55182 --harness codex --model gpt-5.5 --dry-run`.
