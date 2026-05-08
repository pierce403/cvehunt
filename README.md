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
npm run build
./contribute.sh CVE-2025-55182
```

## Safety Boundary

PoC artifacts in this repository are scoped to the local CVEHunt harness only:

- Service ports are bound to `127.0.0.1` exclusively in the generated `harness/docker-compose.yml`.
- Generated PoC scripts hardcode `http://127.0.0.1:4000` (vulnerable) and `http://127.0.0.1:4001` (patched). There is no environment override.
- `SafetyPolicy.assert_localhost_scoped` rejects any PoC content that would reach a non-loopback host.
- The pipeline does not exfiltrate credentials, target real third-party deployments, or fetch weaponized public exploit code.

The PoC validates the harness, not real services. See `ISOLATION.md` for the target-environment policy: Docker is the current implemented userland harness backend, while kernel, Kubernetes escape, container escape, browser, and runtime-boundary CVEs should use disposable VM or microVM backends such as QEMU/KVM, Firecracker, Cloud Hypervisor, or Kata Containers when those backends are implemented.

## Current Pipeline

- `CollectorAgent`: loads CVE metadata from fixtures.
- `ResearcherAgent`: extracts defensive hypotheses, downloads supported package releases (npm and pypi), and writes a real source diff.
- `HarnessBuilderAgent`: generates Dockerfiles plus a localhost-only `docker-compose.yml` for the vulnerable and patched variants.
- `ExploiterAgent`: emits a localhost-scoped PoC (`exploiter/poc.py`) and orchestration runner (`exploiter/run-poc.sh`) keyed on the inferred vulnerability class.
- `FixDeveloperAgent`: promotes the upstream vulnerable→patched diff as `fix/candidate.patch` with a rationale.
- `ValidatorAgent`: records evidence for source acquisition, diff capture, harness generation, PoC scaffolding, and candidate fix.
- `JudgeAgent`: assigns a status, confidence, and remediation notes.

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

Every persisted run receives a run score out of 100. A score of 100 means the workflow produced a working PoC against the vulnerable target, produced a candidate patch, and proved the patch blocks the same PoC. Partial runs receive lower scores based on source acquisition, harness setup, PoC generation/execution, patch generation, and fix validation.

The public site is a React/Vite app generated into `docs/` for GitHub Pages:

```bash
npm run build
```

The build reads `cves/`, emits `web/public/data/cves.json`, and exposes both the latest CVE state and an all-runs leaderboard sorted by run score before bundling the site. GitHub Actions runs the same build and deploys Pages on commits to `main`.

## Example

```bash
uv run cvehunt run CVE-2025-55182 --model codex:gpt-5.5
```

The command prints a markdown report with the pipeline outcome, real source/harness artifacts for supported ecosystems, generated localhost PoC artifacts, and explicit notes about any unimplemented validation stages.

For an interactive contributor run, use `./contribute.sh`. It detects installed agent harness CLIs (`codex`, `gemini`, `claude`, `opencode`, or `pi`), validates model names when the harness exposes a local catalog, runs an isolation preflight (`CVEHUNT_ISOLATION_BACKEND=docker` by default), syncs missing project dependencies when prompted, runs a persisted CVEHunt workflow with local harness execution enabled by default, invokes supported model CLIs afterward, extracts safety-checked model-authored artifacts into `model_attempt/`, writes `contribution_audit.{json,md}` plus interaction/output/isolation logs into the run directory, and rebuilds the dashboard data. Environment overrides are also available as flags, for example `./contribute.sh --cve CVE-2025-55182 --harness codex --model gpt-5.5 --dry-run`.
