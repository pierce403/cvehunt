# CVEHunt

CVEHunt is a safe proof-of-concept for an agentic CVE exploitability workflow. It borrows the orchestration shape of systems like MOAK without generating exploit code, payloads, or operational attack steps.

The goal is to model a defensive workflow:

1. Collect CVE context.
2. Research high-level vulnerability traits.
3. Plan an isolated validation environment.
4. Collect synthetic evidence.
5. Judge exploitability and remediation urgency.

## Quick Start

```bash
uv sync --dev
uv run cvehunt run CVE-2025-55182 --model gpt-5.5-cyber
uv run cvehunt run CVE-2025-55182 --json
uv run cvehunt run CVE-2025-55182 --persist --model gpt-5.5-cyber
uv run cvehunt sync-recent --days 7 --limit 25
uv run cvehunt serve
uv run python -m pytest
npm run build
```

## Safety Boundary

This repository is intentionally defensive. The PoC does not:

- Generate exploit scripts
- Produce payloads
- Fetch public PoCs
- Provide bypass instructions
- Execute against real targets

Instead, it uses local fixtures and synthetic validation checks to demonstrate how an agent pipeline can capture structured evidence and produce an explainable assessment.

## Current Pipeline

- `CollectorAgent`: loads CVE metadata from fixtures.
- `ResearcherAgent`: extracts defensive hypotheses and impacted surfaces.
- `EnvironmentPlannerAgent`: creates a safe validation plan.
- `ValidatorAgent`: simulates vulnerable/patched evidence from fixtures.
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

The public site is a React/Vite app generated into `docs/` for GitHub Pages:

```bash
npm run build
```

The build reads `cves/` and emits `web/public/data/cves.json` before bundling the site. GitHub Actions runs the same build and deploys Pages on commits to `main`.

## Example

```bash
uv run cvehunt run CVE-2025-55182 --model gpt-5.5-cyber
```

The command prints a markdown report with the pipeline outcome and defensive recommendations.
