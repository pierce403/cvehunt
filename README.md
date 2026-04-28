# OpenMOAK

OpenMOAK is a safe proof-of-concept for an agentic CVE exploitability workflow. It borrows the orchestration shape of systems like MOAK without generating exploit code, payloads, or operational attack steps.

The goal is to model a defensive workflow:

1. Collect CVE context.
2. Research high-level vulnerability traits.
3. Plan an isolated validation environment.
4. Collect synthetic evidence.
5. Judge exploitability and remediation urgency.

## Quick Start

```bash
uv sync --dev
uv run openmoak run CVE-2025-55182
uv run openmoak run CVE-2025-55182 --json
uv run pytest
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

## Example

```bash
uv run openmoak run CVE-2025-55182
```

The command prints a markdown report with the pipeline outcome and defensive recommendations.

