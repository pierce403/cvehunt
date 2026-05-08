# CVEHunt - Features

This file follows the `FEATURES.md` format described at [features.md](https://features.md/): each feature has a stability level, a short description, testable properties, and test criteria. Feature wording should distinguish implemented behavior from scaffolded or planned behavior.

## Current Implementation Boundary

CVEHunt's core Python workflow is deterministic. `./contribute.sh` now invokes supported selected model CLIs after persistence as read-only bounded evaluators and stores the prompt/transcript/response under `model_attempt/`; those external model calls do not directly modify files or replace the deterministic pipeline stages.

By default, `uv run cvehunt run` generates artifacts only and requires `--execute-poc` for Docker execution. By default, `./contribute.sh` enables Docker/Compose target harness execution and external model evaluation; use `--skip-execute-poc` / `CVEHUNT_EXECUTE_POC=0` and `--skip-model` / `CVEHUNT_SKIP_MODEL=1` to opt out.

A run score of 100 means: metadata was collected, vulnerable/patched sources were diffed, an isolated harness was generated, a harness-scoped PoC was generated, the PoC triggered the vulnerable target, the patched target blocked the same PoC, a candidate fix was generated, and that candidate fix was validated. Current normal scaffold-only runs do not reach 100.

## Features

### CVE Metadata Collection
- **Stability**: stable
- **Description**: Load tracked CVEs from local fixtures and persisted workdirs so every run starts from structured metadata.
- **Implemented**:
  - `cvehunt run <CVE-ID>` resolves fixture-backed CVE metadata for supported CVEs.
  - Unknown CVEs return a structured unsupported/insufficient-evidence result instead of failing implicitly.
  - `cves/<CVE-ID>/cve.json` is the durable metadata entrypoint for tracked CVEs.
  - `sync-recent` can fetch recent NVD records and optionally run the pipeline.
- **Not Implemented**:
  - Complete automated test coverage for `sync-recent` network behavior.
- **Test Criteria**:
  - [x] Known fixture run returns metadata for `CVE-2025-55182`.
  - [x] Unknown CVE returns a structured non-success result.
  - [ ] `sync-recent` coverage is exercised in automated tests.

### Timestamped Run Archiving
- **Stability**: stable
- **Description**: Persist every run into a timestamped CVE workdir so traces and reports can be audited independently.
- **Implemented**:
  - Persisted runs land in `cves/<CVE-ID>/runs/<RUN-ID>/`.
  - Each run writes `cve.json`, `trace.jsonl`, `pipeline_status.json`, `report.json`, and `report.md`.
  - Root-level artifacts under `cves/<CVE-ID>/` are reserved for fully successful end-to-end runs.
  - `pipeline_status.json` and `report.md` include `run_score` details.
- **Not Implemented**:
  - Automatic promotion of a fully successful run to root-level CVE artifacts.
- **Test Criteria**:
  - [x] Persisted test run writes the expected artifact set.
  - [x] Incomplete runs are not promoted into `cves/<CVE-ID>/report.json`.
  - [x] Run IDs use filename-safe ISO timestamps.
  - [x] Persisted status includes a run score.

### Run Scoring
- **Stability**: stable
- **Description**: Score how far a run progressed toward a complete exploitability and remediation proof.
- **Implemented**:
  - Scores are calculated centrally by `calculate_run_score(report)`.
  - Score components total 100 points:
    - metadata collected: 5
    - source diff captured: 15
    - isolated harness generated: 15
    - PoC generated: 10
    - PoC triggers vulnerable target: 20
    - patched target blocks PoC: 10
    - candidate fix generated: 10
    - candidate fix validated: 15
  - Scores are written to `pipeline_status.json`, `report.md`, dashboard latest-CVE rows, and dashboard historical run rows.
  - Historical runs without embedded scores are scored during site-data generation from their report artifacts.
- **Not Implemented**:
  - A current deterministic run normally cannot earn candidate-fix-validation points because fix validation is not implemented.
- **Test Criteria**:
  - [x] Persisted test run includes the expected partial score.
  - [x] Markdown reports include a run-score checklist.
  - [x] Dashboard data includes scored historical runs.

### npm and PyPI Source Acquisition
- **Stability**: in-progress
- **Description**: For supported package CVEs, download vulnerable and patched package releases, extract them locally, and record a source diff.
- **Implemented**:
  - `ResearcherAgent` downloads published npm tarballs for supported npm package/version pairs.
  - `ResearcherAgent` downloads PyPI source distributions for supported single-version PyPI package/version pairs.
  - Extracted package trees are stored under `sources/`.
  - A unified diff is written to `research/source_diff.patch`.
  - Reports capture changed files, tarball URLs, tarball SHA-256 hashes, package roots, and strongest observed patch signal.
- **Not Implemented**:
  - Ecosystems beyond npm and PyPI.
  - PyPI version ranges; PyPI entries must resolve to a single version.
  - Hermetic/offline package acquisition without registry access.
- **Test Criteria**:
  - [x] Local test doubles verify the source artifact layout and diff path.
  - [x] Manual run for `CVE-2025-55182` downloads `react-server-dom-webpack 19.0.0` and `19.0.1`.
  - [x] Manual run for `CVE-2025-55182` records a patch signal around `Object.prototype.hasOwnProperty`.
  - [ ] Additional ecosystems beyond npm/PyPI are supported.

### Harness Scaffolding
- **Stability**: in-progress
- **Description**: Generate local vulnerable and patched target environment scaffolding from acquired sources.
- **Implemented**:
  - `HarnessBuilderAgent` writes `harness/Dockerfile.vulnerable` and `harness/Dockerfile.patched`.
  - `harness/docker-compose.yml` binds services to `127.0.0.1` only.
  - `harness/build-images.sh` is created for local image builds.
  - `harness/README.md` summarizes package/version/source details and captured patch signal.
  - The harness stage is reflected in `pipeline_status.json` and `report.md`.
- **Not Implemented**:
  - Docker image build/run by default in the raw `uv run cvehunt run` CLI. Execution there requires `--execute-poc`.
  - VM or microVM execution backends for kernel, container escape, Kubernetes escape, browser/client, or other non-userland-package CVEs.
  - Guaranteed hermetic builds; package manager operations during Docker build may still need network access unless supplied by the operator.
- **Test Criteria**:
  - [x] Persisted test run writes harness artifacts.
  - [x] Manual run for `CVE-2025-55182` writes Dockerfiles and helper scripts.
  - [x] Compose port bindings are localhost-only.
  - [ ] Firecracker/QEMU/external VM execution backends are implemented.

### Local Harness Execution
- **Stability**: in-progress
- **Description**: Build and run the generated localhost Docker/Compose harness and execute the generated PoC.
- **Implemented**:
  - `uv run cvehunt run <CVE-ID> --persist --json --execute-poc` opts into harness execution for the raw CLI.
  - `./contribute.sh` enables harness execution by default and passes `--execute-poc` unless `--skip-execute-poc` or `CVEHUNT_EXECUTE_POC=0` is set.
  - `HarnessRunnerAgent` invokes only generated local scripts and parses `exploiter/outcome.json` when present.
  - Docker availability is checked before execution.
  - PoC targets are hardcoded to loopback ports.
- **Not Implemented**:
  - Non-Docker execution backends are not implemented.
  - The runner does not apply and re-test a candidate fix beyond the upstream patched container.
- **Test Criteria**:
  - [x] CLI exposes `--execute-poc`.
  - [x] Contributor wrapper exposes default execution plus `--skip-execute-poc` and `CVEHUNT_EXECUTE_POC=0` opt-out.
  - [ ] Automated tests build and run Docker harnesses in CI.

### Harness-Scoped PoC Generation
- **Stability**: in-progress
- **Description**: Generate localhost-scoped PoC artifacts for supported vulnerability classes and controlled harnesses.
- **Implemented**:
  - `ExploiterAgent` writes `exploiter/poc.py` and `exploiter/run-poc.sh` when a supported template exists.
  - Supported template classes currently include SQL injection, unsafe deserialization, and unsafe interpolation.
  - Generated PoCs hardcode `127.0.0.1:4000` for vulnerable and `127.0.0.1:4001` for patched targets.
  - `SafetyPolicy.assert_localhost_scoped` rejects non-loopback PoC target URLs before artifacts are written.
  - Unsupported vulnerability classes receive an explicit `exploiter/README.md` stub instead of a PoC.
- **Not Implemented**:
  - Model-authored PoC generation.
  - General-purpose exploit development.
  - PoCs targeting real third-party systems.
  - Full vulnerable/patched outcome proof unless `--execute-poc` is used and the harness produces structured outcomes.
- **Test Criteria**:
  - [x] Current pipeline writes PoC artifacts for supported classes.
  - [x] Safety tests block non-localhost PoC targeting and unsafe phrases.
  - [ ] Model-authored PoC attempts are captured as separate audited artifacts.

### Candidate Fix Generation
- **Stability**: in-progress
- **Description**: Preserve a candidate remediation artifact for comparison and future validation.
- **Implemented**:
  - `FixDeveloperAgent` promotes the upstream vulnerable-to-patched source diff to `fix/candidate.patch`.
  - `fix/rationale.md` records why the observed patch signal is relevant.
  - Fix generation status is reflected in reports, pipeline status, evidence, and run score.
- **Not Implemented**:
  - Model-authored patch generation.
  - Applying the candidate patch to a local vulnerable tree.
  - Building a newly fixed target from the candidate patch.
  - Re-running the PoC against that newly fixed target.
  - Marking a fix as `validated` in the current deterministic workflow.
- **Test Criteria**:
  - [x] Candidate fix artifacts are generated when a source diff exists.
  - [x] Persisted test run writes `fix/candidate.patch`.
  - [ ] Fix validation results are recorded after applying and testing a candidate fix.

### Validation and Judgement
- **Stability**: in-progress
- **Description**: Convert collected artifacts into evidence and an explainable assessment.
- **Implemented**:
  - Validator records evidence for source acquisition, patch diff capture, harness scaffolding, PoC generation, PoC execution outcomes when present, and candidate fix generation.
  - Judge emits an overall status and confidence based on available evidence.
  - Unsupported ecosystems without fixture coverage end as insufficient evidence instead of silently passing.
- **Not Implemented**:
  - Independent semantic proof that the candidate fix is sufficient.
  - Full end-to-end remediation validation in a patched-from-candidate environment.
  - Human review workflows.
- **Test Criteria**:
  - [x] Tests verify unsupported ecosystem fallback behavior.
  - [x] Reports include evidence and judgement fields.
  - [ ] Candidate fix validation evidence is produced by an applied-patch run.

### Target Environment Reporting
- **Stability**: stable
- **Description**: Include detailed target setup/version information in final reports.
- **Implemented**:
  - `report.md` includes CVE, ecosystem, vulnerable/patched versions, harness runtime, isolation notes, package name, source roots, tarball SHA-256 values, PoC target URLs, and captured PoC outcomes when present.
  - `report.json` preserves the underlying structured source, harness, exploiter, fix, evidence, and judgement fields.
- **Not Implemented**:
  - Automatic capture of host kernel, Docker daemon, image digests, or guest VM image IDs in `report.md`.
- **Test Criteria**:
  - [x] Persisted report tests assert target environment fields are present.
  - [ ] Executed harness reports include immutable image digests.

### Contributor Wrapper
- **Stability**: in-progress
- **Description**: Provide an interactive or flag-driven contributor loop around persisted CVEHunt runs.
- **Implemented**:
  - `./contribute.sh <CVE-ID>` still works.
  - Every documented `CVEHUNT_*` override has an equivalent flag: `--cve`, `--harness`, `--model`, `--skip-install`, `--skip-build`, `--skip-git`, `--dry-run`, `--execute-poc`, `--skip-execute-poc`, `--skip-model`, `--model-timeout`, and `--isolation-backend`.
  - Flags override environment variables.
  - Harness CLIs are detected from `codex`, `gemini`, `claude`, `opencode`, and `pi`.
  - Codex and Pi model names are validated against local catalogs when available.
  - Contributor runs write `model_attempt/`, `contribution_audit.{json,md}`, `contribution-interaction.log`, `contribute-output.log`, and `isolation-preflight.log`.
  - The wrapper prints a run plan that states whether external model invocation and target execution are enabled.
- **Not Implemented**:
  - Shell-script behavior is not covered by a dedicated automated test harness.
  - The wrapper invokes supported models as read-only reviewers, but does not let them directly author or modify repository files.
- **Test Criteria**:
  - [x] Manual dry-run verifies flag parsing for `--cve`, `--harness`, `--model`, and boolean flags.
  - [x] `bash -n contribute.sh` passes.
  - [ ] Dedicated shell tests cover parser edge cases in CI.

### Model Evaluation and Run Comparison
- **Stability**: in-progress
- **Description**: Record which harness/model label was associated with each run and invoke supported selected models as bounded read-only evaluators.
- **Implemented**:
  - `Run ID` and `Model` are written into `report.json`, `report.md`, and `pipeline_status.json`.
  - `./contribute.sh` records attribution as `<harness>:<model>`.
  - Supported external evaluation harnesses currently include `pi`, `codex`, `gemini`, and best-effort `claude`.
  - External model evaluation stores `model_attempt/prompt.md`, `transcript.txt`, `stderr.txt`, `response.md`, `command.txt`, and `metadata.json`.
  - `contribution_audit.md` records external model invocation status and artifacts.
  - The dashboard shows model metadata for latest CVE rows and historical run rows.
- **Not Implemented**:
  - Model-authored exploit or patch files that are automatically applied to the run.
  - Direct file modifications by the external model invocation.
  - Scoring of model response quality beyond persisted metadata.
- **Test Criteria**:
  - [x] Automated tests verify the report includes the model label.
  - [x] The dashboard shows model metadata for analyzed CVEs.
  - [x] Manual smoke run verified `model_attempt/` artifacts are written for Pi invocation, including timeout metadata.
  - [ ] Model-authored attempt artifacts are parsed and scored.

### Repository-Backed Dashboard
- **Stability**: stable
- **Description**: Publish a React dashboard that links each CVE and run artifact back to the GitHub repository.
- **Implemented**:
  - Dashboard data is generated from `cves/` by `scripts/generate_site_data.py`.
  - Each latest-CVE row links to its detail view and repository workdir.
  - Detail pages show phase-level status, run metadata, report content, run score, and artifact links.
  - An all-runs leaderboard lists persisted runs sorted by run score and links to selectable historical run detail pages.
  - GitHub Pages output is built into `docs/`.
- **Not Implemented**:
  - Side-by-side diff UI between two selected runs.
  - Client-side filtering by model, score range, or CVE status.
- **Test Criteria**:
  - [x] `npm run build` regenerates `web/public/data/cves.json` and `docs/`.
  - [x] Dashboard tests cover tracked CVE rendering and repository URL generation.
  - [x] Phase-level state is read from `pipeline_status.json`.
  - [x] Generated site data includes historical runs and run scores.

### Isolation Backend Policy and Preflight
- **Stability**: in-progress
- **Description**: Make target-isolation expectations explicit before contributor runs.
- **Implemented**:
  - `ISOLATION.md` documents which target classes require Docker, external VMs, QEMU/KVM, Firecracker, or other VM-backed isolation.
  - `./contribute.sh` supports `--isolation-backend docker|external-vm|firecracker|qemu` and `CVEHUNT_ISOLATION_BACKEND`.
  - Docker preflight checks Docker CLI/server availability.
  - Firecracker and QEMU preflights check expected dependencies and fail early because execution is not implemented.
  - Every contributor run writes `isolation-preflight.log`.
- **Not Implemented**:
  - Firecracker, QEMU, Cloud Hypervisor, Kubernetes VM-node, browser/client VM, or snapshot/rollback execution.
  - Enforcement that Docker runs happen inside a disposable VM for container-runtime-adjacent targets.
- **Test Criteria**:
  - [x] Manual preflight confirms Docker status is recorded.
  - [x] Manual preflight confirms Firecracker/QEMU fail early when selected.
  - [ ] VM/microVM execution backends build and run real targets.

## Planned Work

### Model-Authored Artifact Stage
- **Stability**: planned
- **Description**: Allow the selected model/harness to propose bounded, harness-scoped artifacts that CVEHunt can safety-check, persist, and optionally apply in a controlled workspace.
- **Planned Properties**:
  - Parse model responses into structured states such as `refused`, `unsafe_blocked`, `partial`, `poc_generated`, `patch_generated`, and `validated`.
  - Store proposed model-authored files under paths such as `model_attempt/poc.py`, `model_attempt/fix.patch`, `model_attempt/notes.md`, or `model_attempt/refusal.md`.
  - Safety-check model-authored artifacts before they can affect the run or score.
- **Test Criteria**:
  - [x] Selected supported model harnesses are invoked read-only by `./contribute.sh`.
  - [ ] Model-authored artifacts are safety-checked and persisted as structured files.
  - [ ] Refusals and unsafe outputs are explicitly classified.

### Candidate Fix Revalidation
- **Stability**: planned
- **Description**: Apply a candidate fix, rebuild a fixed target, rerun the same PoC, and prove the fix blocks the vulnerable behavior.
- **Planned Properties**:
  - Revalidation compares vulnerable, upstream patched, and candidate-fixed outcomes.
  - Successful end-to-end runs are promotable to the CVE root.
  - Run score can reach 100 only after this proof exists.
- **Test Criteria**:
  - [ ] Candidate fix is applied to a local vulnerable tree.
  - [ ] Fixed target is built and tested.
  - [ ] Fix validation result is recorded in `pipeline_status.json` and `report.md`.
