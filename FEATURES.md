# CVEHunt - Features

This file follows the `FEATURES.md` format described at [features.md](https://features.md/): each feature has a stability level, a short description, testable properties, and test criteria.

## Features

### CVE Metadata Collection
- **Stability**: stable
- **Description**: Load tracked CVEs from local fixtures and persisted workdirs so every run starts from structured metadata.
- **Properties**:
  - `cvehunt run <CVE-ID>` resolves fixture-backed CVE metadata for supported CVEs
  - Unknown CVEs return a structured `not_supported` result instead of failing implicitly
  - `cves/<CVE-ID>/cve.json` is the durable metadata entrypoint for tracked CVEs
- **Test Criteria**:
  - [x] Known fixture run returns metadata for `CVE-2025-55182`
  - [x] Unknown CVE returns `not_supported`
  - [ ] `sync-recent` coverage is exercised in automated tests

### Timestamped Run Archiving
- **Stability**: stable
- **Description**: Persist every autonomous run into a timestamped CVE workdir so traces and reports can be audited independently.
- **Properties**:
  - Persisted runs land in `cves/<CVE-ID>/runs/<RUN-ID>/`
  - Each run writes `cve.json`, `trace.jsonl`, `pipeline_status.json`, `report.json`, and `report.md`
  - Root-level artifacts under `cves/<CVE-ID>/` are reserved for fully successful end-to-end runs
- **Test Criteria**:
  - [x] Persisted test run writes the expected artifact set
  - [x] Incomplete runs are not promoted into `cves/<CVE-ID>/report.json`
  - [x] Run IDs use filename-safe ISO timestamps

### Supported npm Source Acquisition
- **Stability**: in-progress
- **Description**: For supported npm CVEs, download the vulnerable and patched package releases, extract them locally, and record a real source diff.
- **Properties**:
  - `ResearcherAgent` downloads published npm tarballs for the vulnerable and patched versions
  - Extracted package trees are stored under `sources/`
  - A unified diff is written to `research/source_diff.patch`
  - The report captures changed files and the strongest observed patch signal
- **Test Criteria**:
  - [x] Local test doubles verify the source artifact layout and diff path
  - [x] Manual run for `CVE-2025-55182` downloads `react-server-dom-webpack 19.0.0` and `19.0.1`
  - [x] Manual run for `CVE-2025-55182` records a patch signal around `Object.prototype.hasOwnProperty`
  - [ ] Additional ecosystems beyond npm are supported

### Harness Scaffolding
- **Stability**: in-progress
- **Description**: Generate isolated vulnerable and patched environment scaffolding from the acquired sources.
- **Properties**:
  - `HarnessBuilderAgent` writes `harness/Dockerfile.vulnerable` and `harness/Dockerfile.patched`
  - `harness/build-images.sh` is created for local image builds
  - `harness/README.md` summarizes the package pair and captured patch signal
  - The harness stage is reflected in `pipeline_status.json`
- **Test Criteria**:
  - [x] Persisted test run writes harness artifacts
  - [x] Manual run for `CVE-2025-55182` writes Dockerfiles and helper scripts
  - [ ] Images are built and validated automatically during the pipeline

### Repository-Backed Dashboard
- **Stability**: stable
- **Description**: Publish a React dashboard that links each CVE and run artifact back to the GitHub repository.
- **Properties**:
  - Dashboard data is generated from `cves/`
  - Each CVE row links to its detail view and repository workdir
  - Detail pages show phase-level status, latest run metadata, report content, and artifact links
  - GitHub Pages output is built into `docs/`
- **Test Criteria**:
  - [x] `npm run build` regenerates `web/public/data/cves.json` and `docs/`
  - [x] Dashboard tests cover tracked CVE rendering and repository URL generation
  - [x] Phase-level state is read from `pipeline_status.json`

### Model Attribution And Run Comparison
- **Stability**: in-progress
- **Description**: Record which model produced each run so contributors can compare how far different models get on the same CVE.
- **Properties**:
  - `Run ID` and `Model` are written into `report.json`, `report.md`, and `pipeline_status.json`
  - The dashboard surfaces the latest run ID and model label per CVE
  - Contributors can supply `--model <label>` or `CVEHUNT_MODEL`
- **Test Criteria**:
  - [x] Automated tests verify the report includes the model label
  - [x] The dashboard shows model metadata for analyzed CVEs
  - [ ] The site exposes side-by-side comparisons across multiple runs for the same CVE

### Harness-Scoped PoC Developer
- **Stability**: planned
- **Description**: Evolve the current Exploiter stub into a harness-scoped PoC stage that can prove exploitability inside controlled evaluation environments.
- **Properties**:
  - PoC generation is constrained to isolated vulnerable/patched harnesses
  - The stage emits durable traces and outcome artifacts
  - The stage does not target real third-party systems
- **Test Criteria**:
  - [x] Current pipeline writes an explicit `exploiter/README.md` stub
  - [ ] A real harness-scoped PoC stage is implemented
  - [ ] Vulnerable and patched harness outcomes are captured automatically

### Fix Generation And Revalidation
- **Stability**: planned
- **Description**: Generate or apply a candidate fix, rerun validation, and prove the fix blocks the same behavior seen in the vulnerable harness.
- **Properties**:
  - Fix artifacts are stored alongside the run
  - Revalidation compares vulnerable, patched, and fixed outcomes
  - Successful end-to-end runs are promotable to the CVE root
- **Test Criteria**:
  - [ ] Candidate fix artifacts are generated
  - [ ] Fix validation results are recorded in `pipeline_status.json`
  - [ ] Root-level promotion happens only after a fully successful end-to-end run
