from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from cvehunt.dashboard import serve_dashboard, write_dashboard
from cvehunt.models import utc_run_id
from cvehunt.nvd import fetch_recent_cves
from cvehunt.reporting import render_markdown
from cvehunt.storage import WorkdirStore
from cvehunt.workflow import CveHuntWorkflow


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cvehunt")
    parser.add_argument("--data-dir", default=".", help="Local data/workdir root")
    subcommands = parser.add_subparsers(dest="command", required=True)

    run = subcommands.add_parser("run", help="Run the defensive workflow for a CVE")
    run.add_argument("cve_id", help="CVE identifier, for example CVE-2025-55182")
    run.add_argument("--json", action="store_true", help="Emit structured JSON")
    run.add_argument("--persist", action="store_true", help="Write report and trace to data dir")
    run.add_argument(
        "--run-id",
        default=None,
        help="Run directory id to use under cves/<CVE>/runs; defaults to current UTC time.",
    )
    run.add_argument(
        "--model",
        default=None,
        help="Model label for this run, defaults to CVEHUNT_MODEL or unspecified",
    )
    run.add_argument(
        "--base-port",
        type=int,
        default=int(os.environ.get("CVEHUNT_BASE_PORT", "4000")),
        help="Base localhost port for vulnerable/patched harness targets; patched uses base+1.",
    )
    run.add_argument(
        "--execute-poc",
        action="store_true",
        help=(
            "Build the harness images, bring up the compose stack, and run the "
            "PoC against the local containers. Requires Docker."
        ),
    )
    run.add_argument(
        "--residual-rounds",
        type=int,
        default=int(os.environ.get("CVEHUNT_RESIDUAL_ROUNDS", "0")),
        help=(
            "When --execute-poc is set, run this many residual/variant exploit "
            "rounds against a freshly-started patched target to check the fix "
            "holds under bounded adversarial probing. 0 disables residual (fast "
            "default). Defaults to CVEHUNT_RESIDUAL_ROUNDS or 0."
        ),
    )

    sync = subcommands.add_parser("sync-recent", help="Fetch recent CVEs from NVD")
    sync.add_argument("--days", type=int, default=7, help="Publication lookback window")
    sync.add_argument("--limit", type=int, default=50, help="Maximum CVEs to fetch")
    sync.add_argument("--run", action="store_true", help="Run the pipeline for fetched CVEs")
    sync.add_argument(
        "--model",
        default=None,
        help="Model label for persisted sync runs, defaults to CVEHUNT_MODEL or unspecified",
    )

    dashboard = subcommands.add_parser("dashboard", help="Write a static dashboard HTML file")
    dashboard.add_argument(
        "--out",
        default=None,
        help="Output HTML path, defaults to DATA_DIR/dashboard.html",
    )
    dashboard.add_argument(
        "--repo-url",
        default=None,
        help="GitHub repository URL used for artifact links",
    )

    serve = subcommands.add_parser("serve", help="Serve the local dashboard")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)

    verify = subcommands.add_parser(
        "verify-model-poc",
        help="Build the harness for a persisted run and execute model_attempt/poc.py against it, writing model_attempt/poc_outcome.json.",
    )
    verify.add_argument("run_dir", help="Path to the persisted run directory to verify")
    verify.add_argument(
        "--base-port",
        type=int,
        default=int(os.environ.get("CVEHUNT_BASE_PORT", "4000")),
        help="Base localhost port the run used for vulnerable/patched targets.",
    )
    verify.add_argument("--json", action="store_true", help="Emit the resulting poc_outcome record as JSON")
    return parser


def _model_label(value: str | None) -> str:
    return value or os.environ.get("CVEHUNT_MODEL") or "unspecified"


def main() -> None:
    args = build_parser().parse_args()
    store = WorkdirStore(args.data_dir)
    store.ensure()
    if args.command == "run":
        cve = store.read_cve(args.cve_id)
        workflow = CveHuntWorkflow(model=_model_label(args.model), base_port=args.base_port)
        run_id = args.run_id or utc_run_id()
        artifact_root = store.run_dir(args.cve_id, run_id)
        report, events = workflow.run_with_trace(
            args.cve_id, cve, artifact_root=artifact_root, run_id=run_id,
            execute_poc=args.execute_poc,
            residual_rounds=args.residual_rounds,
        )
        if args.persist:
            store.write_report(report, events, artifact_root=workflow.last_artifact_root)
        if args.json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print(render_markdown(report))
    elif args.command == "sync-recent":
        records = fetch_recent_cves(days=args.days, limit=args.limit)
        workflow = CveHuntWorkflow(model=_model_label(args.model))
        for record in records:
            store.write_cve(record)
            if args.run:
                run_id = utc_run_id()
                artifact_root = store.run_dir(record.cve_id, run_id)
                report, events = workflow.run_with_trace(
                    record.cve_id, record, artifact_root=artifact_root, run_id=run_id
                )
                store.write_report(report, events, artifact_root=workflow.last_artifact_root)
        print(f"Synced {len(records)} CVEs into {store.cves_dir}")
    elif args.command == "dashboard":
        out = Path(args.out) if args.out else store.root / "dashboard.html"
        path = write_dashboard(store, out, repo_url=args.repo_url)
        print(path)
    elif args.command == "serve":
        serve_dashboard(store, args.host, args.port)
    elif args.command == "verify-model-poc":
        from cvehunt.agents import ModelPocVerifier
        # Resolve /cves/<CVE>/runs/<RUN-ID>/<run-name relative>, accept CVE+run too.
        run_dir = Path(args.run_dir)
        # Try store-relative shorthand: CVE-XXXX-NNNNN 2026-MM-DDTHH-MM-SSZ
        if not run_dir.exists() and " " in args.run_dir and not Path.cwd().joinpath(args.run_dir).exists():
            cve_id, run_id = args.run_dir.split(" ", 1)
            run_dir = store.run_dir(cve_id, run_id)
        if not run_dir.exists():
            raise SystemExit(f"run directory not found: {run_dir}")
        cve_path = run_dir / "cve.json"
        if not cve_path.exists():
            cve_path = store.cve_dir(run_dir.parent.name) / "cve.json"
        cve_record = None
        if cve_path.exists():
            data = json.loads(cve_path.read_text(encoding="utf-8"))
            from cvehunt.models import CveRecord
            cve_record = CveRecord(**data)
        outcome = ModelPocVerifier().verify(cve_record, run_dir, base_port=args.base_port)
        if args.json:
            print(json.dumps(outcome or {"verified": False, "reason": "no poc to verify"}, indent=2))
        else:
            ok = bool(outcome and outcome.get("verified"))
            print(
                f"model PoC verification: {'VERIFIED (vulnerable triggered)' if ok else 'NOT verified'}\n"
                + json.dumps(outcome or {}, indent=2)
            )


if __name__ == "__main__":
    main()
