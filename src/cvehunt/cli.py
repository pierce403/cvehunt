from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from cvehunt.dashboard import serve_dashboard, write_dashboard
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
        "--model",
        default=None,
        help="Model label for this run, defaults to CVEHUNT_MODEL or unspecified",
    )
    run.add_argument(
        "--execute-poc",
        action="store_true",
        help=(
            "Build the harness images, bring up the compose stack, and run the "
            "PoC against the local containers. Requires Docker."
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
    return parser


def _model_label(value: str | None) -> str:
    return value or os.environ.get("CVEHUNT_MODEL") or "unspecified"


def main() -> None:
    args = build_parser().parse_args()
    store = WorkdirStore(args.data_dir)
    store.ensure()
    if args.command == "run":
        cve = store.read_cve(args.cve_id)
        workflow = CveHuntWorkflow(model=_model_label(args.model))
        report, events = workflow.run_with_trace(
            args.cve_id, cve, execute_poc=args.execute_poc
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
                report, events = workflow.run_with_trace(record.cve_id, record)
                store.write_report(report, events, artifact_root=workflow.last_artifact_root)
        print(f"Synced {len(records)} CVEs into {store.cves_dir}")
    elif args.command == "dashboard":
        out = Path(args.out) if args.out else store.root / "dashboard.html"
        path = write_dashboard(store, out, repo_url=args.repo_url)
        print(path)
    elif args.command == "serve":
        serve_dashboard(store, args.host, args.port)


if __name__ == "__main__":
    main()
