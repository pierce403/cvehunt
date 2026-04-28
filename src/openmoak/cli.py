from __future__ import annotations

import argparse
import json
from pathlib import Path

from openmoak.dashboard import serve_dashboard, write_dashboard
from openmoak.nvd import fetch_recent_cves
from openmoak.reporting import render_markdown
from openmoak.storage import WorkdirStore
from openmoak.workflow import OpenMoakWorkflow


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="openmoak")
    parser.add_argument("--data-dir", default=".openmoak", help="Local data/workdir root")
    subcommands = parser.add_subparsers(dest="command", required=True)

    run = subcommands.add_parser("run", help="Run the defensive workflow for a CVE")
    run.add_argument("cve_id", help="CVE identifier, for example CVE-2025-55182")
    run.add_argument("--json", action="store_true", help="Emit structured JSON")
    run.add_argument("--persist", action="store_true", help="Write report and trace to data dir")

    sync = subcommands.add_parser("sync-recent", help="Fetch recent CVEs from NVD")
    sync.add_argument("--days", type=int, default=7, help="Publication lookback window")
    sync.add_argument("--limit", type=int, default=50, help="Maximum CVEs to fetch")
    sync.add_argument("--run", action="store_true", help="Run the pipeline for fetched CVEs")

    dashboard = subcommands.add_parser("dashboard", help="Write a static dashboard HTML file")
    dashboard.add_argument(
        "--out",
        default=None,
        help="Output HTML path, defaults to DATA_DIR/dashboard.html",
    )

    serve = subcommands.add_parser("serve", help="Serve the local dashboard")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    store = WorkdirStore(args.data_dir)
    store.ensure()
    if args.command == "run":
        cve = store.read_cve(args.cve_id)
        report, events = OpenMoakWorkflow().run_with_trace(args.cve_id, cve)
        if args.persist:
            store.write_report(report, events)
        if args.json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print(render_markdown(report))
    elif args.command == "sync-recent":
        records = fetch_recent_cves(days=args.days, limit=args.limit)
        workflow = OpenMoakWorkflow()
        for record in records:
            store.write_cve(record)
            if args.run:
                report, events = workflow.run_with_trace(record.cve_id, record)
                store.write_report(report, events)
        print(f"Synced {len(records)} CVEs into {store.cves_dir}")
    elif args.command == "dashboard":
        out = Path(args.out) if args.out else store.root / "dashboard.html"
        path = write_dashboard(store, out)
        print(path)
    elif args.command == "serve":
        serve_dashboard(store, args.host, args.port)


if __name__ == "__main__":
    main()
