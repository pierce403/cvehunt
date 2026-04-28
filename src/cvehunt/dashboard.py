from __future__ import annotations

import html
import json
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cvehunt.storage import WorkdirStore


def _repo_artifact_url(repo_url: str | None, path: str, *, tree: bool = False) -> str:
    if not repo_url:
        return path
    kind = "tree" if tree else "blob"
    normalized = path[2:] if path.startswith("./") else path
    return f"{repo_url.rstrip('/')}/{kind}/main/{normalized}"


def build_dashboard(store: WorkdirStore, repo_url: str | None = None) -> str:
    rows = store.list_reports()
    analyzed = [row for row in rows if row["report"]]
    high = [
        row
        for row in rows
        if (row["cve"].get("cvss") is not None and row["cve"]["cvss"] >= 7)
    ]
    for row in rows:
        row["repo_workdir_url"] = _repo_artifact_url(
            repo_url,
            str(row["workdir"]),
            tree=True,
        )
        row["repo_trace_url"] = _repo_artifact_url(repo_url, str(row["trace"]))
        row["repo_report_url"] = _repo_artifact_url(
            repo_url,
            f"{row['workdir']}/report.md",
        )
    payload = json.dumps(rows)
    github_link = (
        f'<a class="repo-link" href="{html.escape(repo_url)}">GitHub</a>'
        if repo_url
        else ""
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CVEHunt Dashboard</title>
  <style>
    :root {{ color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }}
    body {{ margin: 0; background: #08090f; color: #f4f5fb; }}
    header {{ padding: 28px 32px 18px; border-bottom: 1px solid #202232; background: #0d0f18; position: sticky; top: 0; z-index: 2; }}
    .header-row {{ display: flex; align-items: center; justify-content: space-between; gap: 16px; }}
    h1 {{ margin: 0; font-size: 24px; letter-spacing: 0; }}
    .subtitle {{ margin: 8px 0 0; color: #a9adbd; font-size: 14px; }}
    .repo-link {{ border: 1px solid #333a54; border-radius: 6px; padding: 8px 10px; color: #f4f5fb; background: #151a29; font-size: 13px; white-space: nowrap; }}
    main {{ padding: 24px 32px 40px; }}
    .stats {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin-bottom: 18px; }}
    .stat {{ border: 1px solid #24283a; background: #111420; border-radius: 8px; padding: 14px; }}
    .stat strong {{ display: block; font-size: 24px; }}
    .stat span {{ color: #a9adbd; font-size: 12px; text-transform: uppercase; }}
    .controls {{ display: flex; gap: 10px; align-items: center; margin: 18px 0; flex-wrap: wrap; }}
    input, select {{ background: #10131e; color: #f4f5fb; border: 1px solid #2a2f44; border-radius: 6px; padding: 9px 10px; }}
    table {{ width: 100%; border-collapse: collapse; background: #0d1019; border: 1px solid #24283a; }}
    th, td {{ padding: 11px 12px; border-bottom: 1px solid #202436; text-align: left; vertical-align: top; font-size: 13px; }}
    th {{ color: #aeb4c8; font-size: 11px; text-transform: uppercase; background: #121624; position: sticky; top: 82px; }}
    tr:hover td {{ background: #121725; }}
    .status {{ display: inline-block; padding: 3px 8px; border-radius: 999px; background: #1f2d22; color: #9fe3ae; white-space: nowrap; }}
    .pending {{ background: #2b2731; color: #d4b5ff; }}
    .muted {{ color: #9298ab; }}
    a {{ color: #9da7ff; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .summary {{ max-width: 620px; color: #c5c9d6; }}
  </style>
</head>
<body>
  <header>
    <div class="header-row">
      <h1>CVEHunt CVE Dashboard</h1>
      {github_link}
    </div>
    <p class="subtitle">Recent CVEs with repository-backed pipeline workdirs and full agent traces.</p>
  </header>
  <main>
    <section class="stats">
      <div class="stat"><strong>{len(rows)}</strong><span>CVEs tracked</span></div>
      <div class="stat"><strong>{len(analyzed)}</strong><span>Analyzed</span></div>
      <div class="stat"><strong>{len(rows) - len(analyzed)}</strong><span>Not analyzed</span></div>
      <div class="stat"><strong>{len(high)}</strong><span>CVSS >= 7</span></div>
    </section>
    <section class="controls">
      <input id="search" placeholder="CVE-" aria-label="Search CVEs">
      <select id="status" aria-label="Status filter">
        <option value="">All statuses</option>
        <option value="analyzed">Analyzed</option>
        <option value="not_analyzed">Not analyzed</option>
      </select>
    </section>
    <table>
      <thead>
        <tr>
          <th>CVE</th>
          <th>CVSS</th>
          <th>Disclosed</th>
          <th>Ecosystem</th>
          <th>Status</th>
          <th>Confidence</th>
          <th>Summary</th>
          <th>Artifacts</th>
        </tr>
      </thead>
      <tbody id="rows"></tbody>
    </table>
  </main>
  <script>
    const DATA = {payload};
    const rowsEl = document.getElementById('rows');
    const searchEl = document.getElementById('search');
    const statusEl = document.getElementById('status');
    function esc(value) {{
      return String(value ?? '').replace(/[&<>"']/g, ch => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[ch]));
    }}
    function render() {{
      const q = searchEl.value.toLowerCase();
      const status = statusEl.value;
      rowsEl.innerHTML = '';
      DATA.filter(row => {{
        const cve = row.cve;
        const report = row.report;
        if (q && !JSON.stringify(cve).toLowerCase().includes(q)) return false;
        if (status === 'analyzed' && !report) return false;
        if (status === 'not_analyzed' && report) return false;
        return true;
      }}).forEach(row => {{
        const cve = row.cve;
        const report = row.report;
        const judgement = report?.judgement;
        const tr = document.createElement('tr');
        const statusClass = report ? 'status' : 'status pending';
        const statusText = report ? judgement.status : 'Not analyzed';
        const confidence = report ? Number(judgement.confidence).toFixed(2) : '—';
        const artifactLinks = report
          ? `<a href="${{esc(row.repo_trace_url)}}">trace</a> · <a href="${{esc(row.repo_report_url)}}">report</a>`
          : `<a href="${{esc(row.repo_workdir_url)}}">workdir</a>`;
        tr.innerHTML = `
          <td><strong>${{esc(cve.cve_id)}}</strong><br><span class="muted">${{esc(cve.name)}}</span></td>
          <td>${{esc(cve.cvss ?? '—')}}</td>
          <td>${{esc(cve.disclosed)}}</td>
          <td>${{esc(cve.ecosystem)}}</td>
          <td><span class="${{statusClass}}">${{esc(statusText)}}</span></td>
          <td>${{esc(confidence)}}</td>
          <td class="summary">${{esc(cve.summary)}}</td>
          <td>${{artifactLinks}}</td>
        `;
        rowsEl.appendChild(tr);
      }});
    }}
    searchEl.addEventListener('input', render);
    statusEl.addEventListener('change', render);
    render();
  </script>
</body>
</html>"""


def write_dashboard(
    store: WorkdirStore,
    out: Path | str,
    repo_url: str | None = None,
) -> Path:
    path = Path(out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(build_dashboard(store, repo_url=repo_url), encoding="utf-8")
    return path


def serve_dashboard(store: WorkdirStore, host: str, port: int) -> None:
    out = store.root / "dashboard.html"
    write_dashboard(store, out)
    handler = SimpleHTTPRequestHandler
    server = ThreadingHTTPServer((host, port), handler)
    print(f"Serving CVEHunt dashboard at http://{host}:{port}/{html.escape(str(out))}")
    server.serve_forever()
