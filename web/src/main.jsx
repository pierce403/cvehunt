import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { ArrowLeft, ExternalLink, Github, Search, ShieldCheck } from 'lucide-react';
import './styles.css';

const PHASES = ['Collector', 'Researcher', 'Environment Planner', 'Validator', 'Judge'];

function useHashRoute() {
  const [hash, setHash] = useState(window.location.hash || '#/');
  useEffect(() => {
    const onHashChange = () => setHash(window.location.hash || '#/');
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);
  return hash;
}

function cvssClass(score) {
  if (score == null) return 'score unknown';
  if (score >= 9) return 'score critical';
  if (score >= 7) return 'score high';
  if (score >= 4) return 'score medium';
  return 'score low';
}

function statusLabel(item) {
  return item.report ? item.report.judgement.status : 'Not analyzed';
}

function statusClass(item) {
  return item.report ? 'status analyzed' : 'status pending';
}

function App() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const route = useHashRoute();

  useEffect(() => {
    fetch('/data/cves.json')
      .then((response) => {
        if (!response.ok) throw new Error(`Failed to load data: ${response.status}`);
        return response.json();
      })
      .then(setData)
      .catch((err) => setError(err.message));
  }, []);

  if (error) return <Shell><div className="empty">{error}</div></Shell>;
  if (!data) return <Shell><div className="empty">Loading CVE data...</div></Shell>;

  const detailMatch = route.match(/^#\/cve\/([^/]+)$/);
  if (detailMatch) {
    const cveId = decodeURIComponent(detailMatch[1]).toUpperCase();
    const item = data.cves.find((entry) => entry.cve.cve_id.toUpperCase() === cveId);
    return (
      <Shell repoUrl={data.repo_url}>
        <Detail item={item} />
      </Shell>
    );
  }

  return (
    <Shell repoUrl={data.repo_url}>
      <Dashboard data={data} />
    </Shell>
  );
}

function Shell({ children, repoUrl }) {
  return (
    <>
      <header className="topbar">
        <div>
          <a className="brand" href="#/">CVEHunt</a>
          <p>Defensive CVE triage with repository-backed traces.</p>
        </div>
        <nav>
          <a href="#/">Dashboard</a>
          {repoUrl && (
            <a className="repoButton" href={repoUrl}>
              <Github size={16} />
              GitHub
            </a>
          )}
        </nav>
      </header>
      <main>{children}</main>
    </>
  );
}

function Dashboard({ data }) {
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState('all');
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return data.cves.filter((item) => {
      if (filter === 'analyzed' && !item.report) return false;
      if (filter === 'not_analyzed' && item.report) return false;
      if (!needle) return true;
      return JSON.stringify(item.cve).toLowerCase().includes(needle);
    });
  }, [data.cves, query, filter]);

  return (
    <>
      <section className="stats">
        <Stat label="CVEs tracked" value={data.counts.tracked} />
        <Stat label="Analyzed" value={data.counts.analyzed} />
        <Stat label="Not analyzed" value={data.counts.not_analyzed} />
        <Stat label="CVSS >= 7" value={data.counts.high} />
      </section>
      <section className="controls" aria-label="Dashboard controls">
        <label className="searchBox">
          <Search size={16} />
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="CVE-" />
        </label>
        <select value={filter} onChange={(event) => setFilter(event.target.value)}>
          <option value="all">All statuses</option>
          <option value="analyzed">Analyzed</option>
          <option value="not_analyzed">Not analyzed</option>
        </select>
      </section>
      <section className="tableWrap">
        <table>
          <thead>
            <tr>
              <th>CVE</th>
              <th>CVSS</th>
              <th>Disclosed</th>
              <th>Ecosystem</th>
              <th>Status</th>
              <th>Autonomous progress</th>
              <th>Artifacts</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((item) => (
              <tr key={item.cve.cve_id}>
                <td>
                  <a className="cveLink" href={`#/cve/${item.cve.cve_id}`}>{item.cve.cve_id}</a>
                  <span>{item.cve.name}</span>
                </td>
                <td><span className={cvssClass(item.cve.cvss)}>{item.cve.cvss ?? '-'}</span></td>
                <td>{item.cve.disclosed}</td>
                <td>{item.cve.ecosystem}</td>
                <td><span className={statusClass(item)}>{statusLabel(item)}</span></td>
                <td>{item.progress.completed_phases.length}/{PHASES.length} phases</td>
                <td>
                  <a className="artifactLink" href={item.artifacts.workdir_url}>workdir <ExternalLink size={13} /></a>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </>
  );
}

function Stat({ label, value }) {
  return <div className="stat"><strong>{value}</strong><span>{label}</span></div>;
}

function Detail({ item }) {
  if (!item) {
    return (
      <section className="detail">
        <a className="back" href="#/"><ArrowLeft size={16} /> Back</a>
        <div className="empty">CVE not found.</div>
      </section>
    );
  }
  const report = item.report;
  const judgement = report?.judgement;
  const finding = report?.finding;
  const plan = report?.plan;

  return (
    <section className="detail">
      <a className="back" href="#/"><ArrowLeft size={16} /> Back to dashboard</a>
      <div className="detailHeader">
        <div>
          <h1>{item.cve.cve_id}</h1>
          <p>{item.cve.summary}</p>
        </div>
        <div className="detailMeta">
          <span className={cvssClass(item.cve.cvss)}>CVSS {item.cve.cvss ?? 'unknown'}</span>
          <span className={statusClass(item)}>{statusLabel(item)}</span>
        </div>
      </div>

      <section className="panel gridTwo">
        <Info label="Name" value={item.cve.name} />
        <Info label="Disclosed" value={item.cve.disclosed} />
        <Info label="Ecosystem" value={item.cve.ecosystem} />
        <Info label="Known exploited" value={item.cve.kev ? 'yes' : 'no'} />
      </section>

      <section className="panel">
        <div className="panelTitle">
          <ShieldCheck size={18} />
          Autonomous Process
        </div>
        <p className="mutedText">{item.progress.summary}</p>
        <div className="timeline">
          {PHASES.map((phase) => {
            const event = item.trace.find((entry) => entry.phase === phase);
            return (
              <div className={event ? 'phase complete' : 'phase'} key={phase}>
                <strong>{phase}</strong>
                <span>{event ? event.message : 'Not reached'}</span>
                {event?.artifact && <a href={artifactFor(item, event.artifact)}>{event.artifact}</a>}
              </div>
            );
          })}
        </div>
      </section>

      <section className="panel gridTwo">
        <Outcome title="Exploit generated" value={item.progress.exploit_generated} note={item.progress.exploit_note} />
        <Outcome title="Patch generated" value={item.progress.patch_generated} note={item.progress.patch_note} />
      </section>

      {report && (
        <>
          <section className="panel">
            <h2>Finding</h2>
            <dl className="definitionList">
              <Info label="Class" value={finding.vulnerability_class} />
              <Info label="Surface" value={finding.impacted_surface} />
              <Info label="Defensive hypothesis" value={finding.defensive_hypothesis} />
              <Info label="Patch signal" value={finding.relevant_patch_signal} />
            </dl>
          </section>

          <section className="panel">
            <h2>Validation Plan</h2>
            <p className="mutedText">{plan.runtime} · {plan.isolation}</p>
            {plan.checks.map((check) => (
              <div className="check" key={check.name}>
                <strong>{check.name}</strong>
                <p>{check.purpose}</p>
                <span>{check.safe_method}</span>
              </div>
            ))}
          </section>

          <section className="panel">
            <h2>Evidence</h2>
            {report.evidence.map((entry) => (
              <div className="evidence" key={entry.check_name}>
                <strong>{entry.check_name}</strong>
                <p>Vulnerable fixture signal: {entry.vulnerable_signal}</p>
                <p>Patched fixture signal: {entry.patched_signal}</p>
                <span className={entry.passed ? 'status analyzed' : 'status pending'}>{entry.passed ? 'passed' : 'failed'}</span>
              </div>
            ))}
          </section>

          <section className="panel">
            <h2>Judgement</h2>
            <p><strong>Status:</strong> {judgement.status}</p>
            <p><strong>Confidence:</strong> {Number(judgement.confidence).toFixed(2)}</p>
            <p>{judgement.rationale}</p>
            <h3>Remediation notes</h3>
            <ul>{judgement.remediation_notes.map((note) => <li key={note}>{note}</li>)}</ul>
            <h3>Safety notes</h3>
            <ul>{judgement.safety_notes.map((note) => <li key={note}>{note}</li>)}</ul>
          </section>
        </>
      )}

      <section className="panel">
        <h2>Repository Artifacts</h2>
        <div className="artifactGrid">
          <Artifact href={item.artifacts.workdir_url} label="CVE workdir" />
          <Artifact href={item.artifacts.cve_json_url} label="cve.json" />
          <Artifact href={item.artifacts.trace_url} label="trace.jsonl" disabled={!item.artifacts.trace_exists} />
          <Artifact href={item.artifacts.report_json_url} label="report.json" disabled={!item.artifacts.report_exists} />
          <Artifact href={item.artifacts.report_md_url} label="report.md" disabled={!item.artifacts.report_md_exists} />
        </div>
      </section>
    </section>
  );
}

function Info({ label, value }) {
  return <div className="info"><dt>{label}</dt><dd>{value || '-'}</dd></div>;
}

function Outcome({ title, value, note }) {
  return (
    <div className="outcome">
      <strong>{title}</strong>
      <span className={value ? 'status analyzed' : 'status pending'}>{value ? 'yes' : 'no'}</span>
      <p>{note}</p>
    </div>
  );
}

function Artifact({ href, label, disabled }) {
  if (disabled) return <span className="artifact disabled">{label}</span>;
  return <a className="artifact" href={href}>{label} <ExternalLink size={13} /></a>;
}

function artifactFor(item, artifact) {
  if (artifact === 'cve.json') return item.artifacts.cve_json_url;
  if (artifact === 'report.json') return item.artifacts.report_json_url;
  return item.artifacts.workdir_url;
}

createRoot(document.getElementById('root')).render(<App />);
