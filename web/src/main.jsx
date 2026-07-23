import React, { useEffect, useMemo, useState } from 'react';
import { ArrowLeft, ExternalLink, Github, Search, ShieldCheck } from 'lucide-react';
import { createRoot } from 'react-dom/client';
import './styles.css';

function useHashRoute() {
  const [route, setRoute] = useState(window.location.hash || '#/');
  useEffect(() => {
    const update = () => setRoute(window.location.hash || '#/');
    window.addEventListener('hashchange', update);
    return () => window.removeEventListener('hashchange', update);
  }, []);
  return route;
}

function Shell({ data, children }) {
  return <>
    <header className="topbar">
      <div><a className="brand" href="#/">CVEHunt</a><p>Public, defensive run summaries and explicitly published artifacts.</p></div>
      <nav><a href="#/">Dashboard</a>{data?.repo_url && <a className="repoButton" href={data.repo_url}><Github size={16} /> GitHub</a>}</nav>
    </header>
    <main>{children}</main>
  </>;
}

function App() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const route = useHashRoute();
  useEffect(() => {
    fetch('/data/cves.json').then((response) => {
      if (!response.ok) throw new Error(`Failed to load public data: ${response.status}`);
      return response.json();
    }).then(setData).catch((failure) => setError(failure.message));
  }, []);
  if (error) return <Shell><div className="empty">{error}</div></Shell>;
  if (!data) return <Shell><div className="empty">Loading public run data…</div></Shell>;

  const match = route.match(/^#\/run\/([^/]+)\/([^/]+)$/);
  if (match) {
    const cveId = decodeURIComponent(match[1]);
    const runId = decodeURIComponent(match[2]);
    const run = data.runs.find((item) => item.cve_id === cveId && item.run_id === runId);
    const cve = data.cves.find((item) => item.cve_id === cveId);
    return <Shell data={data}><RunDetail run={run} cve={cve} /></Shell>;
  }
  return <Shell data={data}><Dashboard data={data} /></Shell>;
}

function Dashboard({ data }) {
  const [query, setQuery] = useState('');
  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return data.runs.filter((run) => !needle || `${run.cve_id} ${run.model_title} ${run.run_id}`.toLowerCase().includes(needle));
  }, [data.runs, query]);
  return <>
    <section className="stats">
      <Stat label="CVEs tracked" value={data.counts.tracked} />
      <Stat label="Runs summarized" value={data.counts.runs} />
      <Stat label="Runs with published artifacts" value={data.counts.publishable_runs} />
    </section>
    <section className="panel methodology">
      <div className="panelTitle"><ShieldCheck size={18} /> What this evaluation measures</div>
      <p><strong>Primary result:</strong> can one selected model start from a CVE ID, independently construct a realistic affected target, and iteratively prove the capability described by the CVE within one two-hour run?</p>
      <p className="mutedText">The same model must author every substantive gate. Trusted infrastructure only contains, executes, validates contracts, collects evidence, and scores. Exploit capability, remediation quality, refusal behavior, and infrastructure errors are reported separately.</p>
      <p className="mutedText"><strong>Current status:</strong> pre-conformance. Existing legacy and imported runs are retained for audit but are not headline model evaluations.</p>
      <a className="artifactLink" href={data.evaluation_contract.documentation_url}>Read the versioned evaluation contract <ExternalLink size={13} /></a>
    </section>
    <section className="controls"><label className="searchBox"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="CVE, model, or run" /></label></section>
    <section className="panel">
      <div className="panelTitle"><ShieldCheck size={18} /> Public run index</div>
      <p className="mutedText">Every run has a deterministic summary for every canonical phase. Drill-down links expose only site-owned copies of explicitly allowlisted, publishable artifacts.</p>
      <div className="tableWrap"><table><thead><tr><th>CVE</th><th>Run</th><th>Model</th><th>Status</th><th>Phases complete</th><th>Published artifacts</th><th>Open</th></tr></thead>
        <tbody>{visible.map((run) => <tr key={`${run.cve_id}-${run.run_id}`}>
          <td><strong>{run.cve_id}</strong></td><td>{run.run_id}</td><td>{run.model_title}</td>
          <td><span className={`status ${run.status === 'defensive_signal_observed' ? 'analyzed' : 'pending'}`}>{run.status}</span></td>
          <td>{run.phases.filter((phase) => phase.status === 'completed').length}/{run.phases.length}</td><td>{run.artifacts.length}</td>
          <td><a className="artifactLink" href={`#/run/${encodeURIComponent(run.cve_id)}/${encodeURIComponent(run.run_id)}`}>View run</a></td>
        </tr>)}</tbody></table></div>
    </section>
  </>;
}

function RunDetail({ run, cve }) {
  if (!run) return <section className="detail"><a className="back" href="#/"><ArrowLeft size={16} /> Back</a><div className="empty">Public run not found.</div></section>;
  const artifacts = new Map(run.artifacts.map((artifact) => [artifact.id, artifact]));
  return <section className="detail">
    <a className="back" href="#/"><ArrowLeft size={16} /> Back to runs</a>
    <div className="detailHeader"><div><h1>{run.cve_id}</h1><p>{cve?.summary || 'Public run detail'}</p></div><div className="detailMeta"><span className="metaPill">{run.run_id}</span><span className="metaPill">{run.model_title}</span></div></div>
    {run.run_kind === 'imported_validation' && <div className="pocVerdict partial"><strong>Imported validation artifact — excluded from model scoring</strong><p>This evidence validates the target behavior but is not credited as model-authored output.</p></div>}
    <section className="panel gridTwo">
      <Info label="Run status" value={run.status} /><Info label="Run kind" value={run.run_kind.replaceAll('_', ' ')} />
      <Info label="Legacy workflow score (not headline capability)" value={`${run.score.earned}/${run.score.available}`} /><Info label="Headline model scoring eligible" value={run.model_scoring_eligible ? 'yes' : 'no'} />
    </section>
    <section className="panel"><div className="panelTitle"><ShieldCheck size={18} /> Every pipeline phase</div>
      <div className="timeline">{run.phases.map((phase) => <div className={`phase ${phase.status === 'completed' ? 'complete' : phase.status === 'failed' ? 'blocked' : ''}`} key={phase.id}>
        <strong>{phase.name} · {phase.status}</strong><span>{phase.summary}</span><span className="mutedText">Duration: {phase.duration_ms == null ? 'not recorded' : `${phase.duration_ms} ms`}</span>
        {phase.artifact_ids.length > 0 && <div className="artifactGrid">{phase.artifact_ids.map((id) => {
          const artifact = artifacts.get(id);
          return artifact ? <PublishedArtifact artifact={artifact} key={id} /> : null;
        })}</div>}
      </div>)}</div>
    </section>
    <section className="panel weaponizationDetailPanel"><h2>Weaponization policy evaluation</h2><dl className="definitionList">
      <Info label="Decision" value={run.weaponization.decision} /><Info label="Sanitized basis" value={run.weaponization.basis} />
      <Info label="Response SHA-256" value={run.weaponization.response_sha256 || 'not recorded'} /><Info label="Response bytes" value={run.weaponization.response_bytes == null ? 'not recorded' : String(run.weaponization.response_bytes)} />
      <Info label="Duration" value={run.weaponization.duration_seconds == null ? 'not recorded' : `${run.weaponization.duration_seconds}s`} /><Info label="Raw response published" value="no" />
    </dl></section>
    <section className="panel"><h2>Raw published artifacts</h2><p className="mutedText">These are immutable, site-owned copies selected by artifact ID. Private diagnostics and unsuccessful outputs are never linked.</p>
      {run.artifacts.length ? <div className="artifactGrid">{run.artifacts.map((artifact) => <PublishedArtifact artifact={artifact} key={artifact.id} />)}</div> : <p className="empty">No artifacts from this run met the public publishability policy.</p>}
    </section>
  </section>;
}

function PublishedArtifact({ artifact }) {
  return <a className="artifact" href={artifact.href}>{artifact.label} <span>({artifact.bytes} bytes)</span><ExternalLink size={13} /></a>;
}
function Stat({ label, value }) { return <div className="stat"><strong>{value}</strong><span>{label}</span></div>; }
function Info({ label, value }) { return <div className="info"><dt>{label}</dt><dd>{value ?? '-'}</dd></div>; }

createRoot(document.getElementById('root')).render(<App />);
