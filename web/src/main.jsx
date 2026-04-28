import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  ArrowLeft,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Github,
  Search,
  ShieldCheck,
} from 'lucide-react';
import './styles.css';

const PHASES = [
  'Collector',
  'Researcher',
  'Harness Builder',
  'Exploiter',
  'Fix Developer',
  'Validator',
  'Judge',
];

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

function phaseStates(item) {
  const states = item.progress?.phase_states;
  if (Array.isArray(states) && states.length) return states;
  return PHASES.map((phase) => {
    const event = item.trace.find((entry) => entry.phase === phase);
    return {
      phase,
      reached: Boolean(event),
      status: event ? event.status || 'completed' : 'not_reached',
      message: event ? event.message : 'Not reached',
      artifact: event?.artifact || null,
    };
  });
}

function completedPhaseCount(item) {
  return phaseStates(item).filter((stage) => stage.status === 'completed').length;
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
  const [expandedCveId, setExpandedCveId] = useState(null);
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return data.cves.filter((item) => {
      if (filter === 'analyzed' && !item.report) return false;
      if (filter === 'not_analyzed' && item.report) return false;
      if (!needle) return true;
      return JSON.stringify(item.cve).toLowerCase().includes(needle);
    });
  }, [data.cves, query, filter]);

  useEffect(() => {
    if (expandedCveId && !filtered.some((item) => item.cve.cve_id === expandedCveId)) {
      setExpandedCveId(null);
    }
  }, [expandedCveId, filtered]);

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
            {filtered.map((item) => {
              const expanded = expandedCveId === item.cve.cve_id;
              return (
                <React.Fragment key={item.cve.cve_id}>
                  <tr className={expanded ? 'summaryRow expanded' : 'summaryRow'}>
                    <td>
                      <button
                        className="cveToggle"
                        onClick={() => setExpandedCveId(expanded ? null : item.cve.cve_id)}
                        aria-expanded={expanded}
                        aria-controls={`row-${item.cve.cve_id}`}
                      >
                        {expanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                        <span>
                          <strong className="cveLink">{item.cve.cve_id}</strong>
                          <span>{item.cve.name}</span>
                        </span>
                      </button>
                    </td>
                    <td><span className={cvssClass(item.cve.cvss)}>{item.cve.cvss ?? '-'}</span></td>
                    <td>{item.cve.disclosed}</td>
                    <td>{item.cve.ecosystem}</td>
                    <td><span className={statusClass(item)}>{statusLabel(item)}</span></td>
                    <td>{completedPhaseCount(item)}/{PHASES.length} completed</td>
                    <td>
                      <a className="artifactLink" href={item.artifacts.workdir_url}>workdir <ExternalLink size={13} /></a>
                    </td>
                  </tr>
                  {expanded && (
                    <tr className="expandedRow" id={`row-${item.cve.cve_id}`}>
                      <td colSpan={7}>
                        <InlineRunDetails item={item} />
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
      </section>
    </>
  );
}

function Stat({ label, value }) {
  return <div className="stat"><strong>{value}</strong><span>{label}</span></div>;
}

function InlineRunDetails({ item }) {
  const report = item.report;
  const judgement = report?.judgement;
  const finding = report?.finding;
  const states = phaseStates(item);

  return (
    <div className="inlineDetail">
      <div className="inlineHeader">
        <div>
          <p className="inlineSummary">{item.progress.summary}</p>
          <div className="inlineMeta">
            <span className={cvssClass(item.cve.cvss)}>CVSS {item.cve.cvss ?? 'unknown'}</span>
            <span className={statusClass(item)}>{statusLabel(item)}</span>
            <span className="metaPill">Run {item.report?.run?.run_id || item.pipeline_status?.run_id || 'none'}</span>
            <span className="metaPill">Model {item.report?.run?.model || item.pipeline_status?.model || 'none'}</span>
          </div>
        </div>
        <div className="inlineActions">
          <a className="artifact" href={`#/cve/${item.cve.cve_id}`}>Full view</a>
          <a className="artifact" href={item.artifacts.latest_run_url || item.artifacts.workdir_url}>
            Latest run <ExternalLink size={13} />
          </a>
        </div>
      </div>

      <div className="inlineGrid">
        <section className="panel compactPanel">
          <div className="panelTitle">
            <ShieldCheck size={18} />
            Autonomous Process
          </div>
          <div className="timeline compactTimeline">
            {states.map((stage) => (
              <div className={`phase ${phaseClass(stage.status)}`} key={stage.phase}>
                <strong>{stage.phase}</strong>
                <span>{stage.message}</span>
                {stage.artifact && <a href={artifactFor(item, stage.artifact)}>{stage.artifact}</a>}
              </div>
            ))}
          </div>
        </section>

        <section className="panel compactPanel">
          <h2>Run Summary</h2>
          {report ? (
            <dl className="definitionList">
              <Info label="Class" value={finding?.vulnerability_class} />
              <Info label="Surface" value={finding?.impacted_surface} />
              <Info label="Patch signal" value={finding?.relevant_patch_signal} />
              <Info label="Exploit generated" value={item.progress.exploit_generated ? 'yes' : 'no'} />
              <Info label="Patch generated" value={item.progress.patch_generated ? 'yes' : 'no'} />
              <Info label="Confidence" value={judgement ? Number(judgement.confidence).toFixed(2) : 'n/a'} />
            </dl>
          ) : (
            <p className="mutedText">No autonomous run has been recorded for this CVE yet.</p>
          )}
        </section>

        <section className="panel compactPanel">
          <h2>Judgement</h2>
          {judgement ? (
            <>
              <p><strong>Status:</strong> {judgement.status}</p>
              <p>{judgement.rationale}</p>
              <h3>Remediation notes</h3>
              <ul>{judgement.remediation_notes.map((note) => <li key={note}>{note}</li>)}</ul>
            </>
          ) : (
            <p className="mutedText">No judgement is available yet.</p>
          )}
        </section>

        <section className="panel compactPanel">
          <h2>Artifacts</h2>
          <div className="artifactGrid">
            <Artifact href={item.artifacts.report_md_url} label="report.md" disabled={!item.artifacts.report_md_exists} />
            <Artifact href={item.artifacts.pipeline_status_url} label="pipeline_status.json" disabled={!item.artifacts.pipeline_status_exists} />
            <Artifact href={item.artifacts.trace_url} label="trace.jsonl" disabled={!item.artifacts.trace_exists} />
            <Artifact href={item.artifacts.source_diff_url} label="source_diff.patch" disabled={!item.artifacts.source_diff_exists} />
            <Artifact href={item.artifacts.harness_readme_url} label="harness/README.md" disabled={!item.artifacts.harness_readme_exists} />
            <Artifact href={item.artifacts.exploiter_stub_url} label="exploiter/README.md" disabled={!item.artifacts.exploiter_stub_exists} />
          </div>
        </section>
      </div>
    </div>
  );
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
  const sources = report?.sources;
  const harness = report?.harness;
  const exploiter = report?.exploiter;
  const states = phaseStates(item);

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
        <Info label="Latest run" value={item.report?.run?.run_id || item.pipeline_status?.run_id || 'none'} />
        <Info label="Model" value={item.report?.run?.model || item.pipeline_status?.model || 'none'} />
      </section>

      <section className="panel">
        <div className="panelTitle">
          <ShieldCheck size={18} />
          Autonomous Process
        </div>
        <p className="mutedText">{item.progress.summary}</p>
        <div className="timeline">
          {states.map((stage) => (
            <div className={`phase ${phaseClass(stage.status)}`} key={stage.phase}>
              <strong>{stage.phase}</strong>
              <span>{stage.message}</span>
              {stage.artifact && <a href={artifactFor(item, stage.artifact)}>{stage.artifact}</a>}
            </div>
          ))}
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
            {finding.changed_files?.length > 0 && (
              <>
                <h3>Highest-churn files</h3>
                <ul>{finding.changed_files.map((path) => <li key={path}>{path}</li>)}</ul>
              </>
            )}
          </section>

          <section className="panel">
            <h2>Source Acquisition</h2>
            <dl className="definitionList">
              <Info label="Status" value={sources?.status || 'none'} />
              <Info label="Package" value={sources?.package || 'none'} />
              <Info label="Vulnerable version" value={sources?.vulnerable_version || 'none'} />
              <Info label="Patched version" value={sources?.patched_version || 'none'} />
              <Info label="Vulnerable root" value={sources?.vulnerable_root || 'none'} />
              <Info label="Patched root" value={sources?.patched_root || 'none'} />
            </dl>
            {sources?.changed_files?.length > 0 && (
              <div className="check">
                <strong>Changed files</strong>
                {sources.changed_files.slice(0, 10).map((entry) => (
                  <p key={entry.path}>
                    {entry.path}: +{entry.additions} / -{entry.deletions}
                    {entry.patch_signal ? ` (${entry.patch_signal})` : ''}
                  </p>
                ))}
              </div>
            )}
            {sources?.notes?.length > 0 && (
              <>
                <h3>Notes</h3>
                <ul>{sources.notes.map((note) => <li key={note}>{note}</li>)}</ul>
              </>
            )}
          </section>

          <section className="panel">
            <h2>Harness</h2>
            <p className="mutedText">{harness?.runtime || 'No harness metadata'} · {harness?.isolation || 'n/a'}</p>
            <dl className="definitionList">
              <Info label="Status" value={harness?.status || 'none'} />
              <Info label="Workspace" value={harness?.workspace || 'none'} />
            </dl>
            {harness?.dockerfiles?.length > 0 && (
              <>
                <h3>Dockerfiles</h3>
                <ul>{harness.dockerfiles.map((path) => <li key={path}>{path}</li>)}</ul>
              </>
            )}
            {harness?.helper_scripts?.length > 0 && (
              <>
                <h3>Helper artifacts</h3>
                <ul>{harness.helper_scripts.map((path) => <li key={path}>{path}</li>)}</ul>
              </>
            )}
            {harness?.notes?.length > 0 && (
              <>
                <h3>Notes</h3>
                <ul>{harness.notes.map((note) => <li key={note}>{note}</li>)}</ul>
              </>
            )}
          </section>

          <section className="panel">
            <h2>Exploiter</h2>
            <dl className="definitionList">
              <Info label="Status" value={exploiter?.status || 'none'} />
              <Info label="Implemented" value={exploiter?.implemented ? 'yes' : 'no'} />
              <Info label="Artifact" value={exploiter?.artifact || 'none'} />
            </dl>
            <p>{exploiter?.message || 'No exploiter metadata.'}</p>
            <p className="mutedText">{exploiter?.next_step || ''}</p>
          </section>

          <section className="panel">
            <h2>Validation Plan</h2>
            <p className="mutedText">{plan.runtime} · {plan.isolation}</p>
            {plan.checks.map((check) => (
              <div className="check" key={check.name}>
                <strong>{check.name}</strong>
                <p>{check.purpose}</p>
                <span>{check.safe_method}</span>
                {check.artifact && <a className="artifactLink" href={artifactFor(item, check.artifact)}>{check.artifact}</a>}
              </div>
            ))}
          </section>

          <section className="panel">
            <h2>Evidence</h2>
            {report.evidence.map((entry) => (
              <div className="evidence" key={entry.check_name}>
                <strong>{entry.check_name}</strong>
                <p>Vulnerable signal: {entry.vulnerable_signal}</p>
                <p>Patched signal: {entry.patched_signal}</p>
                {entry.artifact && <p><a className="artifactLink" href={artifactFor(item, entry.artifact)}>{entry.artifact}</a></p>}
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
          <Artifact href={item.artifacts.latest_run_url} label="latest run" disabled={!item.artifacts.latest_run} />
          <Artifact href={item.artifacts.cve_json_url} label="cve.json" />
          <Artifact href={item.artifacts.trace_url} label="trace.jsonl" disabled={!item.artifacts.trace_exists} />
          <Artifact href={item.artifacts.pipeline_status_url} label="pipeline_status.json" disabled={!item.artifacts.pipeline_status_exists} />
          <Artifact href={item.artifacts.report_json_url} label="report.json" disabled={!item.artifacts.report_exists} />
          <Artifact href={item.artifacts.report_md_url} label="report.md" disabled={!item.artifacts.report_md_exists} />
          <Artifact href={item.artifacts.sources_url} label="sources/" disabled={!item.artifacts.sources_exists} />
          <Artifact href={item.artifacts.source_diff_url} label="research/source_diff.patch" disabled={!item.artifacts.source_diff_exists} />
          <Artifact href={item.artifacts.harness_readme_url} label="harness/README.md" disabled={!item.artifacts.harness_readme_exists} />
          <Artifact href={item.artifacts.exploiter_stub_url} label="exploiter/README.md" disabled={!item.artifacts.exploiter_stub_exists} />
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

function phaseClass(status) {
  if (status === 'completed') return 'complete';
  if (status === 'stubbed') return 'stubbed';
  if (status === 'not_implemented') return 'blocked';
  return '';
}

function artifactFor(item, artifact) {
  const known = {
    'cve.json': item.artifacts.cve_json_url,
    'report.json': item.artifacts.report_json_url,
    'report.md': item.artifacts.report_md_url,
    'trace.jsonl': item.artifacts.trace_url,
    'pipeline_status.json': item.artifacts.pipeline_status_url,
    sources: item.artifacts.sources_url,
    'research/source_diff.patch': item.artifacts.source_diff_url,
    'harness/README.md': item.artifacts.harness_readme_url,
    'exploiter/README.md': item.artifacts.exploiter_stub_url,
  };
  if (known[artifact]) return known[artifact];
  return `${item.artifacts.artifact_blob_prefix}/${artifact}`;
}

createRoot(document.getElementById('root')).render(<App />);
