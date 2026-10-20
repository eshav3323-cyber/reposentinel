import { useEffect, useMemo, useState } from "react";
import ScannerStatus from "./components/ScannerStatus";
import AttackGraph from "./components/AttackGraph";
import { getBackendStatus, uploadRepository, getAttackGraph, getScanRemediation } from "./services/api";
import "./App.css";

const NAV = [
  { id: "overview", label: "Overview", icon: "◫" },
  { id: "scan", label: "Repository scan", icon: "⌕" },
  { id: "findings", label: "Findings", icon: "◇" },
  { id: "paths", label: "Attack paths", icon: "⌘" },
  { id: "remediation", label: "Remediation", icon: "✓" },
];

function RecommendationCard({ recommendation }) {
  return <article className="remediation-card">
    <div className="remediation-card-heading"><div><span className={`severity-badge severity-${recommendation.severity}`}>{recommendation.severity.toUpperCase()}</span><span className="remediation-effort">{recommendation.estimated_effort} effort</span></div><span className="remediation-score">Heuristic score {recommendation.risk_reduction_score}/100</span></div>
    <h4>{recommendation.finding_title}</h4><p className="remediation-file"><code>{recommendation.file_path}</code></p>
    <p className="remediation-action">{recommendation.recommended_action}</p><p className="remediation-rationale">{recommendation.rationale}</p>
    <div className="remediation-meta"><span>Confidence: {recommendation.confidence}</span><span>Evidence: {recommendation.detection_type}</span><span>{recommendation.evidence_classification.replaceAll("_", " ")}</span></div>
    <div className="remediation-verification"><strong>Verification steps</strong><ol>{recommendation.verification_steps.map((step) => <li key={step}>{step}</li>)}</ol></div>
    <div className="remediation-paths"><strong>Modeled paths associated</strong>{recommendation.covered_path_ids.length ? <div className="remediation-path-chips">{recommendation.covered_path_ids.map((id) => <code key={id}>{id}</code>)}</div> : <span>No modeled path is explicitly associated.</span>}</div>
    <p className="remediation-score-note">{recommendation.score_explanation}</p>
  </article>;
}

function App() {
  const [activeView, setActiveView] = useState("overview");
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [backend, setBackend] = useState(null);
  const [health, setHealth] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [scanError, setScanError] = useState("");
  const [scanResult, setScanResult] = useState(null);
  const [findings, setFindings] = useState([]);
  const [severityFilter, setSeverityFilter] = useState("all");
  const [attackGraph, setAttackGraph] = useState(null);
  const [graphLoading, setGraphLoading] = useState(false);
  const [graphError, setGraphError] = useState("");
  const [remediation, setRemediation] = useState(null);
  const [remediationLoading, setRemediationLoading] = useState(false);
  const [remediationError, setRemediationError] = useState("");
  const [remediationBudget, setRemediationBudget] = useState(5);
  const summary = scanResult?.summary;

  async function loadBackend(showLoading = true) {
    try {
      if (showLoading) setLoading(true);
      const data = await getBackendStatus();
      setBackend(data); setHealth(data.health || null); setError("");
    } catch (err) {
      setError(`${err.message} If this is a production build, set VITE_API_BASE_URL to your backend URL and rebuild.`);
      setBackend(null); setHealth(null);
    } finally { if (showLoading) setLoading(false); }
  }

  useEffect(() => {
    const first = window.setTimeout(() => void loadBackend(), 0);
    const retry = window.setInterval(() => void loadBackend(false), 15000);
    return () => { window.clearTimeout(first); window.clearInterval(retry); };
  }, []);

  function handleFileChange(event) {
    const file = event.target.files?.[0];
    setScanError("");
    if (!file) { setSelectedFile(null); return; }
    if (!file.name.toLowerCase().endsWith(".zip")) { setSelectedFile(null); setScanError("Please choose a repository ZIP file."); event.target.value = ""; return; }
    if (file.size > 20 * 1024 * 1024) { setSelectedFile(null); setScanError("The ZIP file must be 20 MB or smaller."); event.target.value = ""; return; }
    setSelectedFile(file);
  }

  async function handleScanSubmit(event) {
    event.preventDefault();
    if (!selectedFile || uploading) return;
    setUploading(true); setScanError(""); setScanResult(null); setFindings([]); setAttackGraph(null); setGraphError(""); setRemediation(null); setRemediationError("");
    try {
      const result = await uploadRepository(selectedFile);
      setScanResult(result); setFindings(result.findings || []);
      setGraphLoading(true); setRemediationLoading(true);
      const [graph, plan] = await Promise.allSettled([getAttackGraph(result.scan_id), getScanRemediation(result.scan_id, remediationBudget)]);
      if (graph.status === "fulfilled") setAttackGraph(graph.value); else setGraphError(graph.reason?.message || "The attack graph could not be loaded.");
      if (plan.status === "fulfilled") setRemediation(plan.value); else setRemediationError(plan.reason?.message || "Remediation recommendations could not be loaded.");
      setActiveView("findings");
    } catch (err) { setScanError(err.message || "The repository scan failed."); }
    finally { setUploading(false); setGraphLoading(false); setRemediationLoading(false); }
  }

  const visibleFindings = useMemo(() => severityFilter === "all" ? findings : findings.filter((item) => item.severity?.toLowerCase() === severityFilter), [findings, severityFilter]);

  async function refreshRemediation(budget = remediationBudget) {
    if (!scanResult?.scan_id) return;
    setRemediationLoading(true); setRemediationError("");
    try { setRemediation(await getScanRemediation(scanResult.scan_id, Number(budget))); }
    catch (err) { setRemediationError(err.message || "Remediation recommendations could not be loaded."); }
    finally { setRemediationLoading(false); }
  }

  async function refreshGraph() {
    if (!scanResult?.scan_id) return;
    setGraphLoading(true); setGraphError("");
    try { setAttackGraph(await getAttackGraph(scanResult.scan_id)); }
    catch (err) { setGraphError(err.message || "Could not reload the attack graph."); }
    finally { setGraphLoading(false); }
  }

  const page = NAV.find((item) => item.id === activeView);
  const scanPanel = <>
    <section className="workspace-heading"><div><p className="eyebrow">AUTHORIZED REPOSITORY ANALYSIS</p><h1>Repository scan</h1><p>Upload a repository archive for safe, in-memory analysis. Source code is never executed.</p></div><span className="live-label">ZIP · MAX 20 MB</span></section>
    <section className="upload-panel"><form onSubmit={handleScanSubmit}>
      <label className="upload-dropzone" htmlFor="repository-zip"><span className="upload-icon" aria-hidden="true">↑</span><strong>{selectedFile ? selectedFile.name : "Choose a repository ZIP"}</strong><span>{selectedFile ? `${(selectedFile.size / (1024 * 1024)).toFixed(2)} MB selected` : "Select a .zip file from your computer"}</span><input id="repository-zip" type="file" accept=".zip,application/zip" onChange={handleFileChange} disabled={uploading} /></label>
      <div className="upload-actions"><p>Only scan repositories you own or are authorized to assess.</p><button className="primary-button" type="submit" disabled={!selectedFile || uploading}>{uploading ? "Scanning repository…" : "Run security scan"}</button></div>
    </form>
    {uploading && <div className="progress-message" role="status"><span className="loading-spinner" />Validating the ZIP archive and running available scanners…</div>}
    {scanError && <div className="scan-error" role="alert"><strong>Scan issue</strong><p>{scanError}</p></div>}
    </section>
  </>;

  const findingsPanel = <section className="findings-panel"><div className="findings-heading"><div><h2>Security findings</h2><p>Potential issues identified by the heuristic scanner and integrated tools.</p></div><label className="filter-control"><span>Severity</span><select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}><option value="all">All severities</option>{["critical", "high", "medium", "low", "info"].map((severity) => <option key={severity} value={severity}>{severity[0].toUpperCase() + severity.slice(1)}</option>)}</select></label></div>
    {!visibleFindings.length ? <div className="empty-state"><strong>{scanResult ? "No findings in this view" : "No scan results yet"}</strong><p>{scanResult ? "No matching findings were returned. This does not prove the repository is free of security issues." : "Run a repository scan to review its results here."}</p>{!scanResult && <button className="primary-button" onClick={() => setActiveView("scan")}>Start a scan</button>}</div> : <div className="findings-list">{visibleFindings.map((finding) => <article className="finding-card" key={finding.id}><div className="finding-topline"><span className={`severity-badge severity-${(finding.severity || "info").toLowerCase()}`}>{(finding.severity || "UNKNOWN").toUpperCase()}</span><span className="finding-rule">{finding.rule_id}</span><span className="finding-confidence">Confidence: {finding.confidence || "unknown"}</span></div><h3>{finding.title}</h3><p className="finding-description">{finding.description}</p><div className="finding-location"><code>{finding.file_path}{finding.line_number ? `:${finding.line_number}` : ""}</code><span>{finding.source_scanner}</span></div>{finding.redacted_evidence && <div className="evidence-block"><span>Redacted evidence</span><code>{finding.redacted_evidence}</code></div>}{finding.remediation && <div className="remediation-block"><strong>Suggested remediation</strong><p>{finding.remediation}</p></div>}<p className="finding-disclaimer">Detection type: {finding.detection_type || "unknown"}. Review this result manually before treating it as a confirmed vulnerability.</p></article>)}</div>}</section>;

  const remediationPanel = <section className="remediation-panel"><div className="remediation-heading"><div><p className="eyebrow">HUMAN REVIEW WORKFLOW</p><h2>Minimal remediation plan</h2><p>Candidate fixes ranked to cover modeled paths first, within a review budget.</p></div>{scanResult && <div className="remediation-budget"><label htmlFor="remediation-budget">Recommendation budget</label><select id="remediation-budget" value={remediationBudget} onChange={(event) => { const value = Number(event.target.value); setRemediationBudget(value); void refreshRemediation(value); }}>{[1, 3, 5, 10, 25].map((value) => <option key={value} value={value}>{value} fixes</option>)}</select><button type="button" className="retry-button" onClick={() => refreshRemediation()} disabled={remediationLoading}>{remediationLoading ? "Updating…" : "Update plan"}</button></div>}</div>
    {!scanResult ? <div className="empty-state"><strong>Remediation awaits a scan</strong><p>Recommendations are generated from actual findings after a repository scan.</p><button className="primary-button" onClick={() => setActiveView("scan")}>Scan a repository</button></div> : <>{remediationLoading && <p className="remediation-state" role="status"><span className="loading-spinner" />Building the deterministic candidate plan…</p>}{remediationError && <div className="graph-error" role="alert"><strong>Remediation plan unavailable</strong><p>{remediationError}</p><button className="retry-button" onClick={() => refreshRemediation()} disabled={remediationLoading}>Retry recommendations</button></div>}{!remediationLoading && remediation && <><p className="remediation-summary">{remediation.summary}</p><div className="remediation-coverage"><div><span>Modeled paths before</span><strong>{remediation.path_coverage_before.modeled_paths}</strong></div><div><span>Candidate-covered after</span><strong>{remediation.path_coverage_after.candidate_covered_paths}</strong></div><div><span>Still unaddressed</span><strong>{remediation.path_coverage_after.unaddressed_paths}</strong></div></div>{remediation.selected_recommendations.length ? <div className="remediation-list">{remediation.selected_recommendations.map((item) => <RecommendationCard key={item.id} recommendation={item} />)}</div> : <div className="empty-state"><strong>{remediation.ranked_recommendations.length ? "No candidate fix is associated with a modeled path" : "No remediation candidates were returned"}</strong><p>Review findings and path associations. Candidate coverage does not prove a path is eliminated.</p></div>}{remediation.ranked_recommendations.length > 0 && <details className="remediation-ranked"><summary>Show full ranked list ({remediation.ranked_recommendations.length} candidates)</summary><div className="remediation-list">{remediation.ranked_recommendations.map((item) => <RecommendationCard key={item.id} recommendation={item} />)}</div></details>}<div className="remediation-disclaimer"><strong>Human review required.</strong> Scores are transparent heuristics, not measured security outcomes. Candidate coverage is not proof that an attack is eliminated. No repository files are changed automatically.</div><ul className="remediation-limitations">{remediation.limitations.map((item) => <li key={item}>{item}</li>)}</ul></>}</>}
  </section>;

  const graphPanel = <section className="graph-panel"><div className="graph-intro"><div><h3>Repository relationship map</h3><p>Explore observed findings alongside modeled relationships and assets.</p></div>{attackGraph && <div className="graph-stats"><span><strong>{attackGraph.nodes?.length ?? 0}</strong> nodes</span><span><strong>{attackGraph.edges?.length ?? 0}</strong> relationships</span><span><strong>{attackGraph.attack_paths?.length ?? 0}</strong> modeled paths</span></div>}</div>{graphError && <div className="graph-error" role="alert"><strong>Graph unavailable</strong><p>{graphError}</p><button className="retry-button" onClick={refreshGraph} disabled={graphLoading}>{graphLoading ? "Loading…" : "Retry graph"}</button></div>}<AttackGraph graph={attackGraph} loading={graphLoading} error="" /><p className="graph-disclaimer">Attack paths are modeled review hypotheses based on available findings and relationships. They do not prove exploitability, patient-data exposure, or a confirmed compromise.</p></section>;

  return <div className="app-shell product-shell">
    <aside className={`sidebar ${mobileNavOpen ? "sidebar-open" : ""}`}>
      <a className="brand" href="#overview" onClick={() => { setActiveView("overview"); setMobileNavOpen(false); }}><span className="brand-icon">RS</span><span><strong>RepoSentinel</strong><small>HEALTH SECURITY</small></span></a>
      <div className="sidebar-caption">WORKSPACE</div><nav aria-label="Primary navigation">{NAV.map((item) => <button key={item.id} className={`nav-item ${activeView === item.id ? "active" : ""}`} onClick={() => { setActiveView(item.id); setMobileNavOpen(false); }}><span className="nav-icon">{item.icon}</span><span>{item.label}</span>{item.id === "findings" && findings.length > 0 && <b className="nav-count">{findings.length}</b>}</button>)}</nav>
      <div className="sidebar-spacer" /><div className="sidebar-connection"><span className={`status-dot ${backend ? "online" : ""}`} /><div><strong>{backend ? "API connected" : loading ? "Connecting" : "API offline"}</strong><small>{backend?.version ? `Backend v${backend.version}` : "FastAPI service"}</small></div></div><div className="sidebar-foot">DEFENSIVE ANALYSIS · LOCAL WORKSPACE</div>
    </aside>
    {mobileNavOpen && <button className="nav-scrim" aria-label="Close navigation" onClick={() => setMobileNavOpen(false)} />}
    <div className="main-column"><header className="topbar product-topbar"><button className="mobile-menu" aria-label="Open navigation" onClick={() => setMobileNavOpen(true)}>☰</button><div className="breadcrumb">Workspace <span>/</span> <strong>{page?.label}</strong></div><div className="environment"><span className={`status-dot ${backend ? "online" : ""}`} />{backend ? "SYSTEM OPERATIONAL" : loading ? "CONNECTING" : "API DISCONNECTED"}</div></header>
      <main className="dashboard workspace-dashboard">
        {error && <div className="error-banner" role="alert"><div><strong>Backend connection issue</strong><p>{error}</p></div><button onClick={() => loadBackend()} className="retry-button" disabled={loading}>{loading ? "Connecting…" : "Retry connection"}</button></div>}
        {activeView === "overview" && <>
          <section className="workspace-heading overview-heading"><div><p className="eyebrow">SECURITY OPERATIONS WORKSPACE</p><h1>Repository security, in focus.</h1><p>Analyze healthcare software repositories, trace modeled risk, and review practical remediation candidates.</p></div><button className="primary-button" onClick={() => setActiveView("scan")}>＋ New repository scan</button></section>
          <section className="overview-meta"><div><span className="meta-label">CURRENT PROJECT</span><strong>{scanResult?.filename || "No repository selected"}</strong></div><div><span className="meta-label">LATEST SCAN</span><strong>{scanResult ? new Date(scanResult.created_at).toLocaleString() : "Awaiting first scan"}</strong></div><div><span className="meta-label">SCAN DURATION</span><strong>{scanResult ? `${scanResult.duration_ms ?? 0} ms` : "—"}</strong></div><div><span className="meta-label">SCAN ID</span><strong className="mono">{scanResult?.scan_id || "—"}</strong></div></section>
          <section className="section-heading"><div><h2>Risk overview</h2><p>Latest repository scan · findings are indicators for human review</p></div><span className="live-label">{scanResult ? "LATEST RESULT" : "NO SCAN YET"}</span></section>
          <section className="summary-grid overview-risk-grid"><article className="summary-card total"><span>Total findings</span><strong>{summary?.total_findings ?? 0}</strong></article><article className="summary-card critical"><span>Critical</span><strong>{summary?.critical ?? 0}</strong></article><article className="summary-card high"><span>High</span><strong>{summary?.high ?? 0}</strong></article><article className="summary-card medium"><span>Medium</span><strong>{summary?.medium ?? 0}</strong></article><article className="summary-card low"><span>Low</span><strong>{summary?.low ?? 0}</strong></article><article className="summary-card info"><span>Files analyzed</span><strong>{summary?.files_analyzed ?? 0}</strong></article></section>
          <div className="overview-columns"><section className="overview-card"><div className="overview-card-heading"><div><p className="eyebrow">LATEST ACTIVITY</p><h2>Scan intelligence</h2></div><button className="text-button" onClick={() => setActiveView("findings")}>View findings →</button></div>{scanResult ? <><div className="scan-result-head"><div><strong>{scanResult.filename}</strong><span>{scanResult.message || "Analysis complete"}</span></div><span className="scan-duration">{scanResult.duration_ms ?? 0} ms</span></div><div className="scanner-run-grid">{Object.entries(scanResult.scanner_status || {}).map(([name, status]) => <article className="scanner-run-card" key={name}><div><strong>{name === "osv" ? "OSV-Scanner" : name === "heuristic" ? "RepoSentinel" : name}</strong><span className={`pill ${status.status === "completed" ? "success" : "pending"}`}>{status.status}</span></div><p>{status.unique_findings ?? status.findings ?? 0} findings · {status.duration_ms ?? 0} ms</p></article>)}</div></> : <div className="empty-state compact"><strong>Your workspace is ready</strong><p>Run a ZIP scan to populate findings, modeled paths, and remediation candidates.</p><button className="primary-button" onClick={() => setActiveView("scan")}>Scan a repository</button></div>}</section><section className="overview-card scanner-availability"><div className="overview-card-heading"><div><p className="eyebrow">TOOLING</p><h2>Scanner availability</h2></div></div><ScannerStatus /></section></div>
          {scanResult && <div className="overview-shortcuts"><button onClick={() => setActiveView("paths")}><span>⌘</span><strong>Explore attack paths</strong><small>{attackGraph?.attack_paths?.length ?? 0} modeled paths</small></button><button onClick={() => setActiveView("remediation")}><span>✓</span><strong>Review remediation plan</strong><small>{remediation?.selected_recommendations?.length ?? 0} selected candidates</small></button></div>}
          <section className="trust-note"><strong>Analysis boundary</strong><span>Repository code is not executed. Modeled paths are hypotheses, scanner availability does not mean a scan ran, and findings require human validation.</span></section>
        </>}
        {activeView === "scan" && scanPanel}
        {activeView === "findings" && <><section className="workspace-heading"><div><p className="eyebrow">DETECTION REVIEW</p><h1>Findings</h1><p>{scanResult ? <><strong>{scanResult.filename}</strong> · {summary?.total_findings ?? findings.length} potential issues · scan {scanResult.scan_id}</> : "Run a scan to review repository findings."}</p></div>{scanResult && <span className="live-label">{(scanResult.status || "COMPLETED").toUpperCase()} · {scanResult.duration_ms ?? 0} ms</span>}</section>{scanResult && <section className="summary-grid compact-summary"><article className="summary-card total"><span>Total findings</span><strong>{summary?.total_findings ?? findings.length}</strong></article><article className="summary-card critical"><span>Critical</span><strong>{summary?.critical ?? 0}</strong></article><article className="summary-card high"><span>High</span><strong>{summary?.high ?? 0}</strong></article><article className="summary-card medium"><span>Medium</span><strong>{summary?.medium ?? 0}</strong></article><article className="summary-card low"><span>Low</span><strong>{summary?.low ?? 0}</strong></article><article className="summary-card info"><span>Informational</span><strong>{summary?.info ?? 0}</strong></article></section>}{findingsPanel}</>}
        {activeView === "paths" && <><section className="workspace-heading"><div><p className="eyebrow">EXPOSURE MODEL</p><h1>Attack paths</h1><p>Observed findings and modeled repository relationships, presented for investigation.</p></div>{attackGraph && <span className="live-label">{attackGraph.attack_paths?.length ?? 0} MODELED PATHS</span>}</section>{scanResult ? graphPanel : <div className="empty-state"><strong>No repository graph yet</strong><p>The graph is built from an actual scan response.</p><button className="primary-button" onClick={() => setActiveView("scan")}>Scan a repository</button></div>}</>}
        {activeView === "remediation" && <><section className="workspace-heading"><div><p className="eyebrow">PRIORITIZED ACTIONS</p><h1>Remediation</h1><p>A deterministic, budgeted set of candidate fixes based on this scan's evidence.</p></div>{scanResult && <span className="live-label">HUMAN REVIEW REQUIRED</span>}</section>{remediationPanel}</>}
        <footer className="dashboard-footer"><span>RepoSentinel Health · Version 0.1.0</span><span>Defensive repository analysis · Local workspace</span></footer>
      </main>
    </div>
  </div>;
}

export default App;
