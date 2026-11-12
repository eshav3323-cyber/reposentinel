import { useEffect, useMemo, useState } from "react";
import { jsPDF } from "jspdf";
import darkLogo from "./assets/RepoSentinel_Health_Logo-removebg-preview.png";
import lightLogo from "./assets/RepoSentinel_Health_Logo__1_-removebg-preview.png";
import ScannerStatus from "./components/ScannerStatus";
import AttackGraph from "./components/AttackGraph";
import RepositoryMap from "./components/RepositoryMap";
import { scannerStatusClass } from "./components/scanStatus.js";
import { getApiDocsUrl, getBackendStatus, uploadRepository, scanGitHubRepository, getScan, getScanFindings, getAttackGraph, getScanRemediation } from "./services/api";
import "./App.css";

const NAV = [
  { id: "overview", path: "/", label: "Overview", icon: "overview" },
  { id: "scan", path: "/scan", label: "Scan Repository", icon: "scan" },
  { id: "findings", path: "/findings", label: "Findings", icon: "findings" },
  { id: "paths", path: "/attack-paths", label: "Attack Paths", icon: "paths" },
  { id: "repository-map", path: "/repository-map", label: "Repository Map", icon: "repository" },
  { id: "remediation", path: "/remediation", label: "Remediation Plan", icon: "remediation" },
];

const PROJECT_REPOSITORY_URL = "https://github.com/eshav3323-cyber/reposentinel";
const PROJECT_ISSUES_URL = `${PROJECT_REPOSITORY_URL}/issues`;

const FOOTER_COLUMNS = [
  {
    title: "Product",
    links: [
      { label: "Repository Scanner", view: "scan" },
      { label: "Security Findings", view: "findings" },
      { label: "Attack Graph", view: "paths" },
      { label: "Remediation Analysis", view: "remediation" },
      { label: "Scan History", upcoming: true },
    ],
  },
  {
    title: "Resources",
    links: [
      { label: "Documentation", href: PROJECT_REPOSITORY_URL },
      { label: "API Reference", href: getApiDocsUrl() },
      { label: "Security Analysis", view: "findings" },
      { label: "Supported Scanners", view: "overview", targetId: "scanner-availability" },
      { label: "Frequently Asked Questions", upcoming: true },
    ],
  },
  {
    title: "Connect",
    links: [
      { label: "GitHub Repository", href: PROJECT_REPOSITORY_URL },
      { label: "Contact", href: PROJECT_ISSUES_URL },
      { label: "Report an Issue", href: PROJECT_ISSUES_URL },
    ],
  },
];

const NAV_ICON_SHAPES = {
  overview: <><rect x="3.5" y="3.5" width="7" height="7" rx="1" /><rect x="13.5" y="3.5" width="7" height="7" rx="1" /><rect x="3.5" y="13.5" width="7" height="7" rx="1" /><rect x="13.5" y="13.5" width="7" height="7" rx="1" /></>,
  scan: <><path d="M12 15V3" /><path d="m7 8 5-5 5 5" /><path d="M5 14v5h14v-5" /></>,
  findings: <><circle cx="10.8" cy="10.8" r="6.4" /><path d="m16 16 4.5 4.5" /></>,
  paths: <><circle cx="5" cy="12" r="2.3" /><circle cx="19" cy="6" r="2.3" /><circle cx="19" cy="18" r="2.3" /><path d="m7.2 11.1 9.5-4.2M7.2 12.9l9.5 4.2" /></>,
  remediation: <><path d="m4 7 2 2 3-3M12 7h8" /><path d="m4 17 2 2 3-3M12 17h8" /></>,
  evaluation: <><path d="M4 20V11h4v9M10 20V5h4v15M16 20V8h4v12" /></>,
  repository: <><path d="M3 6.5A1.5 1.5 0 0 1 4.5 5H10l2 2h7.5A1.5 1.5 0 0 1 21 8.5v9a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 17.5z" /><path d="M3.5 9.5h17" /></>,
  upload: <><path d="M12 15V3" /><path d="m7 8 5-5 5 5" /><path d="M4 15v5h16v-5" /></>,
  menu: <><path d="M4 6h16M4 12h16M4 18h16" /></>,
};

function NavIcon({ name }) {
  return <svg className="ui-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false">{NAV_ICON_SHAPES[name] || NAV_ICON_SHAPES.overview}</svg>;
}

function GitHubIcon() {
  return <svg className="footer-github-icon" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" focusable="false">
    <path d="M12 .9a11.1 11.1 0 0 0-3.51 21.63c.56.1.76-.24.76-.54v-2.1c-3.1.68-3.76-1.32-3.76-1.32-.5-1.3-1.24-1.65-1.24-1.65-1.01-.7.08-.69.08-.69 1.12.08 1.71 1.15 1.71 1.15 1 .1.77 2.26 4.12 1.61.1-.73.39-1.23.7-1.51-2.48-.28-5.09-1.24-5.09-5.52 0-1.22.44-2.21 1.15-2.99-.12-.28-.5-1.42.11-2.95 0 0 .94-.3 3.05 1.14a10.6 10.6 0 0 1 5.55 0c2.11-1.44 3.05-1.14 3.05-1.14.61 1.53.23 2.67.11 2.95.72.78 1.15 1.77 1.15 2.99 0 4.29-2.62 5.23-5.11 5.51.4.34.75 1 .75 2.02v3c0 .3.2.65.77.54A11.1 11.1 0 0 0 12 .9Z" />
  </svg>;
}

function SiteFooter({ onNavigate }) {
  function renderLink(link) {
    if (link.upcoming) {
      return <span className="footer-link-upcoming" aria-disabled="true">
        {link.label}<small>Coming soon</small>
      </span>;
    }

    if (link.view) {
      const destination = NAV.find((item) => item.id === link.view);
      if (!destination) return null;

      return <a
        href={destination.path}
        onClick={(event) => {
          event.preventDefault();
          onNavigate(link.view);
          if (link.targetId) {
            window.setTimeout(() => {
              document.getElementById(link.targetId)?.scrollIntoView({
                behavior: "smooth",
                block: "center",
              });
            }, 0);
          } else {
            window.scrollTo({ top: 0, behavior: "smooth" });
          }
        }}
      >
        {link.label}
      </a>;
    }

    return <a href={link.href} target="_blank" rel="noopener noreferrer">
      {link.label}
    </a>;
  }

  return <footer className="site-footer">
    <div className="site-footer-inner">
      <div className="footer-main">
        <section className="footer-brand" aria-labelledby="footer-brand-title">
          <a
            className="footer-brand-link"
            href={PROJECT_REPOSITORY_URL}
            target="_blank"
            rel="noopener noreferrer"
            aria-label="RepoSentinel Health on GitHub (opens in a new tab)"
          >
            <img className="footer-logo" src={darkLogo} alt="RepoSentinel Health" />
          </a>
          <h2 id="footer-brand-title">RepoSentinel Health</h2>
          <p>
            Intelligent security analysis for healthcare software repositories.
            Discover vulnerabilities, understand attack paths, and prioritize
            actionable remediation.
          </p>
          <a
            className="footer-social-link"
            href={PROJECT_REPOSITORY_URL}
            target="_blank"
            rel="noopener noreferrer"
            aria-label="Visit the RepoSentinel Health GitHub repository (opens in a new tab)"
          >
            <GitHubIcon />
            <span>GitHub</span>
          </a>
        </section>

        <nav className="footer-navigation" aria-label="Footer navigation">
          {FOOTER_COLUMNS.map((column, index) => (
            <section
              className="footer-column"
              key={column.title}
              aria-labelledby={`footer-column-${index}`}
            >
              <h2 id={`footer-column-${index}`}>{column.title}</h2>
              <ul>
                {column.links.map((link) => (
                  <li key={link.label}>{renderLink(link)}</li>
                ))}
              </ul>
            </section>
          ))}
        </nav>
      </div>

      <div className="footer-bottom">
        <p>© 2026 RepoSentinel Health. All rights reserved.</p>
        <p className="footer-security-note">
          <svg viewBox="0 0 20 20" fill="none" aria-hidden="true" focusable="false">
            <path d="M10 1.7 16 4v4.8c0 4.2-2.5 7.3-6 9.5-3.5-2.2-6-5.3-6-9.5V4l6-2.3Z" stroke="currentColor" strokeWidth="1.4" />
            <path d="m7.2 9.8 1.8 1.8 3.8-4" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <span>Security-minded analysis. Human-validated decisions.</span>
        </p>
      </div>
    </div>
  </footer>;
}

function viewFromPath(path) { return NAV.find((item) => item.path === path)?.id || "overview"; }

function RecommendationCard({ recommendation }) {
  return <article className="remediation-card">
    <div className="remediation-card-heading"><div><span className={`severity-badge severity-${recommendation.severity}`}>{recommendation.severity.toUpperCase()}</span><span className="remediation-effort">{recommendation.estimated_effort} effort</span></div><span className="remediation-score">Priority heuristic {recommendation.risk_reduction_score}/100</span></div>
    <h4>{recommendation.finding_title}</h4><p className="remediation-file"><code>{recommendation.file_path}</code></p>
    <p className="remediation-action">{recommendation.recommended_action}</p><p className="remediation-rationale">{recommendation.rationale}</p>{recommendation.selection_reason && <p className="remediation-selection-reason"><strong>Why selected:</strong> {recommendation.selection_reason}</p>}
    <div className="remediation-meta"><span>Confidence: {recommendation.confidence}</span><span>Evidence: {recommendation.detection_type}</span><span>{recommendation.evidence_classification.replaceAll("_", " ")}</span></div>
    <div className="remediation-verification"><strong>Verification steps</strong><ol>{recommendation.verification_steps.map((step) => <li key={step}>{step}</li>)}</ol></div>
    <div className="remediation-paths"><strong>Modeled paths associated</strong>{recommendation.covered_path_ids.length ? <div className="remediation-path-chips">{recommendation.covered_path_ids.map((id) => <code key={id}>{id}</code>)}</div> : <span>No modeled path is explicitly associated.</span>}</div>
    <p className="remediation-score-note">{recommendation.score_explanation}</p>
  </article>;
}

function App() {
  const [activeView, setActiveView] = useState(() => viewFromPath(window.location.pathname));
  const [theme, setTheme] = useState(() => window.localStorage.getItem("reposentinel.theme") === "light" ? "light" : "dark");
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [backend, setBackend] = useState(null);
  const [health, setHealth] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [selectedFile, setSelectedFile] = useState(null);
  const [scanInputMode, setScanInputMode] = useState("zip");
  const [githubUrl, setGithubUrl] = useState("");
  const [uploading, setUploading] = useState(false);
  const [scanError, setScanError] = useState("");
  const [scanResult, setScanResult] = useState(null);
  const [findings, setFindings] = useState([]);
  const [severityFilter, setSeverityFilter] = useState("all");
  const [findingSearch, setFindingSearch] = useState("");
  const [attackGraph, setAttackGraph] = useState(null);
  const [graphLoading, setGraphLoading] = useState(false);
  const [graphError, setGraphError] = useState("");
  const [remediation, setRemediation] = useState(null);
  const [remediationLoading, setRemediationLoading] = useState(false);
  const [remediationError, setRemediationError] = useState("");
  const [remediationBudget, setRemediationBudget] = useState(5);
  const summary = scanResult?.summary;
  function toggleTheme() {
    setTheme((current) => {
      const next = current === "dark" ? "light" : "dark";
      window.localStorage.setItem("reposentinel.theme", next);
      return next;
    });
  }

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

  useEffect(() => {
    const syncRoute = () => setActiveView(viewFromPath(window.location.pathname));
    window.addEventListener("popstate", syncRoute);
    return () => window.removeEventListener("popstate", syncRoute);
  }, []);

  useEffect(() => {
    const savedScanId = window.sessionStorage.getItem("reposentinel.latestScanId");
    if (!savedScanId) return;
    let cancelled = false;
    async function restoreLatestScan() {
      try {
        const [scan, findingData] = await Promise.all([getScan(savedScanId), getScanFindings(savedScanId)]);
        if (cancelled) return;
        setScanResult({ ...scan, findings: findingData.findings || [] });
        setFindings(findingData.findings || []);
        const [graph, plan] = await Promise.allSettled([getAttackGraph(savedScanId), getScanRemediation(savedScanId, 5)]);
        if (cancelled) return;
        if (graph.status === "fulfilled") setAttackGraph(graph.value); else setGraphError(graph.reason?.message || "The attack graph could not be loaded.");
        if (plan.status === "fulfilled") setRemediation(plan.value); else setRemediationError(plan.reason?.message || "Remediation recommendations could not be loaded.");
      } catch (err) {
        if (!cancelled) {
          window.sessionStorage.removeItem("reposentinel.latestScanId");
          setScanError(`The previous scan could not be restored: ${err.message}`);
        }
      }
    }
    void restoreLatestScan();
    return () => { cancelled = true; };
  }, []);

  function navigate(view) {
    const destination = NAV.find((item) => item.id === view) || NAV[0];
    if (window.location.pathname !== destination.path) window.history.pushState({}, "", destination.path);
    setActiveView(destination.id);
  }

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
    if (uploading) return;

    if (scanInputMode === "zip" && !selectedFile) {
      setScanError("Please choose a repository ZIP file.");
      return;
    }

    if (scanInputMode === "github" && !githubUrl.trim()) {
      setScanError("Please enter a public GitHub repository URL.");
      return;
    }

    setUploading(true);
    setScanError("");
    setScanResult(null);
    setFindings([]);
    setAttackGraph(null);
    setGraphError("");
    setRemediation(null);
    setRemediationError("");

    try {
      const result = scanInputMode === "github"
        ? await scanGitHubRepository(githubUrl.trim())
        : await uploadRepository(selectedFile);

      window.sessionStorage.setItem("reposentinel.latestScanId", result.scan_id);
      setScanResult(result);
      setFindings(result.findings || []);
      setGraphLoading(true);
      setRemediationLoading(true);

      const [graph, plan] = await Promise.allSettled([
        getAttackGraph(result.scan_id),
        getScanRemediation(result.scan_id, remediationBudget),
      ]);

      if (graph.status === "fulfilled") {
        setAttackGraph(graph.value);
      } else {
        setGraphError(graph.reason?.message || "The attack graph could not be loaded.");
      }

      if (plan.status === "fulfilled") {
        setRemediation(plan.value);
      } else {
        setRemediationError(plan.reason?.message || "Remediation recommendations could not be loaded.");
      }

      navigate("findings");
    } catch (err) {
      setScanError(err.message || "The repository scan failed.");
    } finally {
      setUploading(false);
      setGraphLoading(false);
      setRemediationLoading(false);
    }
  }

  const visibleFindings = useMemo(() => findings.filter((item) => {
    const severityMatches = severityFilter === "all" || item.severity?.toLowerCase() === severityFilter;
    const query = findingSearch.trim().toLowerCase();
    const textMatches = !query || [item.title, item.description, item.rule_id, item.file_path, item.source_scanner].some((value) => String(value || "").toLowerCase().includes(query));
    return severityMatches && textMatches;
  }), [findings, severityFilter, findingSearch]);

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
    <section className="workspace-heading">
      <div>
        <p className="eyebrow">AUTHORIZED REPOSITORY ANALYSIS</p>
        <h1>Repository scan</h1>
        <p>Scan a public GitHub repository or upload a ZIP archive. Source code is never executed.</p>
      </div>
      <span className="live-label">{scanInputMode === "github" ? "GITHUB · PUBLIC" : "ZIP · MAX 20 MB"}</span>
    </section>

    <section className="upload-panel">
      <div className="scan-mode-switch" role="tablist" aria-label="Repository input method">
        <button
          type="button"
          className={scanInputMode === "zip" ? "scan-mode-button active" : "scan-mode-button"}
          onClick={() => setScanInputMode("zip")}
        >
          Upload ZIP
        </button>
        <button
          type="button"
          className={scanInputMode === "github" ? "scan-mode-button active" : "scan-mode-button"}
          onClick={() => setScanInputMode("github")}
        >
          GitHub URL
        </button>
      </div>

      <form onSubmit={handleScanSubmit}>
        {scanInputMode === "zip" ? (
          <label className="upload-dropzone" htmlFor="repository-zip">
            <span className="upload-icon" aria-hidden="true"><NavIcon name="upload" /></span>
            <strong>{selectedFile ? selectedFile.name : "Choose a repository ZIP"}</strong>
            <span>{selectedFile ? `${(selectedFile.size / (1024 * 1024)).toFixed(2)} MB selected` : "Select a .zip file from your computer"}</span>
            <input id="repository-zip" type="file" accept=".zip,application/zip" onChange={handleFileChange} disabled={uploading} />
          </label>
        ) : (
          <label className="github-url-field" htmlFor="github-repository-url">
            <span className="github-url-label">Public GitHub repository URL</span>
            <input
              id="github-repository-url"
              type="url"
              className="github-url-input"
              placeholder="https://github.com/owner/repository"
              value={githubUrl}
              onChange={(event) => setGithubUrl(event.target.value)}
              disabled={uploading}
            />
          </label>
        )}

        <div className="upload-actions">
          <p>Only scan repositories you own or are authorized to assess.</p>
          <button
            className="primary-button"
            type="submit"
            disabled={
              uploading ||
              (scanInputMode === "zip" ? !selectedFile : !githubUrl.trim())
            }
          >
            {uploading ? "Scanning repository…" : "Run security scan"}
          </button>
        </div>
      </form>

      {uploading && <div className="progress-message" role="status"><span className="loading-spinner" />Validating the repository and running available scanners…</div>}
      {scanError && <div className="scan-error" role="alert"><strong>Scan issue</strong><p>{scanError}</p></div>}
    </section>
  </>;

  function downloadFindingsPdf() {
    if (!visibleFindings.length) return;

    const doc = new jsPDF({ unit: "pt", format: "a4" });
    const margin = 40;
    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    let y = 60;

    doc.setFont("helvetica", "bold");
    doc.setFontSize(18);
    doc.text("RepoSentinel Health Findings Report", margin, y);
    y += 24;

    doc.setFont("helvetica", "normal");
    doc.setFontSize(10);
    doc.text(`Generated: ${new Date().toLocaleString()}`, margin, y);
    y += 18;

    visibleFindings.forEach((finding, index) => {
      if (y > pageHeight - 110) {
        doc.addPage();
        y = 50;
      }

      const title = `${index + 1}. ${finding.title || "Untitled finding"}`;
      const severity = `Severity: ${(finding.severity || "info").toUpperCase()}`;
      const rule = `Rule: ${finding.rule_id || "unknown"}`;
      const location = `Location: ${finding.file_path || "unknown"}${finding.line_number ? `:${finding.line_number}` : ""}`;
      const scanner = `Scanner: ${finding.source_scanner || "unknown"}`;
      const confidence = `Confidence: ${finding.confidence || "unknown"}`;
      const description = finding.description || "No description provided.";
      const remediation = finding.remediation || "No remediation details provided.";

      doc.setFont("helvetica", "bold");
      doc.setFontSize(12);
      const lines = doc.splitTextToSize(title, pageWidth - margin * 2);
      doc.text(lines, margin, y);
      y += lines.length * 14 + 8;

      doc.setFont("helvetica", "normal");
      doc.setFontSize(10);
      const info = [severity, rule, location, scanner, confidence];
      info.forEach((lineText) => {
        const wrapped = doc.splitTextToSize(lineText, pageWidth - margin * 2);
        doc.text(wrapped, margin, y);
        y += wrapped.length * 12 + 2;
      });

      const descriptionLines = doc.splitTextToSize(`Description: ${description}`, pageWidth - margin * 2);
      doc.text(descriptionLines, margin, y);
      y += descriptionLines.length * 12 + 6;

      const remediationLines = doc.splitTextToSize(`Recommended remediation: ${remediation}`, pageWidth - margin * 2);
      doc.text(remediationLines, margin, y);
      y += remediationLines.length * 12 + 14;

      if (finding.redacted_evidence) {
        const evidenceLines = doc.splitTextToSize(`Evidence: ${finding.redacted_evidence}`, pageWidth - margin * 2);
        doc.text(evidenceLines, margin, y);
        y += evidenceLines.length * 12 + 12;
      }
    });

    const filename = `reposentinel-findings-${new Date().toISOString().slice(0, 10)}.pdf`;
    doc.save(filename);
  }

  const findingsPanel = <section className="findings-panel"><div className="findings-heading"><div><h2>Security findings</h2><p>Potential issues identified by the heuristic scanner and integrated tools.</p></div><div className="finding-controls"><label className="search-control"><span className="sr-only">Search findings</span><input type="search" value={findingSearch} onChange={(event) => setFindingSearch(event.target.value)} placeholder="Search title, rule, file, or scanner" /></label><label className="filter-control"><span>Severity</span><select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}><option value="all">All severities</option>{["critical", "high", "medium", "low", "info"].map((severity) => <option key={severity} value={severity}>{severity[0].toUpperCase() + severity.slice(1)}</option>)}</select></label><button type="button" className="pdf-button" onClick={downloadFindingsPdf} disabled={!visibleFindings.length}>Download PDF</button></div></div>
    {!visibleFindings.length ? <div className="empty-state"><strong>{scanResult ? "No findings match these filters" : "No scan results yet"}</strong><p>{scanResult ? "Adjust your search or severity filter. An empty result does not prove the repository is free of security issues." : "Run a scan to review repository findings here."}</p>{!scanResult && <button className="primary-button" onClick={() => navigate("scan")}>Start a scan</button>}</div> : <div className="findings-list">{visibleFindings.map((finding) => {
      const explanation = finding.explanation || {
        simple_title: finding.title,
        what_it_means: finding.description || "This issue was flagged by the scanner and requires human review.",
        why_it_matters: "This issue matters because it can affect the security, integrity, or reliability of the application or its data.",
        possible_impact: ["The actual impact depends on how the affected code or dependency is used in production.", "This finding should be reviewed before being treated as a confirmed breach."],
        how_to_fix: [finding.remediation || "Review the issue and apply the recommended fix in the project."],
      };

      return <article className="finding-card" key={finding.id}><div className="finding-topline"><span className={`severity-badge severity-${(finding.severity || "info").toLowerCase()}`}>{(finding.severity || "UNKNOWN").toUpperCase()}</span><span className="finding-rule">{finding.rule_id}</span><span className="finding-confidence">Confidence: {finding.confidence || "unknown"}</span></div><h3>{explanation.simple_title || finding.title}</h3>{explanation.simple_title && explanation.simple_title !== finding.title && <p className="finding-simple-title">Original finding: {finding.title}</p>}<div className="explanation-stack"><div className="explanation-section"><h4>What does this mean?</h4><p>{explanation.what_it_means}</p></div><div className="explanation-section"><h4>Why should you care?</h4><p>{explanation.why_it_matters}</p></div><div className="explanation-section"><h4>What could happen?</h4><ul>{(explanation.possible_impact || []).map((item) => <li key={item}>{item}</li>)}</ul></div><div className="explanation-section"><h4>How can you fix it?</h4><ol>{(explanation.how_to_fix || []).map((item) => <li key={item}>{item}</li>)}</ol></div></div><div className="finding-location"><code>{finding.file_path}{finding.line_number ? `:${finding.line_number}` : ""}</code><span>{finding.source_scanner}</span></div>{finding.redacted_evidence && <div className="evidence-block"><span>Redacted evidence</span><code>{finding.redacted_evidence}</code></div>}{finding.remediation && <div className="remediation-block"><strong>Suggested remediation</strong><p>{finding.remediation}</p></div>}<details className="technical-details"><summary>Technical details</summary><div className="technical-content"><div className="technical-grid"><div><span>Original title</span><strong>{finding.title}</strong></div><div><span>Rule ID</span><strong>{finding.rule_id}</strong></div><div><span>Scanner</span><strong>{finding.source_scanner}</strong></div><div><span>File</span><strong>{finding.file_path}</strong></div><div><span>Line</span><strong>{finding.line_number}</strong></div><div><span>Confidence</span><strong>{finding.confidence || "unknown"}</strong></div></div><div className="technical-block"><span>Technical description</span><p>{finding.description}</p></div><div className="technical-block"><span>Original remediation</span><p>{finding.remediation}</p></div>{finding.redacted_evidence && <div className="technical-block"><span>Evidence</span><pre>{finding.redacted_evidence}</pre></div>}<div className="technical-block"><span>Metadata</span><p>Severity: {finding.severity || "unknown"}. Detection type: {finding.detection_type || "unknown"}.</p></div></div></details><p className="finding-disclaimer">Detection type: {finding.detection_type || "unknown"}. Review this result manually before treating it as a confirmed vulnerability.</p></article>;
    })}</div>}</section>;

  const remediationPanel = (
    <section className="remediation-panel">
      <div className="remediation-heading">
        <div>
          <p className="eyebrow">HUMAN REVIEW WORKFLOW</p>
          <h2>Minimal remediation plan</h2>
          <p>Candidate fixes ranked to cover modeled review groups first, within a review budget.</p>
        </div>
        {scanResult && <div className="remediation-budget">
          <label htmlFor="remediation-budget">Recommendation budget</label>
          <select
            id="remediation-budget"
            value={remediationBudget}
            onChange={(event) => {
              const value = Number(event.target.value);
              setRemediationBudget(value);
              void refreshRemediation(value);
            }}
          >
            {[1, 3, 5, 10, 25].map((value) => (
              <option key={value} value={value}>{value} fixes</option>
            ))}
          </select>
          <button
            type="button"
            className="retry-button"
            onClick={() => refreshRemediation()}
            disabled={remediationLoading}
          >
            {remediationLoading ? "Updating…" : "Update plan"}
          </button>
        </div>}
      </div>
      {!scanResult ? (
        <div className="empty-state">
          <strong>Remediation awaits a scan</strong>
          <p>Recommendations are generated from actual findings after a repository scan.</p>
          <button className="primary-button" onClick={() => navigate("scan")}>Scan a repository</button>
        </div>
      ) : (
        <>
          {remediationLoading && <p className="remediation-state" role="status"><span className="loading-spinner" />Building the deterministic candidate plan…</p>}
          {remediationError && <div className="graph-error" role="alert">
            <strong>Remediation plan unavailable</strong>
            <p>{remediationError}</p>
            <button className="retry-button" onClick={() => refreshRemediation()} disabled={remediationLoading}>Retry recommendations</button>
          </div>}
          {!remediationLoading && remediation && <>
            <p className="remediation-summary">{remediation.summary}</p>
            <p className="remediation-optimization">{remediation.optimization_explanation}</p>
            <div className="remediation-coverage">
              <div><span>Modeled review groups before</span><strong>{remediation.path_coverage_before.modeled_paths}</strong></div>
              <div><span>Candidate-covered groups</span><strong>{remediation.path_coverage_after.candidate_covered_paths}</strong></div>
              <div><span>Unaddressed groups</span><strong>{remediation.path_coverage_after.unaddressed_paths}</strong></div>
            </div>
            {remediation.selected_recommendations.length ? (
              <div className="remediation-list">
                {remediation.selected_recommendations.map((item) => <RecommendationCard key={item.id} recommendation={item} />)}
              </div>
            ) : (
              <div className="empty-state">
                <strong>{remediation.ranked_recommendations.length ? "No candidates met the current selection rules" : "No remediation candidates were returned"}</strong>
                <p>Candidate coverage is a planning aid, not evidence that a review group is resolved or eliminated.</p>
              </div>
            )}
            {remediation.ranked_recommendations.length > 0 && <details className="remediation-ranked">
              <summary>Show full ranked list ({remediation.ranked_recommendations.length} candidates)</summary>
              <div className="remediation-list">
                {remediation.ranked_recommendations.map((item) => <RecommendationCard key={item.id} recommendation={item} />)}
              </div>
            </details>}
            <div className="remediation-disclaimer">
              <strong>Human review required.</strong> Priority scores are transparent heuristics, not CVSS/EPSS scores, exploitability probabilities, or measured security outcomes. Candidate coverage is not proof that a review group is resolved or eliminated. No repository files are changed automatically.
            </div>
            <ul className="remediation-limitations">
              {remediation.limitations.map((item) => <li key={item}>{item}</li>)}
            </ul>
          </>}
        </>
      )}
    </section>
  );

  const graphPanel = <section className="graph-panel"><div className="graph-intro"><div><h3>Repository relationship map</h3><p>Explore observed findings alongside modeled relationships and assets.</p></div>{attackGraph && <div className="graph-stats"><span><strong>{attackGraph.nodes?.length ?? 0}</strong> nodes</span><span><strong>{attackGraph.edges?.length ?? 0}</strong> relationships</span><span><strong>{attackGraph.attack_paths?.length ?? 0}</strong> modeled review groups</span></div>}</div>{graphError && <div className="graph-error" role="alert"><strong>Graph unavailable</strong><p>{graphError}</p><button className="retry-button" onClick={refreshGraph} disabled={graphLoading}>{graphLoading ? "Loading…" : "Retry graph"}</button></div>}<AttackGraph graph={attackGraph} findings={findings} loading={graphLoading} error="" /><p className="graph-disclaimer">Grouped findings and modeled relationships are review hypotheses, not confirmed exploit chains. They do not prove exploitability, patient-data exposure, or a confirmed compromise.</p></section>;

  return <div className="app-shell product-shell" data-theme={theme}>
    <aside className={`sidebar ${mobileNavOpen ? "sidebar-open" : ""}`}>
      <a className="brand" href="#overview" onClick={() => { navigate("overview"); setMobileNavOpen(false); }}>
        <img className="brand-logo" src={theme === "dark" ? darkLogo : lightLogo} alt="RepoSentinel Health logo" />
      </a>
      <div className="sidebar-caption">WORKSPACE</div><nav aria-label="Primary navigation">{NAV.map((item) => <button key={item.id} className={`nav-item ${activeView === item.id ? "active" : ""}`} onClick={() => { navigate(item.id); setMobileNavOpen(false); }}><span className="nav-icon"><NavIcon name={item.icon} /></span><span>{item.label}</span>{item.id === "findings" && findings.length > 0 && <b className="nav-count">{findings.length}</b>}</button>)}</nav>
      <div className="sidebar-spacer" /><div className="sidebar-connection"><span className={`status-dot ${health?.status === "healthy" ? "online" : ""}`} /><div><strong>{health?.status === "healthy" ? "Backend healthy" : backend ? "API responding" : loading ? "Connecting" : "API offline"}</strong><small>{backend?.version ? `Backend v${backend.version}` : "FastAPI service"}</small></div></div><div className="sidebar-foot">DEFENSIVE ANALYSIS · LOCAL WORKSPACE</div>
    </aside>
    {mobileNavOpen && <button className="nav-scrim" aria-label="Close navigation" onClick={() => setMobileNavOpen(false)} />}
    <div className="main-column"><header className="topbar product-topbar"><button className="mobile-menu" aria-label="Open navigation" onClick={() => setMobileNavOpen(true)}><NavIcon name="menu" /></button><div className="breadcrumb">Workspace <span>/</span> <strong>{page?.label}</strong></div><button type="button" className="theme-toggle" onClick={toggleTheme} aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`} title={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}><svg className="ui-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{theme === "dark" ? <><circle cx="12" cy="12" r="4" /><path d="M12 2v2m0 16v2M4.93 4.93l1.42 1.42m11.3 11.3 1.42 1.42M2 12h2m16 0h2M4.93 19.07l1.42-1.42m11.3-11.3 1.42-1.42" /></> : <><path d="M20.5 15.3A8.5 8.5 0 0 1 8.7 3.5 8.5 8.5 0 1 0 20.5 15.3Z" /></>}</svg><span>{theme === "dark" ? "Light" : "Dark"}</span></button><div className="environment"><span className={`status-dot ${health?.status === "healthy" ? "online" : ""}`} />{health?.status === "healthy" ? "SYSTEM OPERATIONAL" : backend ? "API RESPONDING" : loading ? "CONNECTING" : "API DISCONNECTED"}</div></header>
      <main className="dashboard workspace-dashboard">
        {error && <div className="error-banner" role="alert"><div><strong>Backend connection issue</strong><p>{error}</p></div><button onClick={() => loadBackend()} className="retry-button" disabled={loading}>{loading ? "Connecting…" : "Retry connection"}</button></div>}
        {activeView === "overview" && <>
          <section className="hero-section" aria-label="RepoSentinel overview hero">
            <div className="hero-copy">
              <span className="eyebrow hero-eyebrow">SECURE EVERY DEPLOYMENT</span>
              <h2>See repository risk before it becomes a breach.</h2>
              <p>RepoSentinel turns noisy scanner output into a clear operational view of exposed paths, high-risk findings, and the remediation work that matters most.</p>
              <div className="hero-actions">
                <button className="primary-button" onClick={() => navigate("scan")}>Scan repository</button>
                <button className="secondary-button" onClick={() => navigate("paths")}>View attack paths</button>
              </div>
              <ul className="hero-metrics">
                <li><strong>Repository graph</strong><span>Map attack paths and dependencies</span></li>
                <li><strong>Prioritized fixes</strong><span>Ranked remediation candidates</span></li>
                <li><strong>Human review</strong><span>Structured evidence and traceability</span></li>
              </ul>
            </div>
          </section>
          <section className="workspace-heading overview-heading"><div><p className="eyebrow">SECURITY OPERATIONS WORKSPACE</p><h1>Security Overview</h1><p>Monitor repository security, investigate findings, and prioritize remediation.</p></div><button className="primary-button" onClick={() => navigate("scan")}>New Repository Scan</button></section>
          <section className="overview-meta"><div><span className="meta-label">CURRENT PROJECT</span><strong>{scanResult?.filename || "No repository selected"}</strong></div><div><span className="meta-label">LATEST SCAN</span><strong>{scanResult ? new Date(scanResult.created_at).toLocaleString() : "Awaiting first scan"}</strong></div><div><span className="meta-label">SCAN DURATION</span><strong>{scanResult ? `${scanResult.duration_ms ?? 0} ms` : "—"}</strong></div><div><span className="meta-label">SCAN ID</span><strong className="mono">{scanResult?.scan_id || "—"}</strong></div></section>
          <section className="section-heading"><div><h2>Risk overview</h2><p>Latest repository scan · findings are indicators for human review</p></div><span className="live-label">{scanResult ? "LATEST RESULT" : "NO SCAN YET"}</span></section>
          <section className="summary-grid overview-risk-grid"><article className="summary-card total"><span>Total findings</span><strong>{summary?.total_findings ?? "—"}</strong></article><article className="summary-card critical"><span>Critical</span><strong>{summary?.critical ?? "—"}</strong></article><article className="summary-card high"><span>High</span><strong>{summary?.high ?? "—"}</strong></article><article className="summary-card medium"><span>Medium</span><strong>{summary?.medium ?? "—"}</strong></article><article className="summary-card low"><span>Low</span><strong>{summary?.low ?? "—"}</strong></article><article className="summary-card info"><span>Files analyzed</span><strong>{summary?.files_analyzed ?? "—"}</strong></article></section>
          <div className="overview-columns"><section className="overview-card"><div className="overview-card-heading"><div><p className="eyebrow">LATEST ACTIVITY</p><h2>Scan intelligence</h2></div><button className="text-button" onClick={() => navigate("findings")}>View findings →</button></div>{scanResult ? <><div className="scan-result-head"><div><strong>{scanResult.filename}</strong><span>{scanResult.message || "Analysis complete"}</span></div><span className="scan-duration">{scanResult.duration_ms ?? 0} ms</span></div><div className="scanner-run-grid">{Object.entries(scanResult.scanner_status || {}).map(([name, status]) => <article className="scanner-run-card" key={name}><div><strong>{name === "osv" ? "OSV-Scanner" : name === "heuristic" ? "RepoSentinel" : name}</strong><span className={`pill ${scannerStatusClass(status.status)}`}>{status.status}</span></div><p>{status.unique_findings ?? status.findings ?? 0} findings · {status.duration_ms ?? 0} ms</p></article>)}</div></> : <div className="empty-state compact"><strong>Your workspace is ready</strong><p>Run a ZIP scan to populate findings, modeled paths, and remediation candidates.</p><button className="primary-button" onClick={() => navigate("scan")}>Scan a repository</button></div>}</section><section className="overview-card scanner-availability" id="scanner-availability"><div className="overview-card-heading"><div><p className="eyebrow">TOOLING</p><h2>Scanner availability</h2></div></div><ScannerStatus /></section></div>
          {scanResult && <section className="overview-card severity-chart"><div className="overview-card-heading"><div><p className="eyebrow">FINDING DISTRIBUTION</p><h2>Severity profile</h2></div><button className="text-button" onClick={() => navigate("findings")}>All findings →</button></div>{[{ key: "critical", label: "Critical" }, { key: "high", label: "High" }, { key: "medium", label: "Medium" }, { key: "low", label: "Low" }, { key: "info", label: "Informational" }].map(({ key, label }) => { const count = summary?.[key] ?? 0; const total = summary?.total_findings ?? 0; return <div className="severity-bar-row" key={key}><span>{label}</span><div className={`severity-track ${key}`}><i style={{ width: `${total ? (count / total) * 100 : 0}%` }} /></div><strong>{count}</strong></div>; })}</section>}
          {scanResult && <div className="overview-shortcuts"><button onClick={() => navigate("paths")}><span><NavIcon name="paths" /></span><strong>Explore attack paths</strong><small>{attackGraph?.attack_paths?.length ?? 0} modeled review groups</small></button><button onClick={() => navigate("remediation")}><span><NavIcon name="remediation" /></span><strong>Review remediation plan</strong><small>{remediation?.selected_recommendations?.length ?? 0} selected candidates</small></button></div>}
          <section className="trust-note"><strong>Analysis boundary</strong><span>Repository code is not executed. Modeled paths are hypotheses, scanner availability does not mean a scan ran, and findings require human validation.</span></section>
        </>}
        {activeView === "scan" && scanPanel}
        {activeView === "findings" && <><section className="workspace-heading"><div><p className="eyebrow">DETECTION REVIEW</p><h1>Findings</h1><p>{scanResult ? <><strong>{scanResult.filename}</strong> · {summary?.total_findings ?? findings.length} potential issues · scan {scanResult.scan_id}</> : "Run a scan to review repository findings."}</p></div>{scanResult && <span className="live-label">{(scanResult.status || "COMPLETED").toUpperCase()} · {scanResult.duration_ms ?? 0} ms</span>}</section>{scanResult && <section className="summary-grid compact-summary"><article className="summary-card total"><span>Total findings</span><strong>{summary?.total_findings ?? findings.length}</strong></article><article className="summary-card critical"><span>Critical</span><strong>{summary?.critical ?? "—"}</strong></article><article className="summary-card high"><span>High</span><strong>{summary?.high ?? "—"}</strong></article><article className="summary-card medium"><span>Medium</span><strong>{summary?.medium ?? "—"}</strong></article><article className="summary-card low"><span>Low</span><strong>{summary?.low ?? "—"}</strong></article><article className="summary-card info"><span>Informational</span><strong>{summary?.info ?? 0}</strong></article></section>}{findingsPanel}</>}
        {activeView === "paths" && <><section className="workspace-heading"><div><p className="eyebrow">EXPOSURE MODEL</p><h1>Attack paths</h1><p>Observed findings and modeled repository relationships, presented for investigation.</p></div>{attackGraph && <span className="live-label">{attackGraph.attack_paths?.length ?? 0} MODELED REVIEW GROUPS</span>}</section>{scanResult ? graphPanel : <div className="empty-state"><strong>No repository graph yet</strong><p>The graph is built from an actual scan response.</p><button className="primary-button" onClick={() => navigate("scan")}>Scan a repository</button></div>}</>}
        {activeView === "repository-map" && <><section className="workspace-heading"><div><p className="eyebrow">REPOSITORY STRUCTURE</p><h1>Repository map</h1><p>Explore file paths surfaced by the latest scan as a graph and a readable tree.</p></div>{scanResult && <span className="live-label">{scanResult.filename}</span>}</section>{scanResult ? <RepositoryMap findings={findings} /> : <div className="empty-state"><strong>No repository structure to map yet</strong><p>Run a ZIP scan first. The current API provides file paths attached to findings, not a complete file inventory.</p><button className="primary-button" onClick={() => navigate("scan")}>Scan a repository</button></div>}</>}
        {activeView === "remediation" && <><section className="workspace-heading"><div><p className="eyebrow">PRIORITIZED ACTIONS</p><h1>Remediation</h1><p>A deterministic, budgeted set of candidate fixes based on this scan's evidence.</p></div>{scanResult && <span className="live-label">HUMAN REVIEW REQUIRED</span>}</section>{remediationPanel}</>}
      </main>
      <SiteFooter onNavigate={navigate} />
    </div>
  </div>;
}

export default App;
