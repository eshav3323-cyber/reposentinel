import { useEffect, useState } from "react";
import ScannerStatus from "./components/ScannerStatus";
import {
  getBackendStatus,
  getHealthStatus,
  uploadRepository,
  getScanFindings,
} from "./services/api";
import "./App.css";

function App() {
  const [backend, setBackend] = useState(null);
  const [health, setHealth] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  const [selectedFile, setSelectedFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [scanError, setScanError] = useState("");
  const [scanResult, setScanResult] = useState(null);
  const [findings, setFindings] = useState([]);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [severityFilter, setSeverityFilter] = useState("all");

  async function loadBackend() {
    try {
      setLoading(true);
      setError("");

      const [backendData, healthData] = await Promise.all([
        getBackendStatus(),
        getHealthStatus(),
      ]);

      setBackend(backendData);
      setHealth(healthData);
    } catch {
      setError(
        "Cannot connect to the backend. Check that FastAPI is running on port 8000."
      );
      setBackend(null);
      setHealth(null);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadBackend();
  }, []);

  function handleFileChange(event) {
    const file = event.target.files?.[0];

    setScanError("");
    setScanResult(null);
    setFindings([]);
    setSeverityFilter("all");

    if (!file) {
      setSelectedFile(null);
      return;
    }

    if (!file.name.toLowerCase().endsWith(".zip")) {
      setSelectedFile(null);
      setScanError("Please choose a repository ZIP file.");
      event.target.value = "";
      return;
    }

    if (file.size > 20 * 1024 * 1024) {
      setSelectedFile(null);
      setScanError("The ZIP file must be 20 MB or smaller.");
      event.target.value = "";
      return;
    }

    setSelectedFile(file);
  }

  async function handleScanSubmit(event) {
    event.preventDefault();

    if (!selectedFile || uploading) {
      return;
    }

    setUploading(true);
    setScanError("");
    setScanResult(null);
    setFindings([]);

    try {
      const result = await uploadRepository(selectedFile);
      setScanResult(result);

      setFindingsLoading(true);
      const findingsResult = await getScanFindings(result.scan_id);
      setFindings(findingsResult.findings || []);
    } catch (err) {
      setScanError(err.message || "The repository scan failed.");
    } finally {
      setUploading(false);
      setFindingsLoading(false);
    }
  }

  const summary = scanResult?.summary;

  const visibleFindings =
    severityFilter === "all"
      ? findings
      : findings.filter(
          (finding) =>
            finding.severity?.toLowerCase() === severityFilter
        );

  function formatSeverity(severity) {
    return severity ? severity.toUpperCase() : "UNKNOWN";
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="/">
          <span className="brand-icon">RS</span>
          <span>
            <strong>RepoSentinel</strong>
            <small>HEALTH SECURITY PLATFORM</small>
          </span>
        </a>

        <div className="environment">
          <span className={`status-dot ${backend ? "online" : ""}`} />
          LOCAL DEVELOPMENT
        </div>
      </header>

      <main className="dashboard">
        <section className="welcome">
          <div>
            <p className="eyebrow">SECURITY OPERATIONS CENTER</p>
            <h1>Healthcare Security Dashboard</h1>
            <p className="subtitle">
              Discover potential weaknesses, review repository findings,
              and prioritize practical security improvements.
            </p>
          </div>

          <div className="shield" aria-hidden="true">
            ⬡
          </div>
        </section>

        {error && (
          <div className="error-banner" role="alert">
            <strong>Connection error</strong>
            <p>{error}</p>
            <button
              onClick={loadBackend}
              className="retry-button"
              disabled={loading}
            >
              {loading ? "Connecting..." : "Retry connection"}
            </button>
          </div>
        )}

        <section className="section-heading">
          <div>
            <h2>Platform overview</h2>
            <p>Live connectivity and scan activity</p>
          </div>
          <span className="live-label">LIVE STATUS</span>
        </section>

        <section className="status-grid">
          <article className="status-card">
            <div className="card-top">
              <span>Backend API</span>
              <span className="card-icon">⌘</span>
            </div>
            <h3>{loading ? "Checking..." : backend ? "Connected" : "Offline"}</h3>
            <p>{backend?.name || "Waiting for FastAPI"}</p>
            <span className={`pill ${backend ? "success" : "pending"}`}>
              {backend ? "● ONLINE" : loading ? "● CHECKING" : "● OFFLINE"}
            </span>
          </article>

          <article className="status-card">
            <div className="card-top">
              <span>API Health</span>
              <span className="card-icon">♡</span>
            </div>
            <h3>
              {loading ? "Checking..." : health?.status || "Unavailable"}
            </h3>
            <p>Backend health endpoint</p>
            <span
              className={`pill ${
                health?.status === "healthy" ? "success" : "pending"
              }`}
            >
              {health?.status === "healthy" ? "● HEALTHY" : "● WAITING"}
            </span>
          </article>

          <article className="status-card">
            <div className="card-top">
              <span>Security Scanners</span>
              <span className="card-icon">⌕</span>
            </div>
            <h3>Scanner status</h3>
            <p>External scanner availability is checked separately.</p>
            <span className="pill pending">● CHECK BELOW</span>
          </article>

          <article className="status-card">
            <div className="card-top">
              <span>Current Scan</span>
              <span className="card-icon">▤</span>
            </div>
            <h3>{summary ? summary.total_findings : "—"}</h3>
            <p>
              {summary
                ? `${summary.files_analyzed} files analyzed`
                : "Findings from your latest scan"}
            </p>
            <span className={`pill ${scanResult ? "success" : "pending"}`}>
              {scanResult ? "● SCAN COMPLETED" : "● AWAITING SCAN"}
            </span>
          </article>
        </section>

        <ScannerStatus />

        <section className="section-heading scan-section-heading">
          <div>
            <h2>Repository security scan</h2>
            <p>Upload a ZIP archive of a repository you own or are authorized to test.</p>
          </div>
          <span className="live-label">ZIP · MAX 20 MB</span>
        </section>

        <section className="upload-panel">
          <form onSubmit={handleScanSubmit}>
            <label className="upload-dropzone" htmlFor="repository-zip">
              <span className="upload-icon" aria-hidden="true">↑</span>
              <strong>{selectedFile ? selectedFile.name : "Choose a repository ZIP"}</strong>
              <span>
                {selectedFile
                  ? `${(selectedFile.size / (1024 * 1024)).toFixed(2)} MB selected`
                  : "Select a .zip file from your computer"}
              </span>
              <input
                id="repository-zip"
                type="file"
                accept=".zip,application/zip"
                onChange={handleFileChange}
                disabled={uploading}
              />
            </label>

            <div className="upload-actions">
              <p>Files are analyzed by the local backend. Repository code is not executed.</p>
              <button
                className="primary-button"
                type="submit"
                disabled={!selectedFile || uploading}
              >
                {uploading ? "Scanning repository..." : "Run security scan"}
              </button>
            </div>
          </form>

          {uploading && (
            <div className="progress-message" role="status">
              <span className="loading-spinner" />
              Validating the ZIP archive and checking supported source files...
            </div>
          )}

          {scanError && (
            <div className="scan-error" role="alert">
              <strong>Scan could not be completed</strong>
              <p>{scanError}</p>
            </div>
          )}
        </section>

        {scanResult && summary && (
          <>
            <section className="section-heading">
              <div>
                <h2>Scan summary</h2>
                <p>
                  <strong>{scanResult.filename}</strong>
                  {" · "}
                  {scanResult.message || "Scan completed"}
                </p>
              </div>
              <span className="live-label">COMPLETED</span>
            </section>

            <section className="summary-grid">
              <article className="summary-card total">
                <span>Total findings</span>
                <strong>{summary.total_findings ?? findings.length}</strong>
              </article>
              <article className="summary-card critical">
                <span>Critical</span>
                <strong>{summary.critical ?? 0}</strong>
              </article>
              <article className="summary-card high">
                <span>High</span>
                <strong>{summary.high ?? 0}</strong>
              </article>
              <article className="summary-card medium">
                <span>Medium</span>
                <strong>{summary.medium ?? 0}</strong>
              </article>
              <article className="summary-card low">
                <span>Low</span>
                <strong>{summary.low ?? 0}</strong>
              </article>
              <article className="summary-card info">
                <span>Info</span>
                <strong>{summary.info ?? 0}</strong>
              </article>
            </section>

            <section className="findings-panel">
              <div className="findings-heading">
                <div>
                  <h2>Security findings</h2>
                  <p>
                    Potential issues identified by the current heuristic rules.
                  </p>
                </div>

                <label className="filter-control">
                  <span>Severity</span>
                  <select
                    value={severityFilter}
                    onChange={(event) => setSeverityFilter(event.target.value)}
                  >
                    <option value="all">All severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="info">Info</option>
                  </select>
                </label>
              </div>

              {findingsLoading ? (
                <p className="empty-state">Loading findings...</p>
              ) : visibleFindings.length === 0 ? (
                <div className="empty-state">
                  <strong>No findings in this view</strong>
                  <p>
                    No matching findings were returned. This does not prove
                    the repository is free of security issues.
                  </p>
                </div>
              ) : (
                <div className="findings-list">
                  {visibleFindings.map((finding) => (
                    <article className="finding-card" key={finding.id}>
                      <div className="finding-topline">
                        <span
                          className={`severity-badge severity-${(
                            finding.severity || "info"
                          ).toLowerCase()}`}
                        >
                          {formatSeverity(finding.severity)}
                        </span>
                        <span className="finding-rule">
                          {finding.rule_id}
                        </span>
                        <span className="finding-confidence">
                          Confidence: {finding.confidence || "unknown"}
                        </span>
                      </div>

                      <h3>{finding.title}</h3>
                      <p className="finding-description">
                        {finding.description}
                      </p>

                      <div className="finding-location">
                        <code>
                          {finding.file_path}
                          {finding.line_number
                            ? `:${finding.line_number}`
                            : ""}
                        </code>
                        <span>{finding.source_scanner}</span>
                      </div>

                      {finding.redacted_evidence && (
                        <div className="evidence-block">
                          <span>Redacted evidence</span>
                          <code>{finding.redacted_evidence}</code>
                        </div>
                      )}

                      {finding.remediation && (
                        <div className="remediation-block">
                          <strong>Suggested remediation</strong>
                          <p>{finding.remediation}</p>
                        </div>
                      )}

                      <p className="finding-disclaimer">
                        Detection type: {finding.detection_type || "unknown"}.
                        Review this result manually before treating it as a confirmed vulnerability.
                      </p>
                    </article>
                  ))}
                </div>
              )}
            </section>
          </>
        )}

        <section className="next-panel">
          <div className="next-icon">✓</div>
          <div>
            <p className="eyebrow">BUILD PROGRESS</p>
            <h2>
              {backend && health?.status === "healthy"
                ? scanResult
                  ? "Repository scan completed"
                  : "Foundation is connected"
                : "Establishing connection"}
            </h2>
            <p>
              {backend && health?.status === "healthy"
                ? scanResult
                  ? "Your uploaded archive was processed by the backend. Findings are heuristic indicators and require review."
                  : "The React dashboard is receiving real responses from your Python backend. Upload an authorized test repository to begin."
                : "Start the FastAPI server and check the connection."}
            </p>
          </div>
        </section>

        <footer className="dashboard-footer">
          <span>RepoSentinel Health · Version 0.1.0</span>
          <span>Defensive security research · Local development</span>
        </footer>
      </main>
    </div>
  );
}

export default App;
