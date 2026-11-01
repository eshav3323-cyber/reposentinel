  // Local development talks to the backend on localhost. Production builds use
  // a dedicated backend host unless a custom VITE_API_BASE_URL is configured.
  function resolveApiBaseUrl() {
    const configured = import.meta.env.VITE_API_BASE_URL;
    if (configured) return configured.replace(/\/$/, "");

    if (typeof window === "undefined") {
      return "http://127.0.0.1:8000";
    }

    const host = window.location.hostname;
    if (host === "localhost" || host === "127.0.0.1" || host.endsWith(".local")) {
      return "http://127.0.0.1:8000";
    }

    return "https://reposentinel-health.onrender.com";
  }

  const API_BASE_URL = resolveApiBaseUrl();
  const DEFAULT_TIMEOUT_MS = 8000;

  async function request(endpoint, options = {}, timeoutMs = DEFAULT_TIMEOUT_MS) {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), timeoutMs);
    let response;

    try {
      response = await fetch(`${API_BASE_URL}${endpoint}`, {
        ...options,
        signal: controller.signal,
      });
    } catch (error) {
      if (error.name === "AbortError") {
        throw new Error(
          `The backend did not respond within ${Math.ceil(timeoutMs / 1000)} seconds.`,
          { cause: error }
        );
      }
      const backendAddress = API_BASE_URL;
      throw new Error(
        `Cannot reach the backend at ${backendAddress}. Start the backend on port 8000 and retry.`,
        { cause: error }
      );
    } finally {
      window.clearTimeout(timeout);
    }

    let data;

    try {
      data = await response.json();
    } catch {
      data = null;
    }

    if (!response.ok) {
      throw new Error(
        data?.detail || `Request failed with status ${response.status}`
      );
    }

    return data;
  }

  export function getBackendStatus() {
    return request("/api/status");
  }

  export function getHealthStatus() {
    return request("/api/health");
  }

  export function getScannerStatus() {
  return request("/api/scanners", {}, 60000);
}

  export function uploadRepository(file) {
    const formData = new FormData();
    formData.append("file", file);

    return request("/api/scans", {
      method: "POST",
      body: formData,
    }, 180000);
  }

  export function getScanFindings(scanId) {
    return request(
      `/api/scans/${encodeURIComponent(scanId)}/findings`
    );
  }

  export function getAttackGraph(scanId) {
    return request(
      `/api/scans/${encodeURIComponent(scanId)}/attack-graph`
    );
  }

  export function getScanRemediation(scanId, budget = 5) {
    const query = new URLSearchParams({ budget: String(budget) });
    return request(
      `/api/scans/${encodeURIComponent(scanId)}/remediation?${query.toString()}`
    );
  }

  export function getScan(scanId) {
    return request(`/api/scans/${encodeURIComponent(scanId)}`);
  }
