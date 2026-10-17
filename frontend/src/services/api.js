const API_BASE_URL = "http://localhost:8000";

async function request(endpoint, options = {}) {
  const response = await fetch(`${API_BASE_URL}${endpoint}`, options);

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
  return request("/");
}

export function getHealthStatus() {
  return request("/api/health");
}

export function getScannerStatus() {
  return request("/api/scanners");
}

export function uploadRepository(file) {
  const formData = new FormData();
  formData.append("file", file);

  return request("/api/scans", {
    method: "POST",
    body: formData,
  });
}

export function getScanFindings(scanId) {
  return request(`/api/scans/${encodeURIComponent(scanId)}/findings`);
}
