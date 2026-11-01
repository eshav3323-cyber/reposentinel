import { useEffect, useState } from "react";
import { getScannerStatus } from "../services/api";

export default function ScannerStatus() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;

    async function loadScannerStatus() {
      try {
        setLoading(true);
        setError("");

        const response = await getScannerStatus();

        // Support both Axios responses and direct JSON responses.
        const payload = response?.data ?? response;

        // Support either { scanners: [...] } or a direct array.
        const scanners = Array.isArray(payload)
          ? payload
          : payload?.scanners;

        if (!Array.isArray(scanners)) {
          throw new Error("Unexpected scanner API response format.");
        }

        const normalizedScanners = scanners.map((scanner, index) => ({
          ...scanner,
          id: scanner.id ?? scanner.name ?? `scanner-${index}`,
          name: scanner.name ?? scanner.id ?? `Scanner ${index + 1}`,
          purpose: scanner.purpose ?? scanner.description ?? "",
          message: scanner.message ?? scanner.version ?? "",
          available:
          scanner.available === true ||
          scanner.status === "available",
        }));

        const available = normalizedScanners.filter(
          (scanner) => scanner.available
        ).length;

        if (!cancelled) {
          setData({
            scanners: normalizedScanners,
            available: payload?.available ?? available,
            total: payload?.total ?? normalizedScanners.length,
          });
        }
      } catch (err) {
        console.error("Scanner availability request failed:", err);

        if (!cancelled) {
          setError(
            err?.message ||
              "Could not load scanner availability. Check the API connection."
          );
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    loadScannerStatus();

    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <section className="scanner-panel">
      <div className="scanner-heading">
        <div>
          <h2>Security scanners</h2>
          <p>Local tool availability · No scans executed</p>
        </div>

        {data && (
          <span className="scanner-count">
            {data.available}/{data.total} available
          </span>
        )}
      </div>

      {loading && (
        <p className="scanner-message">Checking installed tools...</p>
      )}

      {error && (
        <div className="scanner-error" role="alert">
          <p>{error}</p>
          <button
            type="button"
            onClick={() => window.location.reload()}
          >
            Reload page
          </button>
        </div>
      )}

      {data?.scanners.map((scanner) => (
        <article className="scanner-row" key={scanner.id}>
          <div className="scanner-info">
            <strong>{scanner.name}</strong>
            <p>{scanner.purpose}</p>
            <small>{scanner.message}</small>
          </div>

          <span
            className={`pill ${
              scanner.available ? "success" : "pending"
            }`}
          >
            {scanner.available ? "AVAILABLE" : "NOT INSTALLED"}
          </span>
        </article>
      ))}

      {data && (
        <p className="scanner-disclaimer">
          Availability does not mean a security scan has been performed.
        </p>
      )}
    </section>
  );
}
