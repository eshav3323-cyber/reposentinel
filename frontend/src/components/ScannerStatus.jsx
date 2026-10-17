
import { useEffect, useState } from "react";
import { getScannerStatus } from "../services/api";

export default function ScannerStatus() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getScannerStatus()
      .then(setData)
      .catch(() => {
        setError("Could not load scanner availability from the backend.");
      })
      .finally(() => setLoading(false));
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

      {loading && <p className="scanner-message">Checking installed tools...</p>}

      {error && (
        <p className="scanner-error" role="alert">
          {error}
        </p>
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
