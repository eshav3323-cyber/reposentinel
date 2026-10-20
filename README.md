# RepoSentinel Health

RepoSentinel Health analyzes an authorized repository ZIP with local heuristic checks and any installed Gitleaks, Semgrep, and OSV-Scanner tools. Uploaded code is only read as text and is never executed or installed. Findings and scan history are held in backend memory and are cleared when the backend restarts.

## Run locally

Prerequisites: Python 3.10+ and Node.js 20.19+ (or 22.12+).

In one terminal:

```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

In a second terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open the Vite URL shown in the frontend terminal (normally `http://localhost:5173`). Keep the backend terminal running on port 8000; the frontend calls `http://127.0.0.1:8000` by default and also works when served by a local static preview. Set `VITE_API_BASE_URL` before building if your backend uses another host or port. Heuristic analysis works without external scanner executables; install Gitleaks, Semgrep, and OSV-Scanner and place them on the backend `PATH` to enable those scanners. The dashboard reports scanner availability and partial scans when a tool is unavailable.

## Configuration

- `VITE_API_BASE_URL`: optional frontend API origin, for deployments where frontend and backend are hosted separately. Defaults to `http://127.0.0.1:8000` for local use.
- `CORS_ORIGINS`: optional comma-separated backend origins allowed to call the API directly. Localhost and loopback origins on any port are allowed by default; configure this for non-local deployments.

The upload is limited to 20 MiB, with additional limits on archive entries, extracted size, per-file size, compression ratio, and accepted source file types. Scan results are temporary in-memory records; do not treat this prototype as a persistent production service.

## API

- `GET /` and `GET /api/health`: service status
- `GET /api/scanners`: installed scanner availability
- `POST /api/scans` (multipart field `file`): scan a ZIP archive
- `GET /api/scans/{scan_id}`: scan summary
- `GET /api/scans/{scan_id}/findings`: findings
- `GET /api/scans/{scan_id}/attack-graph`: modeled finding relationships
- `GET /api/scans/{scan_id}/remediation?budget=5`: ranked remediation candidates and a budgeted path-coverage plan (`budget` must be between 1 and 25)

Findings and attack paths are review leads, not proof of exploitability or compromise.


## Backend tests

From the backend directory, install development dependencies into the active virtual environment and run the suite:

```powershell
pip install -r requirements-dev.txt
python -m pytest -q
```
