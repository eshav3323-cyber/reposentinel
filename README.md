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

## Deploy the backend to Render

The root `render.yaml` configures the backend as a native Render Python web service with `rootDir: backend`; Docker is not required. Render keeps the Blueprint file at the repository root but runs the service build and start commands relative to `backend/`. The build installs dependencies from `requirements.txt`, creates `.semgrep/` for [Semgrep 1.182.1](https://pypi.org/project/semgrep/1.182.1/), and downloads the official [Gitleaks 8.30.1 Linux x64 release](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1) and [OSV-Scanner 1.9.2 Linux AMD64 release](https://github.com/google/osv-scanner/releases/tag/v1.9.2) into `.tools/`. It verifies each binary against the release SHA-256 before extracting or moving it into the scanner directory. OSV-Scanner 1.x is pinned because the existing adapter consumes its v1 JSON report shape. Semgrep has a separate virtual environment so its pinned dependencies do not conflict with the backend requirements.

The Blueprint sets `PYTHON_VERSION=3.12.12`, the health check path `/api/health`, and `CORS_ORIGINS=https://reposentinel.vercel.app`. The start command adds `.tools/` and `.semgrep/bin/` to `PATH` and launches the existing `app.main:app` on `0.0.0.0:$PORT` from the `backend/` service root.

To apply this configuration to the existing Render service, keep the root-level Blueprint path at `render.yaml` and set the service Root Directory to `backend/` (also declared as `rootDir: backend` in the Blueprint). Use **Python 3**, the build and start commands shown below, `PYTHON_VERSION=3.12.12`, `CORS_ORIGINS=https://reposentinel.vercel.app`, and health check path `/api/health`. Preserve the existing service plan, region, and other settings unless you intend to change them. If the existing service is already managed by this Blueprint, sync it. If it is not Blueprint-managed, update the existing service's settings in the dashboard; do not create a new Blueprint/service just to apply these commands.

**Build command** (same command configured in `render.yaml`, run from `backend/`):

```sh
set -eu
trap 'rm -f /tmp/gitleaks_8.30.1_linux_x64.tar.gz /tmp/osv-scanner_linux_amd64' EXIT
python -m pip install -r requirements.txt
python -m venv .semgrep
.semgrep/bin/python -m pip install --no-cache-dir semgrep==1.182.1
mkdir -p .tools
curl --fail --location --silent --show-error https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz --output /tmp/gitleaks_8.30.1_linux_x64.tar.gz
printf '%s  %s\n' 551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb /tmp/gitleaks_8.30.1_linux_x64.tar.gz | sha256sum --check -
tar --extract --gzip --file /tmp/gitleaks_8.30.1_linux_x64.tar.gz --directory .tools gitleaks
curl --fail --location --silent --show-error https://github.com/google/osv-scanner/releases/download/v1.9.2/osv-scanner_linux_amd64 --output /tmp/osv-scanner_linux_amd64
printf '%s  %s\n' d6af4b67fa5de658598bd2d445efb99e90d1734b3146962418719c4350ecb74b /tmp/osv-scanner_linux_amd64 | sha256sum --check -
mv /tmp/osv-scanner_linux_amd64 .tools/osv-scanner
chmod 0755 .tools/gitleaks .tools/osv-scanner
```

**Start command:**

```sh
PATH="$PWD/.tools:$PWD/.semgrep/bin:$PATH" exec uvicorn app.main:app --host 0.0.0.0 --port "$PORT"
```

No scanner installation or credentials are required from website users. `GET /api/scanners` checks each installed executable by running its version command; an executable that is missing, fails to start, times out, or returns an unsuccessful/empty version response is reported as unavailable. Scanner findings still come only from the real scan reports; scanner failures are not reported as successful scans.

OSV-Scanner queries OSV.dev for vulnerability data during dependency scans, so the Render service needs outbound HTTPS connectivity to OSV.dev. If the lookup or scanner command fails, the scan is reported as failed/partial rather than returning fabricated vulnerability results.

## API

- `GET /` and `GET /api/health`: service status
- `GET /api/scanners`: scanner executable and version availability
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
