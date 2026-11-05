
import asyncio
import json
from time import perf_counter
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from uuid import uuid4

from fastapi import APIRouter, Body, File, HTTPException, UploadFile
from pydantic import BaseModel, Field

from app.core.archive_handler import (
    ArchiveValidationError,
    MAX_ARCHIVE_SIZE,
    read_repository_zip,
)
from app.core.scan_storage import (
    initialize_scan_storage,
    save_scan,
    get_scan as get_persisted_scan,
    load_scans,
    MAX_STORED_SCANS,
)
from app.scanners.heuristic import scan_source_files
from app.scanners.gitleaks import (
    GitleaksScanError,
    scan_with_gitleaks,
)
from app.scanners.semgrep_scanner import (
    SemgrepScanError,
    scan_with_semgrep,
)
from app.scanners.osv_scanner import (
    OsvScanError,
    scan_with_osv,
)
from app.models.findings import Finding

router = APIRouter(prefix="/api/scans", tags=["Scans"])

initialize_scan_storage()
SCAN_STORE: dict[str, dict] = load_scans()

SEVERITIES = ("critical", "high", "medium", "low", "info")


class ScanSummary(BaseModel):
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    files_analyzed: int


class ScannerStatus(BaseModel):
    status: str
    findings: int
    error: str | None = None
    unique_findings: int = 0
    duration_ms: int = 0


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    filename: str
    created_at: str
    summary: ScanSummary
    scanner_status: dict[str, ScannerStatus]
    duration_ms: int = 0
    findings: list[Finding] = Field(default_factory=list)
    message: str


def build_summary(findings: list, files_analyzed: int) -> dict:
    counts = dict.fromkeys(SEVERITIES, 0)

    for finding in findings:
        severity = str(finding.severity).lower()
        if severity not in counts:
            severity = "info"
        counts[severity] += 1

    return {
        "total_findings": len(findings),
        **counts,
        "files_analyzed": files_analyzed,
    }


def deduplicate_findings(findings: list) -> list:
    unique = {}

    for finding in findings:
        finding_id = getattr(finding, "id", None) or str(uuid4())
        if finding_id not in unique:
            unique[finding_id] = finding

    return list(unique.values())


def count_unique_by_scanner(findings: list) -> dict[str, int]:
    counts = {
        "heuristic": 0,
        "gitleaks": 0,
        "semgrep": 0,
        "osv": 0,
    }

    aliases = {
        "heuristic": "heuristic",
        "reposentinel heuristic": "heuristic",
        "gitleaks": "gitleaks",
        "semgrep": "semgrep",
        "osv-scanner": "osv",
        "osv": "osv",
    }

    for finding in findings:
        source = str(
            finding.get("source_scanner", "")
            if isinstance(finding, dict)
            else getattr(finding, "source_scanner", "")
        ).strip().lower()

        scanner_name = aliases.get(source)
        if scanner_name:
            counts[scanner_name] += 1

    return counts


class GitHubScanRequest(BaseModel):
    repository_url: str = Field(
        ...,
        min_length=1,
        description="Public GitHub repository URL, for example https://github.com/owner/repo",
    )


def normalize_github_repository_url(raw_url: str) -> tuple[str, str, str | None]:
    candidate = (raw_url or "").strip()
    if not candidate:
        raise ValueError("GitHub repository URL is required.")

    parsed = urlsplit(candidate)
    hostname = (parsed.hostname or "").lower()

    if parsed.scheme.lower() != "https":
        raise ValueError("GitHub repository URL must use HTTPS.")

    if hostname not in {"github.com", "www.github.com"}:
        raise ValueError("Only public GitHub.com repository URLs are supported.")

    if parsed.username or parsed.password:
        raise ValueError("GitHub repository URLs must not include credentials.")

    parts = [segment for segment in parsed.path.split("/") if segment and segment != "."]
    if len(parts) < 2:
        raise ValueError(
            "Enter a GitHub repository URL like https://github.com/owner/repository."
        )

    owner, repo = parts[0], parts[1].removesuffix(".git")
    if not owner or not repo:
        raise ValueError("The GitHub URL does not contain both an owner and repository name.")

    branch_name: str | None = None
    if len(parts) >= 4 and parts[2] in {"tree", "blob", "commit"}:
        branch_name = "/".join(parts[3:])
    elif len(parts) >= 3 and parts[2] in {"tree", "blob", "commit"}:
        branch_name = parts[3] if len(parts) > 3 else None

    return owner, repo, branch_name


def _gitHub_rate_limit_message(status_code: int | None = None, detail: str = "") -> str:
    detail_text = detail.strip()
    if status_code in {403, 429} or "rate limit" in detail_text.lower():
        return (
            "GitHub API rate limit reached while resolving the default branch for "
            "this public repository. Please try again later or use a repository URL "
            "that includes the branch name."
        )
    return "GitHub rate limit reached. Please try again later."


def _github_default_branch(owner: str, repo: str) -> str:
    headers = {
        "User-Agent": "RepoSentinel-Health/1.0",
        "Accept": "application/vnd.github+json",
    }
    api_url = f"https://api.github.com/repos/{owner}/{repo}"
    api_request = Request(api_url, headers=headers)

    try:
        with urlopen(api_request, timeout=30) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        error_text = exc.read().decode("utf-8", errors="replace")
        if exc.code in {403, 429} or "rate limit" in error_text.lower():
            raise ValueError(_gitHub_rate_limit_message(exc.code, error_text)) from exc
        raise ValueError(
            "The GitHub repository could not be accessed. Check the URL and ensure it is public."
        ) from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise ValueError("Unable to reach GitHub to fetch the repository archive.") from exc

    if not isinstance(payload, dict):
        raise ValueError("GitHub repository metadata could not be read.")

    if payload.get("private") is True:
        raise ValueError("Only public GitHub repositories are supported.")

    default_branch = payload.get("default_branch")
    if not default_branch:
        raise ValueError("The GitHub repository has no default branch configured.")

    return str(default_branch)


def _codeload_archive_url(owner: str, repo: str, branch: str) -> str:
    return (
        f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{branch.strip('/')}"
    )


def fetch_public_github_archive(repository_url: str) -> tuple[str, bytes]:
    owner, repo, branch_hint = normalize_github_repository_url(repository_url)
    repo_id = f"{owner}/{repo}"
    headers = {
        "User-Agent": "RepoSentinel-Health/1.0",
        "Accept": "application/vnd.github+json",
    }

    branch_name = branch_hint
    if not branch_name:
        for candidate in ("main", "master"):
            archive_url = _codeload_archive_url(owner, repo, candidate)
            archive_request = Request(archive_url, headers=headers, method="HEAD")
            try:
                with urlopen(archive_request, timeout=20):
                    branch_name = candidate
                    break
            except HTTPError as exc:
                if exc.code not in {404, 410}:
                    raise ValueError(
                        "The public GitHub repository archive could not be downloaded."
                    ) from exc
            except (URLError, TimeoutError, OSError):
                continue

        if not branch_name:
            branch_name = _github_default_branch(owner, repo)

    archive_url = _codeload_archive_url(owner, repo, branch_name)
    archive_request = Request(archive_url, headers=headers)

    try:
        with urlopen(archive_request, timeout=30) as response:
            archive_bytes = response.read()
    except HTTPError as exc:
        error_text = exc.read().decode("utf-8", errors="replace")
        if exc.code in {403, 429} or "rate limit" in error_text.lower():
            raise ValueError(_gitHub_rate_limit_message(exc.code, error_text)) from exc
        raise ValueError(
            "The public GitHub repository archive could not be downloaded."
        ) from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise ValueError(
            "The public GitHub repository archive could not be downloaded."
        ) from exc

    if not archive_bytes:
        raise ValueError("The downloaded GitHub repository archive is empty.")

    return repo_id, archive_bytes


async def run_scan_pipeline(filename: str, source_files: list) -> dict:
    scan_started = perf_counter()
    scanners = [
        ("heuristic", scan_source_files, None),
        ("gitleaks", scan_with_gitleaks, GitleaksScanError),
        ("semgrep", scan_with_semgrep, SemgrepScanError),
        ("osv", scan_with_osv, OsvScanError),
    ]

    async def run_scanner(name, scan_function, _expected_error):
        started = perf_counter()
        try:
            results = await asyncio.to_thread(scan_function, source_files)
            return name, results, {
                "status": "completed",
                "findings": len(results),
                "error": None,
                "duration_ms": round((perf_counter() - started) * 1000),
            }
        except Exception as exc:
            error_message = str(exc).strip()
            return name, [], {
                "status": "failed",
                "findings": 0,
                "error": (
                    f"{type(exc).__name__}: {error_message[:1500]}"
                    if error_message
                    else f"{name} could not complete the scan."
                ),
                "duration_ms": round((perf_counter() - started) * 1000),
            }

    outcomes = await asyncio.gather(*(
        run_scanner(name, function, expected_error)
        for name, function, expected_error in scanners
    ))

    all_findings = []
    scanner_status = {}

    for name, results, status in outcomes:
        all_findings.extend(results)
        scanner_status[name] = status

    findings = deduplicate_findings(all_findings)
    unique_counts = count_unique_by_scanner(findings)

    for name, status in scanner_status.items():
        status["unique_findings"] = unique_counts.get(name, 0)

    failures = [
        name for name, status in scanner_status.items()
        if status["status"] != "completed"
    ]

    scan_status = "partial" if failures else "completed"
    message = (
        "Partial analysis: one or more scanners failed. "
        "Review scanner_status before relying on these results."
        if failures
        else (
            "Heuristic, Gitleaks, Semgrep, and OSV-Scanner analysis "
            "completed. Findings require human review."
        )
    )

    scan_id = str(uuid4())
    created_at = datetime.now(timezone.utc).isoformat()

    result = {
        "scan_id": scan_id,
        "status": scan_status,
        "filename": filename,
        "created_at": created_at,
        "summary": build_summary(findings, len(source_files)),
        "scanner_status": scanner_status,
        "duration_ms": round((perf_counter() - scan_started) * 1000),
        "findings": [finding.model_dump() for finding in findings],
        "message": message,
    }

    try:
        await asyncio.to_thread(save_scan, result)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Unable to save scan results to persistent storage.",
        ) from exc

    SCAN_STORE[scan_id] = result
    while len(SCAN_STORE) > MAX_STORED_SCANS:
        SCAN_STORE.pop(next(iter(SCAN_STORE)))

    return result


@router.post("", response_model=ScanResponse)
async def scan_repository(file: UploadFile = File(...)):
    filename = file.filename or ""

    if not filename.lower().endswith(".zip"):
        await file.close()
        raise HTTPException(
            status_code=415,
            detail="Only ZIP archives are supported.",
        )

    try:
        archive_bytes = await file.read(MAX_ARCHIVE_SIZE + 1)
    finally:
        await file.close()

    if not archive_bytes:
        raise HTTPException(
            status_code=400,
            detail="The uploaded ZIP file is empty.",
        )

    if len(archive_bytes) > MAX_ARCHIVE_SIZE:
        raise HTTPException(
            status_code=413,
            detail="The ZIP archive exceeds the 20 MB limit.",
        )

    try:
        source_files = await asyncio.to_thread(
            read_repository_zip, archive_bytes
        )
    except ArchiveValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return await run_scan_pipeline(filename, source_files)


@router.post("/github", response_model=ScanResponse)
async def scan_repository_from_github(
    payload: GitHubScanRequest = Body(...),
):
    try:
        repo_id, archive_bytes = await asyncio.to_thread(
            fetch_public_github_archive,
            payload.repository_url,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        source_files = await asyncio.to_thread(
            read_repository_zip,
            archive_bytes,
        )
    except ArchiveValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return await run_scan_pipeline(repo_id, source_files)


def find_scan(scan_id: str) -> dict | None:
    """Read the cache first, then SQLite if the scan isn't cached."""
    result = SCAN_STORE.get(scan_id)
    if result is not None:
        return result

    result = get_persisted_scan(scan_id)
    if result is not None:
        SCAN_STORE[scan_id] = result

    return result


@router.get("/{scan_id}")
def get_scan(scan_id: str):
    result = find_scan(scan_id)

    if result is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found. It may have expired or been deleted.",
        )

    return {
        key: value
        for key, value in result.items()
        if key != "findings"
    }


@router.get("/{scan_id}/findings")
def get_scan_findings(scan_id: str):
    result = find_scan(scan_id)

    if result is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found. It may have expired or been deleted.",
        )

    findings = result.get("findings", [])

    return {
        "scan_id": scan_id,
        "total": len(findings),
        "findings": findings,
    }
