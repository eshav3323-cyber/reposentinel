import asyncio
import io
import zipfile

import pytest
from fastapi.testclient import TestClient

import app.routes.scans as scan_routes
from app.core.archive_handler import MAX_ARCHIVE_SIZE, SourceFile
from app.core.finding_normalizer import normalize_finding
from app.main import app


client = TestClient(app)
SCANNER_FUNCTIONS = (
    "scan_with_reposentinel_core",
    "scan_source_files",
    "scan_with_gitleaks",
    "scan_with_semgrep",
    "scan_with_osv",
)


def test_pipeline_invokes_all_scanners_and_zero_findings_succeed(monkeypatch):
    calls = []
    for scanner_name in SCANNER_FUNCTIONS:
        monkeypatch.setattr(
            scan_routes,
            scanner_name,
            lambda _files, name=scanner_name: calls.append(name) or [],
        )
    monkeypatch.setattr(scan_routes, "save_scan", lambda _result: None)

    result = asyncio.run(
        scan_routes.run_scan_pipeline(
            "repository.zip",
            [SourceFile("app.py", "print('safe')\n", 1)],
        )
    )

    assert set(calls) == set(SCANNER_FUNCTIONS)
    assert result["status"] == "completed"
    assert result["summary"]["total_findings"] == 0
    assert set(result["scanner_status"]) == {
        "reposentinel_core",
        "heuristic",
        "gitleaks",
        "semgrep",
        "osv",
    }
    for status in result["scanner_status"].values():
        assert status["status"] == "completed"
        assert status["findings"] == status["unique_findings"] == 0
        assert status["error"] is None
        assert isinstance(status["duration_ms"], int)
        assert status["duration_ms"] >= 0


def test_pipeline_isolates_independent_scanner_failures(monkeypatch):
    calls = []
    for scanner_name in SCANNER_FUNCTIONS:
        def run(_files, name=scanner_name):
            calls.append(name)
            if name in {"scan_with_reposentinel_core", "scan_with_semgrep"}:
                raise RuntimeError(f"{name} failed")
            return []

        monkeypatch.setattr(scan_routes, scanner_name, run)
    monkeypatch.setattr(scan_routes, "save_scan", lambda _result: None)

    result = asyncio.run(
        scan_routes.run_scan_pipeline(
            "repository.zip",
            [SourceFile("app.py", "print('safe')\n", 1)],
        )
    )

    assert set(calls) == set(SCANNER_FUNCTIONS)
    assert result["status"] == "partial"
    assert result["scanner_status"]["reposentinel_core"]["status"] == "failed"
    assert result["scanner_status"]["semgrep"]["status"] == "failed"
    assert result["scanner_status"]["heuristic"]["status"] == "completed"
    assert result["scanner_status"]["gitleaks"]["status"] == "completed"
    assert result["scanner_status"]["osv"]["status"] == "completed"
    assert all(
        isinstance(status["duration_ms"], int)
        for status in result["scanner_status"].values()
    )


def _finding(source_scanner, *, description, remediation, severity="medium"):
    return normalize_finding(
        {
            "title": "Potential hardcoded credential",
            "rule_id": "SHARED-CREDENTIAL",
            "severity": severity,
            "confidence": "medium",
            "file_path": r"src\config.py",
            "line_number": 5,
            "description": description,
            "evidence": "password = [REDACTED]",
            "remediation": remediation,
        },
        source_scanner=source_scanner,
        detection_type="scanner",
    )


def test_deduplication_merges_unique_attribution_and_counts_each_scanner_once():
    first = _finding(
        "Gitleaks, Gitleaks",
        description="Gitleaks description.",
        remediation="Rotate the credential.",
        severity="medium",
    )
    second = _finding(
        "RepoSentinel Core, Semgrep, semgrep",
        description="Core description.",
        remediation="Remove it from source control.",
        severity="high",
    )

    findings = scan_routes.deduplicate_findings([first, second])

    assert len(findings) == 1
    finding = findings[0]
    assert finding.file_path == "src/config.py"
    assert finding.severity == "high"
    assert finding.source_scanner == "Gitleaks, RepoSentinel Core, Semgrep"
    assert "Gitleaks description." in finding.description
    assert "Core description." in finding.description
    assert "Rotate the credential." in finding.remediation
    assert "Remove it from source control." in finding.remediation
    assert scan_routes.count_unique_by_scanner(findings) == {
        "reposentinel_core": 1,
        "heuristic": 0,
        "gitleaks": 1,
        "semgrep": 1,
        "osv": 0,
    }


def test_single_finding_has_unique_scanner_attribution():
    finding = _finding(
        "Gitleaks, gitleaks, Semgrep",
        description="A finding.",
        remediation="Review it.",
    )

    assert finding.source_scanner == "Gitleaks, Semgrep"
    assert scan_routes.count_unique_by_scanner([finding])["gitleaks"] == 1
    assert scan_routes.count_unique_by_scanner([finding])["semgrep"] == 1


def test_deduplication_retains_long_distinct_descriptions_and_remediations():
    first = _finding(
        "Gitleaks",
        description="A" * 450,
        remediation="R" * 450,
    )
    second = _finding(
        "Semgrep",
        description="B" * 450,
        remediation="M" * 450,
    )

    finding = scan_routes.deduplicate_findings([first, second])[0]

    assert "A" * 450 in finding.description
    assert "B" * 450 in finding.description
    assert "R" * 450 in finding.remediation
    assert "M" * 450 in finding.remediation


def test_zip_upload_still_returns_compatible_five_scanner_response(monkeypatch):
    for scanner_name in SCANNER_FUNCTIONS:
        monkeypatch.setattr(scan_routes, scanner_name, lambda _files: [])
    monkeypatch.setattr(scan_routes, "save_scan", lambda _result: None)

    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("app.py", "print('safe')\n")

    response = client.post(
        "/api/scans",
        files={"file": ("repository.zip", archive.getvalue(), "application/zip")},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["filename"] == "repository.zip"
    assert payload["status"] == "completed"
    assert payload["summary"]["files_analyzed"] == 1
    assert set(payload["scanner_status"]) == {
        "reposentinel_core",
        "heuristic",
        "gitleaks",
        "semgrep",
        "osv",
    }


class _DownloadResponse(io.BytesIO):
    def __init__(self, content, content_length=None):
        super().__init__(content)
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = content_length
        self.read_sizes = []

    def read(self, size=-1):
        self.read_sizes.append(size)
        return super().read(size)


@pytest.mark.parametrize("content_length", [None, "1", "invalid"])
def test_github_download_enforces_stream_limit_with_missing_or_misleading_length(
    monkeypatch, content_length
):
    monkeypatch.setattr(scan_routes, "MAX_ARCHIVE_SIZE", 16)
    response = _DownloadResponse(b"x" * 17, content_length)
    monkeypatch.setattr(scan_routes, "urlopen", lambda *_args, **_kwargs: response)

    with pytest.raises(ValueError, match="exceeds"):
        scan_routes.fetch_public_github_archive(
            "https://github.com/example/demo/tree/main"
        )

    assert sum(response.read_sizes) <= 17
    assert all(size <= 17 for size in response.read_sizes)


def test_github_download_rejects_oversized_content_length_without_reading(monkeypatch):
    monkeypatch.setattr(scan_routes, "MAX_ARCHIVE_SIZE", 16)
    response = _DownloadResponse(b"unused", "17")
    monkeypatch.setattr(scan_routes, "urlopen", lambda *_args, **_kwargs: response)

    with pytest.raises(ValueError, match="exceeds"):
        scan_routes.fetch_public_github_archive(
            "https://github.com/example/demo/tree/main"
        )

    assert response.read_sizes == []


def test_github_archive_limit_uses_existing_twenty_mib_configuration():
    assert MAX_ARCHIVE_SIZE == 20 * 1024 * 1024
