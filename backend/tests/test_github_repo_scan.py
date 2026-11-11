import io

from urllib.error import HTTPError

from fastapi.testclient import TestClient

import app.routes.scans as scan_routes
from app.core.archive_handler import SourceFile
from app.main import app

client = TestClient(app)


def test_normalize_public_github_url_accepts_repository_path():
    assert scan_routes.normalize_github_repository_url(
        "https://github.com/example/demo/tree/main"
    ) == ("example", "demo", "main")


def test_normalize_public_github_url_handles_branch_names_with_slashes():
    assert scan_routes.normalize_github_repository_url(
        "https://github.com/example/demo/tree/feature/health-check"
    ) == ("example", "demo", "feature/health-check")


def test_public_github_route_rejects_non_github_hosts():
    response = client.post(
        "/api/scans/github",
        json={"repository_url": "https://gitlab.com/example/demo"},
    )

    assert response.status_code == 400
    assert "GitHub.com" in response.json()["detail"]


def test_public_github_route_rejects_invalid_repository_url():
    response = client.post(
        "/api/scans/github",
        json={"repository_url": "https://github.com/example"},
    )

    assert response.status_code == 400
    assert "github repository url" in response.json()["detail"].lower()


def test_fetch_public_github_archive_uses_codeload_for_branch_in_url(monkeypatch):
    requests = []

    def fake_urlopen(request, timeout=30):
        requests.append((request.full_url, request.get_method()))
        return io.BytesIO(b"archive-bytes")

    monkeypatch.setattr(scan_routes, "urlopen", fake_urlopen)

    repo_id, archive_bytes = scan_routes.fetch_public_github_archive(
        "https://github.com/example/demo/tree/release/1.0"
    )

    assert repo_id == "example/demo"
    assert archive_bytes == b"archive-bytes"
    assert any(
        "codeload.github.com/example/demo/zip/refs/heads/release/1.0" in url
        for url, _ in requests
    )
    assert not any("api.github.com/repos/example/demo" in url for url, _ in requests)


def test_fetch_public_github_archive_falls_back_to_default_branch(monkeypatch):
    calls = []

    def fake_urlopen(request, timeout=30):
        calls.append((request.full_url, request.get_method()))
        if request.full_url == "https://api.github.com/repos/example/demo":
            return io.BytesIO(b'{"default_branch":"develop"}')
        if request.full_url == "https://codeload.github.com/example/demo/zip/refs/heads/develop":
            return io.BytesIO(b"archive-bytes")
        if request.full_url in {
            "https://codeload.github.com/example/demo/zip/refs/heads/main",
            "https://codeload.github.com/example/demo/zip/refs/heads/master",
        }:
            raise HTTPError(
                request.full_url,
                404,
                "Not Found",
                hdrs=None,
                fp=io.BytesIO(b"{}"),
            )
        raise AssertionError(f"Unexpected URL: {request.full_url}")

    monkeypatch.setattr(scan_routes, "urlopen", fake_urlopen)

    repo_id, archive_bytes = scan_routes.fetch_public_github_archive(
        "https://github.com/example/demo"
    )

    assert repo_id == "example/demo"
    assert archive_bytes == b"archive-bytes"
    assert any("api.github.com/repos/example/demo" in url for url, _ in calls)
    assert any("codeload.github.com/example/demo/zip/refs/heads/develop" in url for url, _ in calls)


def test_fetch_public_github_archive_reports_rate_limit(monkeypatch):
    def fake_urlopen(request, timeout=30):
        if request.full_url in {
            "https://codeload.github.com/example/demo/zip/refs/heads/main",
            "https://codeload.github.com/example/demo/zip/refs/heads/master",
        }:
            raise HTTPError(
                request.full_url,
                404,
                "Not Found",
                hdrs=None,
                fp=io.BytesIO(b"{}"),
            )
        if request.full_url == "https://api.github.com/repos/example/demo":
            raise HTTPError(
                request.full_url,
                403,
                "rate limit exceeded",
                hdrs=None,
                fp=io.BytesIO(b'{"message":"API rate limit exceeded"}'),
            )
        raise AssertionError(f"Unexpected URL: {request.full_url}")

    monkeypatch.setattr(scan_routes, "urlopen", fake_urlopen)

    try:
        scan_routes.fetch_public_github_archive("https://github.com/example/demo")
        assert False, "Expected a ValueError for the GitHub rate limit"
    except ValueError as exc:
        message = str(exc)
        assert "rate limit" in message.lower()
        assert "try again later" in message.lower()


def test_scan_repository_from_github_uses_downloaded_archive(monkeypatch):
    captured = {}

    def fake_fetch_public_github_archive(repository_url):
        captured["repository_url"] = repository_url
        return ("example/demo", b"archive-bytes")

    def fake_read_repository_zip(archive_bytes):
        assert archive_bytes == b"archive-bytes"
        return [
            SourceFile(
                path="config.py",
                content="DEBUG = True\n",
                line_count=1,
            )
        ]

    monkeypatch.setattr(scan_routes, "fetch_public_github_archive", fake_fetch_public_github_archive)
    monkeypatch.setattr(scan_routes, "read_repository_zip", fake_read_repository_zip)
    for scanner_name in (
        "scan_with_reposentinel_core",
        "scan_source_files",
        "scan_with_gitleaks",
        "scan_with_semgrep",
        "scan_with_osv",
    ):
        monkeypatch.setattr(scan_routes, scanner_name, lambda _files: [])
    monkeypatch.setattr(scan_routes, "save_scan", lambda _result: None)

    response = client.post(
        "/api/scans/github",
        json={"repository_url": "https://github.com/example/demo"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert captured["repository_url"] == "https://github.com/example/demo"
    assert payload["filename"] == "example/demo"
    assert payload["status"] == "completed"
    assert payload["summary"]["files_analyzed"] >= 1
    assert set(payload["scanner_status"]) == {
        "reposentinel_core",
        "heuristic",
        "gitleaks",
        "semgrep",
        "osv",
    }
