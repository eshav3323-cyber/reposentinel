from fastapi.testclient import TestClient

import app.routes.scans as scan_routes
from app.core.archive_handler import SourceFile
from app.main import app

client = TestClient(app)


def test_normalize_public_github_url_accepts_repository_path():
    assert scan_routes.normalize_github_repository_url(
        "https://github.com/example/demo/tree/main"
    ) == ("example", "demo")


def test_public_github_route_rejects_non_github_hosts():
    response = client.post(
        "/api/scans/github",
        json={"repository_url": "https://gitlab.com/example/demo"},
    )

    assert response.status_code == 400
    assert "GitHub.com" in response.json()["detail"]


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

    response = client.post(
        "/api/scans/github",
        json={"repository_url": "https://github.com/example/demo"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert captured["repository_url"] == "https://github.com/example/demo"
    assert payload["filename"] == "example/demo"
    assert payload["status"] in {"completed", "partial"}
    assert payload["summary"]["files_analyzed"] >= 1
