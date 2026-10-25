import subprocess

import pytest

from app.routes import scanners
from app.scanners.gitleaks import GitleaksScanError, scan_with_gitleaks
from app.scanners.osv_scanner import OsvScanError, scan_with_osv
from app.scanners.semgrep_scanner import SemgrepScanError, scan_with_semgrep
from app.core.archive_handler import SourceFile


def test_scanner_availability_includes_verified_versions(monkeypatch):
    executables = {
        "gitleaks": "/tools/gitleaks",
        "semgrep": "/tools/semgrep",
        "osv-scanner": "/tools/osv-scanner",
    }
    versions = {
        "gitleaks": "gitleaks version 8.30.1",
        "semgrep": "1.182.1",
        "osv-scanner": "Version: 1.9.2",
    }
    calls = []

    monkeypatch.setattr(
        scanners.shutil,
        "which",
        lambda command: executables.get(command),
    )

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(
            command,
            0,
            versions[command[0].rsplit("/", 1)[-1]],
            "",
        )

    monkeypatch.setattr(scanners.subprocess, "run", fake_run)

    payload = scanners.get_scanner_status()

    assert payload["available"] == payload["total"] == 3
    assert payload["executed"] == 0
    assert [scanner["version"] for scanner in payload["scanners"]] == list(
        versions.values()
    )
    assert all(scanner["available"] for scanner in payload["scanners"])
    assert all(
        scanner["version"] in scanner["message"]
        for scanner in payload["scanners"]
    )
    assert [call[0][1] for call in calls] == [
        "version",
        "--version",
        "--version",
    ]
    assert all(call[1]["shell"] is False for call in calls)


def test_missing_scanner_executables_are_unavailable_without_running_commands(
    monkeypatch,
):
    monkeypatch.setattr(scanners.shutil, "which", lambda _command: None)

    def unexpected_run(*_args, **_kwargs):
        raise AssertionError("A missing executable must not be run.")

    monkeypatch.setattr(scanners.subprocess, "run", unexpected_run)

    payload = scanners.get_scanner_status()

    assert payload["available"] == 0
    assert payload["executed"] == 0
    assert all(not scanner["available"] for scanner in payload["scanners"])
    assert all(scanner["status"] == "not_installed" for scanner in payload["scanners"])
    assert all(scanner["version"] is None for scanner in payload["scanners"])


@pytest.mark.parametrize(
    "result",
    [
        subprocess.CompletedProcess(["scanner"], 1, "", "version error"),
        subprocess.CompletedProcess(["scanner"], 0, "", ""),
    ],
)
def test_failed_or_empty_version_check_is_unavailable(monkeypatch, result):
    monkeypatch.setattr(
        scanners.shutil,
        "which",
        lambda command: f"/tools/{command}",
    )
    monkeypatch.setattr(
        scanners.subprocess,
        "run",
        lambda *_args, **_kwargs: result,
    )

    payload = scanners.get_scanner_status()

    assert payload["available"] == 0
    assert all(not scanner["available"] for scanner in payload["scanners"])
    assert all(scanner["version"] is None for scanner in payload["scanners"])


@pytest.mark.parametrize(
    "error",
    [
        OSError("cannot execute"),
        subprocess.TimeoutExpired(["scanner", "--version"], 5),
    ],
)
def test_version_check_launch_errors_are_unavailable(monkeypatch, error):
    monkeypatch.setattr(
        scanners.shutil,
        "which",
        lambda command: f"/tools/{command}",
    )

    def fail_run(*_args, **_kwargs):
        raise error

    monkeypatch.setattr(scanners.subprocess, "run", fail_run)

    payload = scanners.get_scanner_status()

    assert payload["available"] == 0
    assert all(not scanner["available"] for scanner in payload["scanners"])
    assert all(scanner["version"] is None for scanner in payload["scanners"])


@pytest.mark.parametrize(
    ("scanner_id", "scanner_error", "scan"),
    [
        ("gitleaks", GitleaksScanError, scan_with_gitleaks),
        ("semgrep", SemgrepScanError, scan_with_semgrep),
    ],
)
def test_source_scanner_reports_missing_executable(
    monkeypatch, scanner_id, scanner_error, scan
):
    if scanner_id == "gitleaks":
        monkeypatch.setattr("app.scanners.gitleaks.shutil.which", lambda _name: None)
    else:
        monkeypatch.setattr("app.scanners.semgrep_scanner.shutil.which", lambda _name: None)
        monkeypatch.setattr(
            "app.scanners.semgrep_scanner.Path.is_file",
            lambda _path: False,
        )

    with pytest.raises(scanner_error):
        scan([])


def test_osv_reports_missing_executable(monkeypatch):
    monkeypatch.setattr(
        "app.scanners.osv_scanner._find_osv_executable",
        lambda: None,
    )

    with pytest.raises(OsvScanError):
        scan_with_osv([
            SourceFile("requirements.txt", "sample==1.0\n", 1)
        ])


def test_gitleaks_nonzero_exit_is_a_scan_error(monkeypatch):
    monkeypatch.setattr(
        "app.scanners.gitleaks.shutil.which",
        lambda _name: "/tools/gitleaks",
    )
    monkeypatch.setattr(
        "app.scanners.gitleaks.subprocess.run",
        lambda command, **_kwargs: subprocess.CompletedProcess(
            command, 2, "", "scanner failed"
        ),
    )

    with pytest.raises(GitleaksScanError, match="exited with an error"):
        scan_with_gitleaks([
            SourceFile("sample.py", "value = 1\n", 1)
        ])


def test_semgrep_missing_report_is_a_scan_error(monkeypatch):
    monkeypatch.setattr(
        "app.scanners.semgrep_scanner.shutil.which",
        lambda _name: "/tools/semgrep",
    )
    monkeypatch.setattr(
        "app.scanners.semgrep_scanner.subprocess.run",
        lambda command, **_kwargs: subprocess.CompletedProcess(
            command, 0, "", ""
        ),
    )

    with pytest.raises(SemgrepScanError, match="did not produce its JSON report"):
        scan_with_semgrep([
            SourceFile("sample.py", "value = 1\n", 1)
        ])


def test_osv_missing_report_is_a_scan_error(monkeypatch):
    monkeypatch.setattr(
        "app.scanners.osv_scanner._find_osv_executable",
        lambda: "/tools/osv-scanner",
    )
    monkeypatch.setattr(
        "app.scanners.osv_scanner.subprocess.run",
        lambda command, **_kwargs: subprocess.CompletedProcess(
            command, 1, "", "scanner failed"
        ),
    )

    with pytest.raises(OsvScanError, match="did not produce a JSON report"):
        scan_with_osv([
            SourceFile("requirements.txt", "sample==1.0\n", 1)
        ])
