
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from app.core.archive_handler import SourceFile
from app.core.finding_normalizer import normalize_finding


MAX_REPORT_SIZE = 5 * 1024 * 1024
OSV_TIMEOUT_SECONDS = 90

DEPENDENCY_FILES = {
    "requirements.txt",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "pyproject.toml",
    "uv.lock",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "Gemfile",
    "Gemfile.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
}


class OsvScanError(RuntimeError):
    """Raised when OSV-Scanner cannot complete a dependency scan."""


def _find_osv_executable() -> str | None:
    """Find OSV-Scanner on PATH."""
    return shutil.which("osv-scanner") or shutil.which("osv-scanner.exe")


def _numeric_score(value: object) -> float | None:
    """Return a numeric CVSS score, never a CVSS vector string."""
    if isinstance(value, (int, float)):
        score = float(value)
        return score if 0 <= score <= 10 else None

    if not isinstance(value, str):
        return None

    text = value.strip()

    # A vector such as CVSS:4.0/AV:N/... is not a numeric score.
    if text.upper().startswith("CVSS:"):
        return None

    try:
        score = float(text)
    except ValueError:
        return None

    return score if 0 <= score <= 10 else None


def _severity_from_osv(vulnerability: dict) -> str:
    """Map numeric CVSS scores to the shared severity scale."""
    for item in vulnerability.get("severity") or []:
        if not isinstance(item, dict):
            continue

        score = _numeric_score(item.get("score"))
        if score is None:
            continue

        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        return "low"

    # OSV may provide a CVSS vector without a numeric score.
    # Do not pretend that a vector alone establishes severity.
    database_specific = vulnerability.get("database_specific") or {}
    severity = str(database_specific.get("severity") or "").lower()

    if severity in {"critical", "high", "medium", "low"}:
        return severity

    return "medium"


def _first_text(*values: object) -> str:
    """Return the first nonempty string."""
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _aliases(vulnerability: dict) -> list[str]:
    """Collect normalized vulnerability IDs and aliases."""
    values = [vulnerability.get("id")]
    values.extend(vulnerability.get("aliases") or [])

    result = []
    seen = set()

    for value in values:
        if not isinstance(value, str):
            continue

        value = value.strip().upper()
        if value and value not in seen:
            seen.add(value)
            result.append(value)

    return result


def _deduplication_key(
    vulnerability: dict,
    package_name: str,
    package_version: str,
    ecosystem: str,
) -> str:
    """
    Use shared aliases to merge alternate IDs for the same advisory.
    Scope the key to the affected package, version, and ecosystem.
    """
    aliases = _aliases(vulnerability)
    advisory = min(aliases) if aliases else "OSV-UNKNOWN"

    return "|".join(
        (
            ecosystem.lower(),
            package_name.lower(),
            package_version,
            advisory,
        )
    )


def scan_with_osv(source_files: list[SourceFile]) -> list:
    """
    Scan dependency manifests and lockfiles with OSV-Scanner.

    Only validated dependency text files are written to a temporary
    directory. Uploaded application code is never executed or installed.
    """
    candidates = [
        item
        for item in source_files
        if Path(item.path).name in DEPENDENCY_FILES
    ]

    if not candidates:
        return []

    executable = _find_osv_executable()
    if not executable:
        raise OsvScanError(
            "OSV-Scanner was not found. Check that it is installed "
            "and available on the backend PATH."
        )

    findings = []
    seen = set()

    with tempfile.TemporaryDirectory(prefix="reposentinel-osv-") as temp:
        root = Path(temp).resolve()

        for item in candidates:
            relative = Path(item.path)

            if relative.is_absolute() or ".." in relative.parts:
                raise OsvScanError(
                    "A dependency file had an unsafe relative path."
                )

            destination = (root / relative).resolve()

            if root not in destination.parents:
                raise OsvScanError(
                    "A dependency file resolved outside the temporary directory."
                )

            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(item.content, encoding="utf-8")

        # Keep the report outside the scanned directory.
        report_handle = tempfile.NamedTemporaryFile(
            prefix="reposentinel-osv-",
            suffix=".json",
            delete=False,
        )
        report_path = Path(report_handle.name)
        report_handle.close()
        report_path.unlink(missing_ok=True)

        command = [
            executable,
            "scan",
            "source",
            "--recursive",
            "--format",
            "json",
            "--output-file",
            str(report_path),
            str(root),
        ]

        try:
            try:
                completed = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=OSV_TIMEOUT_SECONDS,
                    check=False,
                    shell=False,
                    cwd=str(root),
                )
            except subprocess.TimeoutExpired as exc:
                raise OsvScanError(
                    "OSV-Scanner timed out while checking dependencies."
                ) from exc
            except OSError as exc:
                raise OsvScanError(
                    "OSV-Scanner could not be started."
                ) from exc

            if not report_path.is_file():
                detail = (completed.stderr or completed.stdout or "").strip()
                detail = detail[-1000:]
                raise OsvScanError(
                    "OSV-Scanner did not produce a JSON report."
                    + (f" Scanner output: {detail}" if detail else "")
                )

            try:
                if report_path.stat().st_size > MAX_REPORT_SIZE:
                    raise OsvScanError(
                        "OSV-Scanner report exceeded the size limit."
                    )

                report = json.loads(
                    report_path.read_text(encoding="utf-8")
                )
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise OsvScanError(
                    "OSV-Scanner produced an unreadable JSON report."
                ) from exc

            if not isinstance(report, dict):
                raise OsvScanError(
                    "OSV-Scanner returned an unexpected report format."
                )

            results = report.get("results", [])
            if not isinstance(results, list):
                raise OsvScanError(
                    "OSV-Scanner report has an invalid results field."
                )

            # A nonzero exit code can accompany findings. A missing or
            # malformed report is handled separately above.
            if completed.returncode != 0 and not results:
                detail = (completed.stderr or completed.stdout or "").strip()
                raise OsvScanError(
                    "OSV-Scanner did not complete successfully."
                    + (f" Scanner output: {detail[-1000:]}" if detail else "")
                )

            for result in results:
                if not isinstance(result, dict):
                    continue

                source = result.get("source") or {}
                source_path = _first_text(
                    source.get("path") if isinstance(source, dict) else "",
                    result.get("sourcePath"),
                    "dependency manifest",
                )

                packages = result.get("packages") or []
                if not isinstance(packages, list):
                    continue

                for package in packages:
                    if not isinstance(package, dict):
                        continue

                    package_info = package.get("package") or {}
                    if not isinstance(package_info, dict):
                        continue

                    package_name = _first_text(
                        package_info.get("name"), "unknown package"
                    )
                    package_version = _first_text(
                        package_info.get("version"), "unknown"
                    )
                    ecosystem = _first_text(
                        package_info.get("ecosystem"), "unknown"
                    )

                    vulnerabilities = package.get("vulnerabilities") or []
                    if not isinstance(vulnerabilities, list):
                        continue

                    for vulnerability in vulnerabilities:
                        if not isinstance(vulnerability, dict):
                            continue

                        vuln_id = _first_text(
                            vulnerability.get("id"), "OSV-UNKNOWN"
                        )
                        aliases = _aliases(vulnerability)

                        dedup_key = _deduplication_key(
                            vulnerability,
                            package_name,
                            package_version,
                            ecosystem,
                        )

                        if dedup_key in seen:
                            continue
                        seen.add(dedup_key)

                        summary = _first_text(
                            vulnerability.get("summary"),
                            vulnerability.get("details"),
                            f"Known vulnerability affecting {package_name}.",
                        )

                        # Prevent extremely long advisory text in the UI.
                        summary = summary[:1200]

                        alias_text = (
                            ", ".join(aliases[:8])
                            if aliases
                            else vuln_id
                        )

                        raw_finding = {
                            "title": f"{vuln_id}: {package_name}",
                            "rule_id": vuln_id,
                            "severity": _severity_from_osv(vulnerability),
                            "file_path": source_path,
                            "line_number": 1,
                            "description": (
                                f"{summary} "
                                f"Package: {package_name} "
                                f"Version: {package_version}. "
                                f"Ecosystem: {ecosystem}. "
                                f"Related advisory IDs: {alias_text}."
                            ),
                            "evidence": (
                                f"Dependency: {package_name} "
                                f"Version: {package_version}"
                            ),
                            "remediation": (
                                "Review the OSV advisory and determine whether "
                                "this installed version is affected. Upgrade "
                                "to a fixed version when available, then verify "
                                "compatibility and retest the application."
                            ),
                            "confidence": "high",
                        }

                        findings.append(
                            normalize_finding(
                                raw_finding,
                                source_scanner="OSV-Scanner",
                                detection_type="scanner",
                            )
                        )

        finally:
            try:
                report_path.unlink(missing_ok=True)
            except OSError:
                pass

    return findings
