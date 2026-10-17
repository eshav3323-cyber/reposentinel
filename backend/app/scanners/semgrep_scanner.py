
import json
import shutil
import subprocess
import tempfile
from pathlib import Path, PurePosixPath
import sys

from app.core.archive_handler import SourceFile
from app.core.finding_normalizer import normalize_finding
from app.models.findings import Finding


class SemgrepScanError(RuntimeError):
    """Raised when Semgrep cannot complete a scan."""


RULES_PATH = Path(__file__).with_name("semgrep_rules.yml")


def scan_with_semgrep(
    files: list[SourceFile],
    timeout_seconds: int = 60,
) -> list[Finding]:
    """Run Semgrep with project-owned local rules on validated source files."""

    executable = shutil.which("semgrep")

    if not executable:
        scripts_dir = Path(sys.executable).parent
        candidates = [
            scripts_dir / "semgrep.exe",
            scripts_dir / "semgrep",
        ]
        executable = next(
            (str(path) for path in candidates if path.is_file()),
            None,
        )

    if not executable:
        raise SemgrepScanError(
            "Semgrep executable was not found on PATH or in the backend "
            "Python environment's Scripts directory."
        )

    if not RULES_PATH.is_file():
        raise SemgrepScanError("The local Semgrep rules file is missing.")

    findings: list[Finding] = []

    try:
        with tempfile.TemporaryDirectory(prefix="reposentinel-semgrep-") as temp:
            root = Path(temp) / "source"
            root.mkdir()
            report_path = Path(temp) / "semgrep-report.json"

            for source_file in files:
                relative = PurePosixPath(source_file.path)

                if (
                    relative.is_absolute()
                    or not relative.parts
                    or any(part in ("", ".", "..") for part in relative.parts)
                    or "\\" in source_file.path
                    or ":" in source_file.path
                ):
                    continue

                destination = root.joinpath(*relative.parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(
                    source_file.content,
                    encoding="utf-8",
                    errors="strict",
                )

            command = [
                executable,
                "scan",
                "--config",
                str(RULES_PATH),
                "--json",
                "--output",
                str(report_path),
                "--metrics",
                "off",
                str(root),
            ]

            try:
                completed = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=timeout_seconds,
                    check=False,
                    shell=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise SemgrepScanError(
                    f"Semgrep exceeded the {timeout_seconds}-second timeout."
                ) from exc
            except OSError as exc:
                raise SemgrepScanError(
                    "Semgrep could not be started."
                ) from exc

            # Semgrep may use nonzero exit codes for scan errors or
            # findings, depending on its options/version. Parse the report
            # when available and reject a missing or invalid report.
            if not report_path.is_file():
                raise SemgrepScanError(
                    "Semgrep did not produce its JSON report."
                )

            if report_path.stat().st_size > 5 * 1024 * 1024:
                raise SemgrepScanError(
                    "The Semgrep report exceeded the 5 MiB safety limit."
                )

            try:
                report = json.loads(report_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise SemgrepScanError(
                    "Semgrep produced an invalid JSON report."
                ) from exc

            if not isinstance(report, dict) or not isinstance(
                report.get("results"), list
            ):
                raise SemgrepScanError(
                    "Semgrep returned an unexpected report format."
                )

            errors = report.get("errors", [])
            if errors:
                raise SemgrepScanError(
                    "Semgrep reported scan errors; review the backend logs."
                )

            for item in report["results"]:
                if not isinstance(item, dict):
                    continue

                raw_path = str(item.get("path") or "")
                candidate = Path(raw_path)

                try:
                    if candidate.is_absolute():
                        relative_path = candidate.resolve().relative_to(
                            root.resolve()
                        )
                    else:
                        relative_path = Path(
                            *PurePosixPath(
                                raw_path.replace("\\", "/")
                            ).parts
                        )

                    if (
                        relative_path.is_absolute()
                        or ".." in relative_path.parts
                        or not relative_path.parts
                    ):
                        continue

                except (OSError, ValueError):
                    continue

                start = item.get("start") or {}
                extra = item.get("extra") or {}

                try:
                    line_number = max(1, int(start.get("line") or 1))
                except (ValueError, TypeError, AttributeError):
                    line_number = 1

                severity_map = {
                    "ERROR": "high",
                    "WARNING": "medium",
                    "INFO": "info",
                }
                raw_severity = str(extra.get("severity") or "WARNING").upper()

                findings.append(
                    normalize_finding(
                        {
                            "title": str(
                                extra.get("message")
                                or "Potential code security issue"
                            ),
                            "rule_id": str(
                                item.get("check_id")
                                or "SEMGREP-UNSPECIFIED"
                            ),
                            "severity": severity_map.get(
                                raw_severity, "medium"
                            ),
                            "file_path": relative_path.as_posix(),
                            "line_number": line_number,
                            "description": str(
                                extra.get("message")
                                or "Semgrep matched a configured static-analysis rule."
                            ),
                            # Do not store raw source lines in scan evidence.
                            "evidence": "[Source evidence omitted]",
                            "remediation": (
                                "Review the matching rule and surrounding code. "
                                "Confirm the issue manually before changing "
                                "production code."
                            ),
                            "confidence": "medium",
                        },
                        source_scanner="Semgrep",
                        detection_type="scanner",
                    )
                )

            # A nonzero exit without reported findings/errors is suspicious;
            # don't claim success when Semgrep itself failed.
            if completed.returncode != 0 and not report["results"]:
                raise SemgrepScanError(
                    "Semgrep exited unsuccessfully. Review the backend logs."
                )

    except SemgrepScanError:
        raise
    except (OSError, UnicodeError, ValueError) as exc:
        raise SemgrepScanError(
            "Semgrep could not safely prepare or process the source files."
        ) from exc

    unique = {finding.id: finding for finding in findings}
    return list(unique.values())
