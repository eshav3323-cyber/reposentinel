
import json
import shutil
import subprocess
import tempfile
from pathlib import Path, PurePosixPath

from app.core.archive_handler import SourceFile
from app.core.finding_normalizer import normalize_finding
from app.models.findings import Finding


class GitleaksScanError(RuntimeError):
    """Raised when Gitleaks cannot complete a scan safely."""


def scan_with_gitleaks(
    files: list[SourceFile],
    timeout_seconds: int = 60,
) -> list[Finding]:
    """Scan validated source files with Gitleaks without executing them."""

    executable = shutil.which("gitleaks")
    if not executable:
        raise GitleaksScanError(
            "Gitleaks is not available on the backend PATH."
        )

    findings: list[Finding] = []

    try:
        with tempfile.TemporaryDirectory(prefix="reposentinel-") as temp:
            root = Path(temp) / "source"
            root.mkdir()
            report_path = Path(temp) / "gitleaks-report.json"

            for source_file in files:
                relative = PurePosixPath(source_file.path)

                # Defense in depth: never write outside the temporary root.
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
                "dir",
                str(root),
                "--report-format",
                "json",
                "--report-path",
                str(report_path),
                "--exit-code",
                "0",
                "--no-banner",
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
                raise GitleaksScanError(
                    f"Gitleaks exceeded the {timeout_seconds}-second timeout."
                ) from exc
            except OSError as exc:
                raise GitleaksScanError(
                    "The Gitleaks process could not be started."
                ) from exc

            if completed.returncode != 0:
                raise GitleaksScanError(
                    "Gitleaks exited with an error. Check its installation "
                    "and backend logs."
                )

            if not report_path.exists():
                raise GitleaksScanError(
                    "Gitleaks finished without producing its JSON report."
                )

            # Limit report size before parsing scanner output.
            if report_path.stat().st_size > 5 * 1024 * 1024:
                raise GitleaksScanError(
                    "The Gitleaks report exceeded the 5 MiB safety limit."
                )

            try:
                report = json.loads(report_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise GitleaksScanError(
                    "Gitleaks produced an invalid or unreadable JSON report."
                ) from exc

            if not isinstance(report, list):
                raise GitleaksScanError(
                    "Gitleaks returned an unexpected report format."
                )

            for item in report:
                if not isinstance(item, dict):
                    continue

                raw_path = str(item.get("File") or "")
                relative_path = PurePosixPath(raw_path.replace("\\", "/"))

                # Only accept paths that resolve to files in our source tree.
                if relative_path.is_absolute() or ".." in relative_path.parts:
                    continue

                try:
                    line_number = max(1, int(item.get("StartLine") or 1))
                except (ValueError, TypeError):
                    line_number = 1

                # Never expose raw secrets from Gitleaks output in the UI.
                findings.append(
                    normalize_finding(
                        {
                            "title": str(
                                item.get("Description")
                                or "Potential exposed secret"
                            ),
                            "rule_id": str(
                                item.get("RuleID") or "GITLEAKS-UNSPECIFIED"
                            ),
                            "severity": "high",
                            "file_path": relative_path.as_posix(),
                            "line_number": line_number,
                            "description": (
                                "Gitleaks detected a pattern that may represent "
                                "an exposed secret. Validate it securely; "
                                "the scanner finding is not proof that a "
                                "credential is active."
                            ),
                            "evidence": (
                                "[REDACTED: potential secret detected]"
                            ),
                            "remediation": (
                                "Verify the finding without sharing the secret. "
                                "If genuine, revoke or rotate the credential, "
                                "remove it from the source, and store secrets "
                                "in a secure configuration or secret manager."
                            ),
                            "confidence": "medium",
                        },
                        source_scanner="Gitleaks",
                        detection_type="scanner",
                    )
                )

    except GitleaksScanError:
        raise
    except (OSError, UnicodeError, ValueError) as exc:
        raise GitleaksScanError(
            "Gitleaks could not safely prepare or process the source files."
        ) from exc

    # Keep the final results deterministic and free of duplicate IDs.
    unique = {finding.id: finding for finding in findings}
    return list(unique.values())
