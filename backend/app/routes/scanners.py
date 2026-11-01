
import os
import shutil
import subprocess
import sys
from pathlib import Path

from fastapi import APIRouter

router = APIRouter(prefix="/api", tags=["Scanners"])

VERSION_CHECK_TIMEOUT_SECONDS = 15

BACKEND_DIR = Path(__file__).resolve().parents[2]
TOOLS_DIR = BACKEND_DIR / ".tools"
SEMGREP_DIR = BACKEND_DIR / ".semgrep"

SCANNER_DEFINITIONS = (
    {
        "id": "gitleaks",
        "name": "Gitleaks",
        "purpose": "Detects potential secrets in source repositories.",
        "commands": ["gitleaks"],
        "version_args": ["version"],
    },
    {
        "id": "semgrep",
        "name": "Semgrep",
        "purpose": "Performs static analysis using security rules.",
        "commands": ["semgrep"],
        "version_args": ["--version"],
    },
    {
        "id": "osv-scanner",
        "name": "OSV-Scanner",
        "purpose": "Checks supported dependency manifests for known vulnerabilities.",
        "commands": ["osv-scanner"],
        "version_args": ["--version"],
    },
)


def _find_executable(scanner_id: str, commands: list[str]):
    """Find scanner executables in PATH and known installation directories."""
    for command in commands:
        found = shutil.which(command)
        if found:
            return found

    if scanner_id == "semgrep":
        candidates = [
            SEMGREP_DIR / "bin" / "semgrep",
            SEMGREP_DIR / "Scripts" / "semgrep.exe",
        ]
    elif scanner_id == "gitleaks":
        candidates = [TOOLS_DIR / "gitleaks"]
    elif scanner_id == "osv-scanner":
        candidates = [TOOLS_DIR / "osv-scanner"]
    else:
        candidates = []

    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)

    return None


@router.get("/scanners")
def get_scanner_status():
    results = []

    for scanner in SCANNER_DEFINITIONS:
        scanner_id = scanner["id"]
        executable = _find_executable(
            scanner_id, scanner["commands"]
        )
        version = None
        message = "Scanner is not installed or could not be found."

        if executable:
            try:
                env = os.environ.copy()
                env["PATH"] = os.pathsep.join(
                    [
                        str(TOOLS_DIR),
                        str(SEMGREP_DIR / "bin"),
                        env.get("PATH", ""),
                    ]
                )

                completed = subprocess.run(
                    [executable, *scanner["version_args"]],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=VERSION_CHECK_TIMEOUT_SECONDS,
                    check=False,
                    shell=False,
                    env=env,
                )
            except subprocess.TimeoutExpired:
                message = (
                    "Scanner version check timed out after "
                    f"{VERSION_CHECK_TIMEOUT_SECONDS} seconds."
                )
            except OSError as exc:
                message = (
                    "Scanner executable could not be started: "
                    f"{type(exc).__name__}."
                )
            else:
                output = (
                    (completed.stdout or "").strip()
                    or (completed.stderr or "").strip()
                )

                if completed.returncode == 0 and output:
                    version = output.splitlines()[0][:200]
                    message = (
                        "Scanner executable and version check succeeded: "
                        f"{version}."
                    )
                else:
                    message = (
                        "Scanner version check failed "
                        f"(exit code {completed.returncode})."
                    )
                    if output:
                        message += f" Output: {output[:300]}"

        results.append(
            {
                "id": scanner_id,
                "name": scanner["name"],
                "purpose": scanner["purpose"],
                "available": version is not None,
                "status": (
                    "available"
                    if version is not None
                    else "not_installed"
                ),
                "executable": executable,
                "version": version,
                "executed": False,
                "message": message,
            }
        )

    return {
        "scanners": results,
        "total": len(results),
        "available": sum(
            1 for scanner in results if scanner["available"]
        ),
        "executed": 0,
        "note": (
            "Availability checks do not execute scanners "
            "or analyze a repository."
        ),
    }
