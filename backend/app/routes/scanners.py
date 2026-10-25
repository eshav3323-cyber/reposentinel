import shutil
import subprocess

from fastapi import APIRouter

router = APIRouter(prefix="/api", tags=["Scanners"])

VERSION_CHECK_TIMEOUT_SECONDS = 5

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


@router.get("/scanners")
def get_scanner_status():
    results = []

    for scanner in SCANNER_DEFINITIONS:
        executable = next(
            (
                found
                for command in scanner["commands"]
                if (found := shutil.which(command))
            ),
            None,
        )
        version = None
        message = "Scanner is not installed or is not on PATH."

        if executable:
            try:
                completed = subprocess.run(
                    [executable, *scanner["version_args"]],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=VERSION_CHECK_TIMEOUT_SECONDS,
                    check=False,
                    shell=False,
                )
            except subprocess.TimeoutExpired:
                message = "Scanner executable did not respond to its version check."
            except OSError:
                message = "Scanner executable could not be started."
            else:
                output = (completed.stdout or completed.stderr or "").strip()
                if completed.returncode == 0 and output:
                    version = output.splitlines()[0][:200]
                    message = (
                        "Scanner executable and version check succeeded: "
                        f"{version}."
                    )
                else:
                    message = "Scanner executable failed its version check."

        results.append(
            {
                "id": scanner["id"],
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
        "note": "Availability checks do not execute scanners or analyze a repository.",
    }