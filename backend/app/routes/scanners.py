import shutil

from fastapi import APIRouter

router = APIRouter(prefix="/api", tags=["Scanners"])

SCANNER_DEFINITIONS = [
    {
        "id": "gitleaks",
        "name": "Gitleaks",
        "purpose": "Detects potential secrets in source repositories.",
        "commands": ["gitleaks"],
    },
    {
        "id": "semgrep",
        "name": "Semgrep",
        "purpose": "Performs static analysis using security rules.",
        "commands": ["semgrep"],
    },
    {
        "id": "osv-scanner",
        "name": "OSV-Scanner",
        "purpose": "Checks supported dependency manifests for known vulnerabilities.",
        "commands": ["osv-scanner"],
    },
]


@router.get("/scanners")
def get_scanner_status():
    results = []

    for scanner in SCANNER_DEFINITIONS:
        executable = None

        for command in scanner["commands"]:
            executable = shutil.which(command)

            if executable:
                break

        results.append(
            {
                "id": scanner["id"],
                "name": scanner["name"],
                "purpose": scanner["purpose"],
                "available": executable is not None,
                "status": (
                    "available"
                    if executable
                    else "not_installed"
                ),
                "executable": executable,
                "executed": False,
                "message": (
                    "Scanner executable detected; no scan has been run."
                    if executable
                    else "Scanner is not installed or is not on PATH."
                ),
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