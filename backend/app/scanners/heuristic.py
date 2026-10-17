
import re

from app.core.finding_normalizer import normalize_finding
from app.core.archive_handler import SourceFile
from app.models.findings import Finding


RULES = [
    {
        "id": "HEURISTIC-HARDCODED-CREDENTIAL",
        "title": "Potential hardcoded credential",
        "pattern": re.compile(
            r"""(?ix)
            \b(?:password|passwd|client_secret|api_key|access_token)
            \b\s*[:=]\s*
            (?:
                ["'][^"']{4,}["']
                |
                [A-Za-z0-9_./+=-]{8,}
            )
            """
        ),
        "severity": "high",
        "confidence": "medium",
        "description": (
            "A credential-like assignment contains a literal value. "
            "Review whether this is a real secret or harmless test data."
        ),
        "remediation": (
            "Move genuine secrets to a secure runtime configuration source, "
            "rotate exposed credentials, and avoid committing them."
        ),
    },
    {
        "id": "HEURISTIC-DEBUG-ENABLED",
        "title": "Debug mode explicitly enabled",
        "pattern": re.compile(
            r"""(?ix)
            \b(?:DEBUG|debug)\s*[:=]\s*
            (?:True|true|1|"true"|'true')
            """
        ),
        "severity": "medium",
        "confidence": "medium",
        "description": (
            "A debug setting appears explicitly enabled. Confirm whether "
            "this configuration can reach a production environment."
        ),
        "remediation": (
            "Disable debug mode in production and manage environment-specific "
            "configuration explicitly."
        ),
    },
    {
        "id": "HEURISTIC-TLS-VERIFY-DISABLED",
        "title": "TLS certificate verification disabled",
        "pattern": re.compile(
            r"""(?ix)
            \bverify\s*=\s*False\b
            |
            \bCERT_NONE\b
            """
        ),
        "severity": "high",
        "confidence": "medium",
        "description": (
            "A recognizable TLS verification-disabling setting was found. "
            "Review the surrounding code and runtime context."
        ),
        "remediation": (
            "Enable certificate verification and configure a trusted "
            "certificate authority when making TLS connections."
        ),
    },
    {
        "id": "HEURISTIC-SQL-STRING-CONCAT",
        "title": "Potential SQL query string concatenation",
        "pattern": re.compile(
            r"""(?ix)
            \b(?:SELECT|INSERT|UPDATE|DELETE)\b
            .{0,200}
            (?:\+\s*[A-Za-z_]\w*|%\s*[A-Za-z_]\w*|
               \.format\s*\(|f["'])
            """,
        ),
        "severity": "medium",
        "confidence": "low",
        "description": (
            "SQL-like text appears to be combined with a variable or "
            "interpolation. This pattern alone does not establish SQL injection."
        ),
        "remediation": (
            "Review the query construction and use parameterized queries "
            "with the database library's supported API."
        ),
    },
]


def scan_source_files(files: list[SourceFile]) -> list[Finding]:
    """Inspect source text using explicit heuristic patterns only."""

    findings: list[Finding] = []

    for source_file in files:
        for line_number, line in enumerate(
            source_file.content.splitlines(), start=1
        ):
            for rule in RULES:
                if not rule["pattern"].search(line):
                    continue

                finding = normalize_finding(
                    {
                        "title": rule["title"],
                        "rule_id": rule["id"],
                        "severity": rule["severity"],
                        "file_path": source_file.path,
                        "line_number": line_number,
                        "description": rule["description"],
                        "evidence": line.strip(),
                        "remediation": rule["remediation"],
                        "confidence": rule["confidence"],
                    },
                    source_scanner="RepoSentinel Heuristic",
                    detection_type="heuristic",
                )

                findings.append(finding)

    # A file can match multiple rules on the same line. Preserve distinct
    # findings but avoid duplicate IDs.
    unique_findings = {finding.id: finding for finding in findings}

    return list(unique_findings.values())
