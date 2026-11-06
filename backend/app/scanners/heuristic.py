
import ast
import re

from app.core.archive_handler import SourceFile
from app.core.finding_normalizer import normalize_finding
from app.models.findings import Finding


RULES = [
    {
        "id": "HEURISTIC-HARDCODED-CREDENTIAL",
        "title": "Potential hardcoded credential",
        "pattern": re.compile(
            r"""(?ix)
            \b(?:password|passwd|client_secret|api_key|access_token)
            \b\s*[:=]\s*
            (?!\s*(?:os\.environ(?:\.get)?\s*\(|getenv\s*\())
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


def _is_heuristic_ignored_path(path: str) -> bool:
    """Avoid scanner rule definitions, docs, and test/fixture directories."""
    lower = path.lower().replace("\\", "/")
    if "semgrep" in lower and lower.endswith((".yml", ".yaml")):
        return True
    if lower.endswith((".md", ".txt", ".json", ".yaml", ".yml")):
        return True
    if any(part in lower for part in ("/tests/", "/fixtures/", "/examples/", "/docs/")):
        return True
    return False


def _clean_line(line: str) -> str:
    stripped = line.strip()
    return stripped if stripped else ""


def _iter_python_findings(source_file: SourceFile) -> list[dict]:
    findings: list[dict] = []
    try:
        tree = ast.parse(source_file.content)
    except SyntaxError:
        return findings

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "DEBUG":
                    if isinstance(node.value, ast.Constant) and node.value.value is True:
                        findings.append({
                            "id": "HEURISTIC-DEBUG-ENABLED",
                            "title": "Debug mode explicitly enabled",
                            "severity": "medium",
                            "confidence": "medium",
                            "description": "A debug setting appears explicitly enabled.",
                            "remediation": "Disable debug mode in production and manage environment-specific configuration explicitly.",
                            "line": node.lineno,
                            "evidence": ast.get_source_segment(source_file.content, node) or _clean_line(source_file.content.splitlines()[node.lineno - 1]),
                        })
                        break
                if isinstance(target, ast.Attribute) and target.attr == "verify":
                    if isinstance(node.value, ast.Constant) and node.value.value is False:
                        findings.append({
                            "id": "HEURISTIC-TLS-VERIFY-DISABLED",
                            "title": "TLS certificate verification disabled",
                            "severity": "high",
                            "confidence": "medium",
                            "description": "A recognizable TLS verification-disabling setting was found.",
                            "remediation": "Enable certificate verification and configure a trusted certificate authority when making TLS connections.",
                            "line": node.lineno,
                            "evidence": ast.get_source_segment(source_file.content, node) or _clean_line(source_file.content.splitlines()[node.lineno - 1]),
                        })
                if isinstance(target, ast.Attribute) and target.attr == "verify_mode":
                    if isinstance(node.value, ast.Attribute) and isinstance(node.value.value, ast.Name) and node.value.value.id == "ssl" and node.value.attr == "CERT_NONE":
                        findings.append({
                            "id": "HEURISTIC-TLS-VERIFY-DISABLED",
                            "title": "TLS certificate verification disabled",
                            "severity": "high",
                            "confidence": "medium",
                            "description": "A recognizable TLS verification-disabling setting was found.",
                            "remediation": "Enable certificate verification and configure a trusted certificate authority when making TLS connections.",
                            "line": node.lineno,
                            "evidence": ast.get_source_segment(source_file.content, node) or _clean_line(source_file.content.splitlines()[node.lineno - 1]),
                        })

        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in {"get", "post", "put", "patch", "delete", "head", "options", "request"}:
                for kw in node.keywords:
                    if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                        findings.append({
                            "id": "HEURISTIC-TLS-VERIFY-DISABLED",
                            "title": "TLS certificate verification disabled",
                            "severity": "high",
                            "confidence": "medium",
                            "description": "A recognizable TLS verification-disabling setting was found.",
                            "remediation": "Enable certificate verification and configure a trusted certificate authority when making TLS connections.",
                            "line": node.lineno,
                            "evidence": ast.get_source_segment(source_file.content, node) or _clean_line(source_file.content.splitlines()[node.lineno - 1]),
                        })
                        break
            elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id == "ssl" and func.attr == "_create_unverified_context":
                findings.append({
                    "id": "HEURISTIC-TLS-VERIFY-DISABLED",
                    "title": "TLS certificate verification disabled",
                    "severity": "high",
                    "confidence": "medium",
                    "description": "A recognizable TLS verification-disabling setting was found.",
                    "remediation": "Enable certificate verification and configure a trusted certificate authority when making TLS connections.",
                    "line": node.lineno,
                    "evidence": ast.get_source_segment(source_file.content, node) or _clean_line(source_file.content.splitlines()[node.lineno - 1]),
                })

    for line_number, line in enumerate(source_file.content.splitlines(), start=1):
        cleaned = line.strip()
        if not cleaned or cleaned.startswith("#"):
            continue

        credential_match = re.search(
            r"(?ix)\b(?:password|passwd|client_secret|api_key|access_token)\b\s*[:=]\s*(?!\s*(?:os\.environ(?:\.get)?\s*\(|getenv\s*\())(?P<value>[\"'][^\"']{4,}[\"']|[A-Za-z0-9_./+=-]{8,})",
            line,
        )
        if credential_match:
            findings.append({
                "id": "HEURISTIC-HARDCODED-CREDENTIAL",
                "title": "Potential hardcoded credential",
                "severity": "high",
                "confidence": "medium",
                "description": "A credential-like assignment contains a literal value. Review whether this is a real secret or harmless test data.",
                "remediation": "Move genuine secrets to a secure runtime configuration source, rotate exposed credentials, and avoid committing them.",
                "line": line_number,
                "evidence": cleaned,
            })

        if re.search(r"(?is)\b(?:select|insert|update|delete)\b.*(?:\+\s*[A-Za-z_]\w*|%\s*[A-Za-z_]\w*|\.format\s*\(|f[\"'])", line):
            findings.append({
                "id": "HEURISTIC-SQL-STRING-CONCAT",
                "title": "Potential SQL query string concatenation",
                "severity": "medium",
                "confidence": "low",
                "description": "SQL-like text appears to be combined with a variable or interpolation.",
                "remediation": "Review the query construction and use parameterized queries with the database library's supported API.",
                "line": line_number,
                "evidence": cleaned,
            })

    return findings


def _iter_line_based_findings(source_file: SourceFile) -> list[dict]:
    findings: list[dict] = []
    lines = source_file.content.splitlines()
    for line_number, line in enumerate(lines, start=1):
        cleaned = line.strip()
        if not cleaned or cleaned.startswith("#") or cleaned.startswith("//") or cleaned.startswith("/*"):
            continue
        for rule in RULES:
            if not rule["pattern"].search(line):
                continue
            findings.append({
                "id": rule["id"],
                "title": rule["title"],
                "severity": rule["severity"],
                "confidence": rule["confidence"],
                "description": rule["description"],
                "remediation": rule["remediation"],
                "line": line_number,
                "evidence": cleaned,
            })
    return findings


def scan_source_files(files: list[SourceFile]) -> list[Finding]:
    """Inspect source text using explicit heuristic patterns only."""

    findings: list[Finding] = []

    for source_file in files:
        if _is_heuristic_ignored_path(source_file.path):
            continue

        if source_file.path.lower().endswith(".py"):
            relevant = _iter_python_findings(source_file)
        else:
            relevant = _iter_line_based_findings(source_file)

        for item in relevant:
            finding = normalize_finding(
                {
                    "title": item["title"],
                    "rule_id": item["id"],
                    "severity": item["severity"],
                    "file_path": source_file.path,
                    "line_number": item["line"],
                    "description": item["description"],
                    "evidence": item["evidence"],
                    "remediation": item["remediation"],
                    "confidence": item["confidence"],
                },
                source_scanner="RepoSentinel Heuristic",
                detection_type="heuristic",
            )
            findings.append(finding)

    unique_findings = {finding.id: finding for finding in findings}
    return list(unique_findings.values())
