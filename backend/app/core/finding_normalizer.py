
import hashlib
import re
from typing import Any

from app.models.findings import Finding


def _normalize_text(value: Any, *, fallback: str = "") -> str:
    text = str(value if value is not None else fallback)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _normalize_path(path: Any) -> str:
    value = str(path or "unknown").replace("\\", "/").strip()
    value = re.sub(r"^\./+", "", value)
    return value or "unknown"


def _extract_package_details(value: Any) -> tuple[str, str]:
    text = _normalize_text(value)
    match = re.search(
        r"Package:\s*([^\s]+)\s+Version:\s*([^\s.]+(?:\.[^\s]+)*)",
        text,
        flags=re.IGNORECASE,
    )
    if not match:
        return "", ""
    return match.group(1), match.group(2)


def build_finding_fingerprint(finding: dict[str, Any] | Finding) -> str:
    """Create a stable identity for a finding that is safe for backend deduplication."""

    if isinstance(finding, Finding):
        candidate = finding.model_dump()
    else:
        candidate = dict(finding)

    file_path = _normalize_path(candidate.get("file_path") or "unknown")
    line_number = max(1, int(candidate.get("line_number") or 1))
    title = _normalize_text(candidate.get("title") or "Unspecified security finding")
    rule_id = _normalize_text(candidate.get("rule_id") or "UNSPECIFIED")
    evidence = _normalize_text(candidate.get("redacted_evidence") or candidate.get("evidence") or "")
    package_name, package_version = _extract_package_details(
        candidate.get("description") or evidence
    )

    # Prefer the file location plus normalized issue family as the deterministic
    # deduplication key. This keeps distinct findings apart while collapsing the
    # same underlying issue when multiple scanners report it with slightly different
    # rule identifiers or normalized labels.
    key_parts = [
        file_path,
        str(line_number),
        title,
        package_name,
        package_version,
        evidence[:200],
    ]
    if title.lower() in {"unspecified security finding", ""}:
        key_parts.append(rule_id)
    identity = "|".join(part for part in key_parts if part)
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


SECRET_VALUE_PATTERN = re.compile(
    r"""(?ix)
    (
        (?:api[_-]?key|access[_-]?token|auth[_-]?token|
           client[_-]?secret|password|passwd|secret|private[_-]?key)
        \s*[:=]\s*
    )
    (
        ["']?[^"'\s,;#}]+["']?
    )
    """
)

BEARER_PATTERN = re.compile(
    r"(?i)\b(Bearer)\s+[A-Za-z0-9._~+/=-]+"
)
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?"
    r"-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)
TOKEN_PATTERN = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})\b")
SYNTHETIC_CREDENTIAL_PATTERN = re.compile(r"\b(?:DEMO|SYNTH)_[A-Z0-9_]{8,}\b")


def redact_evidence(text: str) -> str:
    """Redact likely credential values before storing evidence."""

    text = PRIVATE_KEY_PATTERN.sub("[REDACTED PRIVATE KEY]", text)
    text = SECRET_VALUE_PATTERN.sub(r"\1[REDACTED]", text)
    text = BEARER_PATTERN.sub(r"\1 [REDACTED]", text)
    text = TOKEN_PATTERN.sub("[REDACTED TOKEN]", text)
    text = SYNTHETIC_CREDENTIAL_PATTERN.sub("[REDACTED SYNTHETIC CREDENTIAL]", text)

    return text[:500]


def normalize_finding(
    raw: dict[str, Any],
    *,
    source_scanner: str,
    detection_type: str,
) -> Finding:
    """Convert a scanner result into the shared finding schema."""

    severity_aliases = {
        "critical": "critical",
        "high": "high",
        "error": "high",
        "medium": "medium",
        "moderate": "medium",
        "warning": "medium",
        "low": "low",
        "info": "info",
        "informational": "info",
    }

    confidence_aliases = {
        "high": "high",
        "medium": "medium",
        "low": "low",
    }

    title = redact_evidence(
        str(raw.get("title") or "Unspecified security finding")
    )[:240]
    rule_id = redact_evidence(str(raw.get("rule_id") or "UNSPECIFIED"))
    file_path = redact_evidence(str(raw.get("file_path") or "unknown"))
    description = redact_evidence(
        str(raw.get("description") or "No description provided.")
    )
    evidence = redact_evidence(str(raw.get("evidence") or ""))
    remediation = redact_evidence(
        str(raw.get("remediation") or "Review the finding manually.")
    )

    try:
        line_number = max(1, int(raw.get("line_number") or 1))
    except (ValueError, TypeError):
        line_number = 1

    severity_input = str(raw.get("severity") or "medium").lower()
    severity = severity_aliases.get(severity_input, "medium")

    confidence_input = str(raw.get("confidence") or "medium").lower()
    confidence = confidence_aliases.get(confidence_input, "medium")

    # Stable identifiers avoid generating a new ID every time the same
    # underlying issue is encountered in an unchanged file or dependency manifest.
    identity = build_finding_fingerprint({
        "title": title,
        "rule_id": rule_id,
        "file_path": file_path,
        "line_number": line_number,
        "redacted_evidence": evidence,
        "description": description,
    })
    finding_id = identity[:16]

    return Finding(
        id=finding_id,
        title=title,
        rule_id=rule_id,
        severity=severity,
        file_path=file_path,
        line_number=line_number,
        description=description,
        redacted_evidence=evidence,
        remediation=remediation,
        source_scanner=source_scanner,
        confidence=confidence,
        detection_type=detection_type,
    )
