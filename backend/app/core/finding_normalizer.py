
import hashlib
import re
from typing import Any

from app.models.findings import Finding


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
    # finding is encountered in an unchanged file.
    identity = "|".join(
        [source_scanner, rule_id, file_path, str(line_number), title]
    )
    finding_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]

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
