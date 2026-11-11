
import hashlib
import re
from typing import Any

from app.core.finding_explanations import build_finding_explanation
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


def scanner_attributions(value: str | None) -> list[str]:
    """Return unique, ordered scanner names from comma-separated attribution."""
    attributions = []
    seen = set()

    for scanner in str(value or "").split(","):
        name = scanner.strip()
        key = name.casefold()
        if name and key not in seen:
            seen.add(key)
            attributions.append(name)

    return attributions


def merge_findings(existing: Finding, candidate: Finding) -> Finding:
    """Merge scanner attribution and complementary data for one deduplicated issue."""
    severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    confidence_rank = {"low": 1, "medium": 2, "high": 3}

    if severity_rank[candidate.severity] > severity_rank[existing.severity]:
        existing.severity = candidate.severity
    if confidence_rank[candidate.confidence] > confidence_rank[existing.confidence]:
        existing.confidence = candidate.confidence

    existing.source_scanner = ", ".join(
        scanner_attributions(
            ", ".join(
                scanner_attributions(existing.source_scanner)
                + scanner_attributions(candidate.source_scanner)
            )
        )
    )

    def combine_text(first: str, second: str, placeholder: str | None = None) -> str:
        first = redact_evidence(first)
        second = redact_evidence(second)
        if not first or first == placeholder:
            return second or first
        if not second or second == placeholder or second in first:
            return first
        if first in second:
            return second
        return f"{first}\n{second}"

    existing.description = (
        combine_text(existing.description, candidate.description, "No description provided.")
    )
    existing.remediation = (
        combine_text(
            existing.remediation,
            candidate.remediation,
            "Review the finding manually.",
        )
    )
    existing.redacted_evidence = (
        combine_text(existing.redacted_evidence, candidate.redacted_evidence)
    )
    existing.explanation = build_finding_explanation(existing)
    return existing


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
    file_path = redact_evidence(_normalize_path(raw.get("file_path") or "unknown"))
    description = redact_evidence(
        str(raw.get("description") or "No description provided.")
    )
    evidence = redact_evidence(str(raw.get("evidence") or ""))
    remediation = redact_evidence(
        str(raw.get("remediation") or "Review the finding manually.")
    )
    source_scanner = ", ".join(scanner_attributions(source_scanner))

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

    finding = Finding(
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
    finding.explanation = build_finding_explanation(finding)
    return finding
