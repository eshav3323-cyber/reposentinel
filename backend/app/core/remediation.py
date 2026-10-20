"""Deterministic, explainable remediation candidate ranking.

The engine proposes review actions only. It does not modify repository files,
execute code, or prove that any modeled path is exploitable or eliminated.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from app.models.remediation import (
    PathCoverage,
    RemediationRecommendation,
    RemediationResponse,
)


SEVERITY_WEIGHT = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}
CONFIDENCE_WEIGHT = {"high": 2, "medium": 1, "low": 0}

_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)(\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|"
    r"client[_-]?secret|password|passwd|secret|private[_-]?key)\b"
    r"\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;#}]+)"
)
_BEARER_SECRET = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_AWS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_GITHUB_TOKEN = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")
_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)
_PACKAGE_DETAILS = re.compile(
    r"\bPackage:\s*(?P<package>.+?)\s+Version:\s*(?P<version>\S+)"
    r"\s+Ecosystem:\s*(?P<ecosystem>\S+)",
    re.IGNORECASE,
)
_SAFE_PACKAGE = re.compile(r"^[A-Za-z0-9@._+/-]{1,180}$")
_SYNTHETIC_CREDENTIAL = re.compile(r"\b(?:DEMO|SYNTH)_[A-Z0-9_]{8,}\b")


def _value(item: Any, key: str, default: Any = "") -> Any:
    if isinstance(item, dict):
        return item.get(key, default)
    return getattr(item, key, default)


def _text(item: Any, key: str, default: str = "") -> str:
    value = _value(item, key, default)
    return default if value is None else str(value)


def redact_public_text(value: Any, limit: int = 500) -> str:
    """Remove recognizable credential values before including source text."""
    text = str(value or "")
    text = _PRIVATE_KEY.sub("[REDACTED PRIVATE KEY]", text)
    text = _SENSITIVE_ASSIGNMENT.sub(r"\1[REDACTED]", text)
    text = _BEARER_SECRET.sub("Bearer [REDACTED]", text)
    text = _AWS_KEY.sub("[REDACTED KEY]", text)
    text = _GITHUB_TOKEN.sub("[REDACTED TOKEN]", text)
    text = _SYNTHETIC_CREDENTIAL.sub("[REDACTED SYNTHETIC CREDENTIAL]", text)
    return text[:limit]


def _classify(finding: Any) -> str:
    rule_id = _text(finding, "rule_id").lower()
    title = _text(finding, "title").lower()
    description = _text(finding, "description").lower()
    scanner = _text(finding, "source_scanner").lower()
    primary = f"{rule_id} {title}"

    # Rule IDs and titles are the finding's classification signals. Generic
    # descriptions often mention unrelated terms (including "credential") and
    # must not override an explicit rule.
    if "debug-enabled" in rule_id or "debug mode" in primary:
        return "debug"
    if any(token in primary for token in (
        "tls-verify-disabled", "tls verification", "certificate verification",
        "verify=false", "cert_none",
    )):
        return "tls"
    if any(token in primary for token in (
        "dangerous-eval", "dynamic code", "eval(", "exec(",
        "unsafe dynamic",
    )):
        return "dynamic_code"
    if any(token in primary for token in (
        "vulnerability", "vulnerable dependency", "dependency", "package",
        "cve-", "ghsa-", "pysec-", "osv-",
    )) or "osv" in scanner:
        return "dependency"
    if any(token in primary for token in (
        "hardcoded-credential", "credential", "gitleaks", "secret",
        "password", "api key", "access token", "private key",
    )) or "gitleaks" in scanner:
        return "credential"
    # Descriptions can refine classification only when they carry a specific
    # detection phrase; generic prose such as "credential-like assignment"
    # is not enough to reclassify an unrelated rule.
    if any(token in description for token in (
        "secret detected", "hardcoded password", "private key detected",
    )):
        return "credential"
    return "generic"


def _dependency_context(finding: Any) -> tuple[str | None, str | None, str | None]:
    if "osv" not in _text(finding, "source_scanner").lower():
        return None, None, None
    match = _PACKAGE_DETAILS.search(_text(finding, "description"))
    if not match:
        return None, None, None

    package = match.group("package").strip().rstrip(".,;:")
    version = match.group("version").strip().rstrip(".,;:")
    ecosystem = match.group("ecosystem").strip().rstrip(".,;:")
    package = redact_public_text(package, 180)
    version = redact_public_text(version, 100)
    ecosystem = redact_public_text(ecosystem, 100)
    if not _SAFE_PACKAGE.fullmatch(package):
        package = None
    if not _SAFE_PACKAGE.fullmatch(version):
        version = None
    if not _SAFE_PACKAGE.fullmatch(ecosystem):
        ecosystem = None
    return package, version, ecosystem


def _finding_path_ids(finding_id: str, graph: Any) -> list[str]:
    """Associate only exact graph finding IDs or explicit has_finding edges."""
    graph_nodes = _value(graph, "nodes", []) or []
    graph_edges = _value(graph, "edges", []) or []
    graph_paths = _value(graph, "attack_paths", []) or []
    canonical_id = f"finding-{finding_id}"
    valid_finding_nodes = {
        _text(node, "id")
        for node in graph_nodes
        if _text(node, "node_type") == "finding"
        and _text(node, "id") in {finding_id, canonical_id}
    }
    # Accept the finding ID itself when a caller supplies it directly in a
    # path, even if the graph node list is incomplete.
    explicit_finding_ids = valid_finding_nodes | {finding_id, canonical_id}
    component_nodes = {
        _text(edge, "source")
        for edge in graph_edges
        if _text(edge, "edge_type") == "has_finding"
        and _text(edge, "target") in valid_finding_nodes
    }

    covered = []
    for path in graph_paths:
        if _text(path, "evidence_type", "modeled") != "modeled":
            continue
        node_ids = set(_value(path, "node_ids", []) or [])
        if node_ids.intersection(explicit_finding_ids) or node_ids.intersection(component_nodes):
            path_id = _text(path, "id")
            if path_id:
                covered.append(path_id)
    return sorted(set(covered))


def _candidate(finding: Any, graph: Any) -> RemediationRecommendation:
    finding_id = _text(finding, "id")
    rule_id = _text(finding, "rule_id").upper()
    severity = _text(finding, "severity", "info").lower()
    confidence = _text(finding, "confidence", "low").lower()
    detection_type = _text(finding, "detection_type", "scanner").lower()
    title = redact_public_text(_text(finding, "title", "Security finding"), 240)
    file_path = redact_public_text(_text(finding, "file_path", "unknown"), 300)
    kind = _classify(finding)

    if kind == "credential":
        action = (
            "Move the secret to an approved secret manager or protected runtime "
            "environment configuration, rotate it if genuine, and prevent future commits."
        )
        rationale = (
            "A credential-like value was reported. Rotation limits the usefulness "
            "of any exposed credential; this result does not establish that it is active."
        )
        steps = [
            "Confirm whether the value is a real credential without copying it into tickets or logs.",
            "Rotate or revoke it with the issuing service if genuine.",
            "Load the replacement from an approved secret manager or protected runtime configuration.",
            "Add an appropriate secret-scanning check and verify the value is absent from the current source and history according to repository policy.",
        ]
        effort = "medium"
    elif kind == "debug":
        action = "Disable debug mode in production and verify the deployed configuration uses the production setting."
        rationale = "Debug settings can reveal implementation details or diagnostics if enabled in a production context; the scan does not establish deployment context."
        steps = [
            "Trace the setting to the production configuration source.",
            "Set debug mode off for production and keep local development settings separate.",
            "Verify the effective setting in a production-like deployment without exposing diagnostic data.",
        ]
        effort = "low"
    elif kind == "tls":
        action = "Enable certificate verification and configure the trusted certificate authorities required by the deployment."
        rationale = "Disabling certificate validation weakens peer identity checks; this finding alone does not show that a connection was intercepted."
        steps = [
            "Review the affected client and its deployment certificate requirements.",
            "Enable the client library's normal certificate verification.",
            "Configure a trusted CA bundle where needed and verify valid and invalid certificates are handled as expected.",
        ]
        effort = "medium"
    elif kind == "dynamic_code":
        action = "Remove dynamic evaluation where practical; otherwise constrain the accepted inputs and use a narrowly defined parser or allowlist."
        rationale = "Dynamic evaluation can interpret input as code. The reported pattern requires contextual review and does not establish attacker control."
        steps = [
            "Trace the value passed to the dynamic execution call to its sources.",
            "Replace evaluation with a data parser or explicit operation mapping when possible.",
            "Add tests for rejected input and verify no untrusted string is interpreted as code.",
        ]
        effort = "medium"
    elif kind == "dependency":
        package, version, ecosystem = _dependency_context(finding)
        if package and version:
            action = (
                f"Review the advisory for {package} {version} ({ecosystem or 'ecosystem not stated'}), "
                "identify a patched or supported version from authoritative advisory evidence, "
                "then update the manifest or lockfile after compatibility review. No fixed version is inferred here."
            )
            rationale = f"Scanner evidence identifies {package} version {version}; this recommendation does not assume a particular fixed release."
        else:
            action = "Use the scanner advisory and the repository's dependency manifest to identify the affected package and version, then choose a patched or supported version only when the advisory establishes one."
            rationale = "The finding suggests a dependency issue, but the available fields do not establish a specific safe target version."
        steps = [
            "Confirm the package, resolved version, and affected range against the scanner advisory.",
            "Choose a fixed or supported version only when the advisory provides evidence for it.",
            "Update the relevant manifest and lockfile using the package manager.",
            "Re-run dependency analysis and the relevant compatibility and application checks.",
        ]
        effort = "medium"
    else:
        action = redact_public_text(
            _text(finding, "remediation") or
            "Review the finding in context and select a corrective action supported by the scanner evidence.",
            500,
        )
        rationale = "The finding does not match a remediation rule with a safe, specific action; review its source evidence and surrounding code before changing it."
        steps = [
            "Review the scanner rule and source location in the repository.",
            "Validate the reported condition in context without executing uploaded code.",
            "Choose a corrective change supported by the evidence and add a regression check.",
        ]
        effort = "medium"

    covered = _finding_path_ids(finding_id, graph)
    severity_weight = SEVERITY_WEIGHT.get(severity, 1)
    confidence_weight = CONFIDENCE_WEIGHT.get(confidence, 0)
    path_bonus = min(len(covered), 3) * 5
    score = min(100, severity_weight * 15 + confidence_weight * 5 + path_bonus)
    score_explanation = (
        f"Heuristic score = severity weight ({severity_weight} x 15) + "
        f"confidence weight ({confidence_weight} × 5) + modeled path association "
        f"({path_bonus}); capped at 100. It is a prioritization estimate, not a measured risk reduction."
    )
    evidence_classification = (
        "modeled_assumption"
        if detection_type == "modeled_assumption"
        else "observed_finding"
    )
    recommendation_id = "rem-" + hashlib.sha256(
        f"{finding_id}|{rule_id}".encode("utf-8")
    ).hexdigest()[:16]

    return RemediationRecommendation(
        id=recommendation_id,
        rank=1,
        related_finding_ids=[finding_id],
        finding_title=title,
        file_path=file_path,
        severity=severity if severity in SEVERITY_WEIGHT else "info",
        confidence=confidence if confidence in CONFIDENCE_WEIGHT else "low",
        detection_type=detection_type,
        recommended_action=action,
        rationale=rationale,
        verification_steps=steps,
        estimated_effort=effort,
        risk_reduction_score=score,
        score_explanation=score_explanation,
        evidence_classification=evidence_classification,
        covered_path_ids=covered,
        limitations=[
            "This is a candidate action for human review, not a verified patch.",
            "Finding confidence, runtime reachability, and business context may change priority.",
        ],
    )


def _coverage(paths: list[Any], covered_ids: set[str]) -> PathCoverage:
    path_ids = sorted({
        _text(path, "id") for path in paths
        if _text(path, "id") and _text(path, "evidence_type", "modeled") == "modeled"
    })
    covered = sorted(set(path_ids).intersection(covered_ids))
    unaddressed = sorted(set(path_ids).difference(covered))
    return PathCoverage(
        modeled_paths=len(path_ids),
        candidate_covered_paths=len(covered),
        unaddressed_paths=len(unaddressed),
        covered_path_ids=covered,
        unaddressed_path_ids=unaddressed,
        interpretation=(
            "A path is counted as candidate-covered when a selected recommendation "
            "targets a finding explicitly represented on that modeled path. This "
            "does not mean the path is eliminated."
        ),
    )


def build_remediation_plan(
    scan_id: str,
    findings: list[Any],
    graph: Any,
    budget: int = 5,
) -> RemediationResponse:
    """Rank candidates and greedily select a deterministic, budgeted subset."""
    budget = max(1, min(int(budget), 25))
    candidates = [_candidate(finding, graph) for finding in findings]
    severity_by_id = {
        recommendation.id: SEVERITY_WEIGHT.get(recommendation.severity, 1)
        for recommendation in candidates
    }

    paths = [
        path for path in (_value(graph, "attack_paths", []) or [])
        if _text(path, "evidence_type", "modeled") == "modeled"
        and _text(path, "id")
    ]
    remaining = list(candidates)
    selected: list[RemediationRecommendation] = []
    covered_so_far: set[str] = set()

    while remaining and len(selected) < budget:
        def greedy_key(recommendation: RemediationRecommendation):
            new_paths = set(recommendation.covered_path_ids) - covered_so_far
            return (
                -len(new_paths),
                -severity_by_id[recommendation.id],
                -recommendation.risk_reduction_score,
                recommendation.id,
            )

        choice = min(remaining, key=greedy_key)
        if paths and not (
            set(choice.covered_path_ids) - covered_so_far
        ):
            break
        selected.append(choice)
        covered_so_far.update(choice.covered_path_ids)
        remaining.remove(choice)

    # Ranked list begins with the greedy selection order; unselected candidates
    # use transparent static priority and stable ID tie-breaking.
    unselected = sorted(
        remaining,
        key=lambda rec: (
            -len(rec.covered_path_ids),
            -severity_by_id[rec.id],
            -rec.risk_reduction_score,
            rec.id,
        ),
    )
    ranked = selected + unselected
    ranked = [rec.model_copy(update={"rank": rank}) for rank, rec in enumerate(ranked, 1)]
    selected_ids = {rec.id for rec in selected}
    selected_ranked = [rec for rec in ranked if rec.id in selected_ids]
    after = _coverage(paths, covered_so_far)
    before = _coverage(paths, set())

    if paths:
        summary = (
            f"Selected {len(selected_ranked)} candidate remediation(s) within a "
            f"budget of {budget}; {after.candidate_covered_paths} of "
            f"{after.modeled_paths} modeled paths contain at least one targeted finding."
        )
        optimization = (
            "Greedy selection maximizes newly covered modeled paths at each step; "
            "ties break by severity, heuristic score, then stable recommendation ID. "
            "Path coverage means a path contains a targeted finding, not that it is eliminated."
        )
    else:
        summary = (
            f"Selected {len(selected_ranked)} candidate remediation(s) within a "
            f"budget of {budget}. No valid modeled paths were available, so path coverage was not calculated."
        )
        optimization = (
            "Without modeled paths, selection is ordered by severity, heuristic "
            "score, then stable recommendation ID; no path coverage claim is made."
        )

    limitations = [
        "Recommendations are candidates for human review, not verified patches or automatic code modifications.",
        "Risk-reduction scores are transparent prioritization heuristics, not proven or measured security outcomes.",
        "Modeled attack paths are hypotheses and do not prove exploitability, reachability, or compromise.",
    ]
    if not paths:
        limitations.append("Path coverage could not be calculated because the graph contains no valid modeled paths.")

    return RemediationResponse(
        scan_id=scan_id,
        budget=budget,
        summary=summary,
        limitations=limitations,
        path_coverage_before=before,
        path_coverage_after=after,
        optimization_explanation=optimization,
        ranked_recommendations=ranked,
        selected_recommendations=selected_ranked,
    )
