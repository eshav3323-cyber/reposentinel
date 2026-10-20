from __future__ import annotations

from collections import defaultdict
from typing import Any
import hashlib
import re

from app.models.attack_graph import (
    AttackGraphNode,
    AttackGraphEdge,
    AttackPath,
    AttackGraphResponse,
)
from app.core.finding_normalizer import redact_evidence


SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "unknown": 0,
}


def _get_value(item: Any, key: str, default: Any = None) -> Any:
    """Read a value from either a Pydantic model or a dictionary."""
    if isinstance(item, dict):
        return item.get(key, default)

    return getattr(item, key, default)


def _safe_text(value: Any, default: str = "") -> str:
    if value is None:
        return default

    return str(value)


def _make_id(prefix: str, value: str) -> str:
    """Create stable graph IDs without exposing sensitive evidence."""
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    return f"{prefix}-{digest}"


def _normalize_severity(value: Any) -> str:
    severity = _safe_text(value, "unknown").strip().lower()

    if severity not in SEVERITY_ORDER:
        return "unknown"

    return severity


def _normalize_path(path: Any) -> str:
    """Normalize scanner paths and hide absolute/temp extraction prefixes."""
    value = redact_evidence(_safe_text(path, "unknown")).replace("\\", "/").strip()
    while value.startswith("./"):
        value = value[2:]
    parts = [part for part in value.split("/") if part not in ("", ".")]
    lowered = [part.lower() for part in parts]
    # Scanner extraction roots have an explicit, stable marker. Keep the full
    # repository-relative suffix after it, including legitimate subfolders.
    markers = ("reposentinel-osv", "reposentinel-gitleaks", "reposentinel-semgrep")
    for index, part in enumerate(lowered):
        if any(part == marker or part.startswith(marker + "-") for marker in markers):
            parts = parts[index + 1:]
            break
    else:
        # A remaining drive/absolute path is not a repository-relative label.
        # Keep only its basename to avoid disclosing host filesystem details.
        if value.startswith("/") or re.match(r"^[A-Za-z]:/", value):
            parts = parts[-1:]
    return "/".join(parts) or "unknown"


def _classify_finding(finding: Any) -> tuple[str, str]:
    """Return an asset category and a human-readable explanation."""
    title = _safe_text(_get_value(finding, "title")).lower()
    rule_id = _safe_text(_get_value(finding, "rule_id")).lower()
    description = _safe_text(_get_value(finding, "description")).lower()
    detection_type = _safe_text(
        _get_value(finding, "detection_type"), "scanner"
    ).lower()

    combined = f"{title} {rule_id} {description}"

    if any(word in combined for word in (
        "secret", "credential", "password", "api key",
        "token", "private key", "gitleaks"
    )):
        return (
            "credential",
            "Potential credential exposure; validity and access are unverified.",
        )

    if any(word in combined for word in (
        "dependency", "package", "vulnerability", "osv",
        "cve-", "pysec-", "ghsa-"
    )):
        return (
            "dependency",
            "Dependency-related finding; exploitability is unverified.",
        )

    if any(word in combined for word in (
        "patient", "medical record", "health record", "phi",
        "protected health", "personal data"
    )):
        return (
            "health_data",
            "Potential health-data-related code; actual data access is unverified.",
        )

    if any(word in combined for word in (
        "sql", "injection", "eval(", "command execution",
        "debug", "tls", "verify=false", "permission"
    )):
        return (
            "application_code",
            "Potentially unsafe application behavior requiring manual review.",
        )

    if detection_type == "heuristic":
        return (
            "application_code",
            "Heuristic signal requiring manual validation.",
        )

    return (
        "application_code",
        "Scanner finding requiring manual validation.",
    )


def build_attack_graph(
    scan_id: str,
    findings: list[Any],
) -> AttackGraphResponse:
    """
    Build a conservative, evidence-labelled attack graph.

    Observed nodes represent scan findings and source files.
    Modeled edges represent possible relationships, not proof of exploitation.
    This function never executes repository code.
    """
    nodes: list[AttackGraphNode] = []
    edges: list[AttackGraphEdge] = []
    attack_paths: list[AttackPath] = []
    warnings: list[str] = []

    nodes_by_id: dict[str, AttackGraphNode] = {}
    edges_seen: set[tuple[str, str, str]] = set()
    findings_by_file: dict[str, list[tuple[str, Any, str]]] = defaultdict(list)

    scan_node_id = _make_id("scan", scan_id)

    scan_node = AttackGraphNode(
        id=scan_node_id,
        label=f"Repository scan {scan_id}",
        node_type="entry_point",
        description="Repository analysis entry point; no code was executed.",
        risk_level="unknown",
        evidence_type="observed",
    )

    nodes.append(scan_node)
    nodes_by_id[scan_node_id] = scan_node

    def add_node(node: AttackGraphNode) -> None:
        if node.id not in nodes_by_id:
            nodes_by_id[node.id] = node
            nodes.append(node)

    def add_edge(edge: AttackGraphEdge) -> None:
        key = (edge.source, edge.target, edge.edge_type)

        if key not in edges_seen:
            edges_seen.add(key)
            edges.append(edge)

    if not findings:
        warnings.append(
            "No findings were supplied. The following demo assets are illustrative modeled placeholders, not repository discoveries."
        )
        for key, label in (
            ("application", "Illustrative application surface (demo)"),
            ("dependencies", "Illustrative dependency inventory (demo)"),
            ("health-data", "Illustrative health-data handling (demo)"),
        ):
            add_node(AttackGraphNode(
                id=_make_id("demo-asset", f"{scan_id}|{key}"),
                label=label,
                node_type="asset",
                description="Illustrative modeled asset only; not identified in the scanned repository.",
                risk_level="unknown",
                evidence_type="modeled",
            ))

    for index, finding in enumerate(findings, start=1):
        title = redact_evidence(_safe_text(
            _get_value(finding, "title"), f"Finding {index}"
        ))
        file_path = _normalize_path(
            _get_value(finding, "file_path", "unknown")
        )
        severity = _normalize_severity(
            _get_value(finding, "severity", "unknown")
        )
        source_scanner = _safe_text(
            _get_value(finding, "source_scanner"), "unknown"
        )
        description = redact_evidence(_safe_text(
            _get_value(finding, "description"),
            "Finding requires manual review.",
        ))

        finding_id = _safe_text(_get_value(finding, "id"))

        if not finding_id:
            finding_id = _make_id(
                "finding",
                f"{scan_id}|{source_scanner}|{file_path}|{title}|{index}",
            )

        graph_finding_id = f"finding-{finding_id}"

        finding_node = AttackGraphNode(
            id=graph_finding_id,
            label=title[:160],
            node_type="finding",
            description=description[:500],
            risk_level=severity,
            evidence_type="observed",
        )
        add_node(finding_node)

        file_node_id = _make_id("component", file_path)

        file_node = AttackGraphNode(
            id=file_node_id,
            label=file_path[:180],
            node_type="component",
            description="Source file identified by the scanner.",
            risk_level=severity,
            evidence_type="observed",
        )
        add_node(file_node)

        add_edge(
            AttackGraphEdge(
                source=scan_node_id,
                target=graph_finding_id,
                edge_type="contains",
                description="The finding was returned by this repository scan.",
                evidence_type="observed",
            )
        )

        add_edge(
            AttackGraphEdge(
                source=file_node_id,
                target=graph_finding_id,
                edge_type="has_finding",
                description="The finding is associated with this source file.",
                evidence_type="observed",
            )
        )

        category, category_description = _classify_finding(finding)
        asset_id = _make_id("asset", f"{category}|{file_path}")

        asset_node = AttackGraphNode(
            id=asset_id,
            label={
                "credential": "Potential credential",
                "dependency": "Potential vulnerable dependency",
                "health_data": "Potential health-data handling",
                "application_code": "Application code",
            }.get(category, "Application asset"),
            node_type="asset",
            description=category_description,
            risk_level=severity,
            evidence_type="modeled",
        )
        add_node(asset_node)

        add_edge(
            AttackGraphEdge(
                source=graph_finding_id,
                target=asset_id,
                edge_type="exposes",
                description=(
                    "Modeled association based on finding text; "
                    "the actual exposure has not been verified."
                ),
                evidence_type="modeled",
            )
        )

        findings_by_file[file_path].append(
            (graph_finding_id, finding, category)
        )

    # Build conservative modeled paths only when a file has multiple
    # relevant findings. A path is a hypothesis for review, not proof.
    for file_path, file_findings in findings_by_file.items():
        if len(file_findings) < 2:
            continue

        categories = {entry[2] for entry in file_findings}

        has_credential = "credential" in categories
        has_unsafe_code = "application_code" in categories
        has_health_data = "health_data" in categories
        has_dependency = "dependency" in categories

        if not (
            (has_credential and (has_unsafe_code or has_health_data))
            or (has_dependency and (has_unsafe_code or has_health_data))
        ):
            continue

        ordered = sorted(
            file_findings,
            key=lambda entry: SEVERITY_ORDER[
                _normalize_severity(_get_value(entry[1], "severity"))
            ],
            reverse=True,
        )

        selected = ordered[:4]
        path_node_ids = [entry[0] for entry in selected]

        if len(path_node_ids) < 2:
            continue

        path_severities = [
            _normalize_severity(_get_value(entry[1], "severity"))
            for entry in selected
        ]
        highest_severity = max(
            path_severities,
            key=lambda value: SEVERITY_ORDER[value],
        )

        path_id = _make_id(
            "path",
            f"{scan_id}|{file_path}|{'|'.join(path_node_ids)}",
        )

        attack_paths.append(
            AttackPath(
                id=path_id,
                title="Modeled multi-finding review path",
                node_ids=path_node_ids,
                risk_level=highest_severity,
                explanation=(
                    f"Multiple findings in {file_path} may warrant joint review. "
                    "The graph does not establish reachability, exploitation, "
                    "or access to patient data."
                ),
                evidence_type="modeled",
            )
        )

    if not attack_paths and findings:
        # A single finding can be shown as a review hypothesis linked to its
        # modeled asset; this is not a claim of reachability or exploitation.
        for file_path, file_findings in findings_by_file.items():
            for graph_finding_id, finding, _category in file_findings:
                severity = _normalize_severity(_get_value(finding, "severity"))
                attack_paths.append(AttackPath(
                    id=_make_id("path", f"{scan_id}|review|{file_path}|{graph_finding_id}"),
                    title="Modeled single-finding review hypothesis",
                    node_ids=[graph_finding_id],
                    risk_level=severity,
                    explanation=(
                        f"Review the finding associated with {file_path}. This modeled hypothesis "
                        "does not establish reachability, exploitation, or access to data."
                    ),
                    evidence_type="modeled",
                ))

    if not attack_paths:
        warnings.append(
            "No multi-finding review paths met the current modeling rules. "
            "This does not prove the repository is safe."
        )

    warnings.append(
        "Graph edges and attack paths marked 'modeled' are hypotheses, "
        "not confirmed attack paths or proof of exploitability."
    )

    return AttackGraphResponse(
        scan_id=scan_id,
        nodes=nodes,
        edges=edges,
        attack_paths=attack_paths,
        warnings=warnings,
    )
