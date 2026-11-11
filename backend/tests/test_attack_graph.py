import pytest
from pydantic import ValidationError

from app.core.attack_graph import build_attack_graph
from app.models.attack_graph import (
    AttackGraphEdge,
    AttackGraphNode,
    AttackGraphResponse,
    AttackPath,
)


def test_graph_contains_observed_finding_and_modeled_asset():
    findings = [
        {
            "id": "finding-1",
            "title": "Potential hardcoded credential",
            "rule_id": "HEURISTIC-HARDCODED-CREDENTIAL",
            "severity": "high",
            "file_path": "config.py",
            "source_scanner": "RepoSentinel Heuristic",
        }
    ]

    graph = build_attack_graph("scan-test", findings)

    assert graph.scan_id == "scan-test"
    assert any(n.id == "finding-finding-1" for n in graph.nodes)
    assert any(n.node_type == "asset" for n in graph.nodes)
    assert any(e.evidence_type == "observed" for e in graph.edges)
    assert any(e.evidence_type == "modeled" for e in graph.edges)
    assert len(graph.attack_paths) == 1


def test_empty_findings_produce_warning_and_demo_assets():
    graph = build_attack_graph("empty-scan", [])

    assert graph.attack_paths == []
    assert any(n.node_type == "asset" for n in graph.nodes)
    assert graph.warnings


def test_osv_temporary_path_is_not_exposed_in_component_label():
    findings = [
        {
            "id": "osv-1",
            "title": "PYSEC-2010-12: django",
            "rule_id": "PYSEC-2010-12",
            "severity": "medium",
            "file_path": (
                "C:/Users/Dell/AppData/Local/Temp/"
                "reposentinel-osv/requirements.txt"
            ),
            "source_scanner": "OSV-Scanner",
        }
    ]

    graph = build_attack_graph("osv-scan", findings)

    component_labels = [
        n.label for n in graph.nodes if n.node_type == "component"
    ]

    assert component_labels == ["requirements.txt"]
    assert all("AppData" not in label for label in component_labels)


def test_graph_handles_unknown_severity():
    graph = build_attack_graph(
        "unknown-severity",
        [
            {
                "id": "finding-unknown",
                "title": "Unclassified issue",
                "severity": "not-a-severity",
                "file_path": "app.py",
                "source_scanner": "Test",
            }
        ],
    )

    finding = next(
        n for n in graph.nodes if n.id == "finding-finding-unknown"
    )
    assert finding.risk_level == "unknown"


def test_duplicate_findings_are_collapsed_and_best_severity_is_preserved():
    findings = [
        {
            "id": "same-finding",
            "title": "Potential credential",
            "severity": "high",
            "file_path": "config.py",
            "source_scanner": "Scanner A",
        },
        {
            "id": "same-finding",
            "title": "Potential credential",
            "severity": "critical",
            "file_path": "config.py",
            "source_scanner": "Scanner B",
        },
    ]

    graph = build_attack_graph("deduplicated-scan", findings)
    finding_nodes = [node for node in graph.nodes if node.node_type == "finding"]

    assert len(finding_nodes) == 1
    assert finding_nodes[0].risk_level == "critical"
    assert len(graph.attack_paths) == 1
    assert graph.attack_paths[0].node_ids == ["finding-same-finding"]
    assert any("Duplicate finding IDs" in warning for warning in graph.warnings)


def test_findings_without_ids_get_stable_ids_independent_of_input_order():
    findings = [
        {
            "title": "Potential credential",
            "rule_id": "credential",
            "severity": "high",
            "file_path": "config.py",
            "source_scanner": "Scanner A",
        },
        {
            "title": "Unsafe application behavior",
            "rule_id": "dangerous-eval",
            "severity": "medium",
            "file_path": "app.py",
            "source_scanner": "Scanner B",
        },
    ]

    first = build_attack_graph("stable-id-scan", findings)
    second = build_attack_graph("stable-id-scan", list(reversed(findings)))
    first_ids = {
        node.id for node in first.nodes if node.node_type == "finding"
    }
    second_ids = {
        node.id for node in second.nodes if node.node_type == "finding"
    }

    assert first_ids == second_ids


def test_review_groups_cover_each_finding_without_duplicate_members():
    findings = [
        {
            "id": f"finding-{index}",
            "title": "Credential" if index == 0 else "Unsafe application behavior",
            "rule_id": "credential" if index == 0 else "dangerous-eval",
            "severity": "high" if index < 4 else "low",
            "file_path": "app.py",
        }
        for index in range(5)
    ]

    graph = build_attack_graph("group-coverage-scan", findings)
    grouped_ids = [
        node_id
        for path in graph.attack_paths
        for node_id in path.node_ids
    ]
    finding_ids = {
        node.id for node in graph.nodes if node.node_type == "finding"
    }

    assert set(grouped_ids) == finding_ids
    assert len(grouped_ids) == len(set(grouped_ids))
    assert any(len(path.node_ids) == 1 for path in graph.attack_paths)
    assert all("review group" in path.title.lower() for path in graph.attack_paths if len(path.node_ids) > 1)


def test_graph_rejects_edges_and_paths_with_unknown_nodes():
    node = AttackGraphNode(
        id="finding-1",
        label="Finding",
        node_type="finding",
    )

    with pytest.raises(ValidationError, match="edges must reference existing nodes"):
        AttackGraphResponse(
            scan_id="invalid-edge",
            nodes=[node],
            edges=[AttackGraphEdge(
                source="finding-1",
                target="missing",
                edge_type="has_finding",
            )],
        )

    with pytest.raises(ValidationError, match="paths must reference existing nodes"):
        AttackGraphResponse(
            scan_id="invalid-path",
            nodes=[node],
            attack_paths=[AttackPath(
                id="path-1",
                title="Review",
                node_ids=["missing"],
                explanation="Invalid reference",
            )],
        )


def test_graph_rejects_repeated_members_in_a_path():
    node = AttackGraphNode(
        id="finding-1",
        label="Finding",
        node_type="finding",
    )

    with pytest.raises(ValidationError, match="must not repeat node IDs"):
        AttackGraphResponse(
            scan_id="duplicate-path-member",
            nodes=[node],
            attack_paths=[AttackPath(
                id="path-1",
                title="Review",
                node_ids=["finding-1", "finding-1"],
                explanation="Repeated member",
            )],
        )
