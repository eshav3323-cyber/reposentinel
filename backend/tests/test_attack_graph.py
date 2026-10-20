from app.core.attack_graph import build_attack_graph


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
