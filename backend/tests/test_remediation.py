from fastapi.testclient import TestClient

from app.core.attack_graph import build_attack_graph
from app.core.remediation import build_remediation_plan
from app.main import app
from app.routes.scans import SCAN_STORE


client = TestClient(app)


def finding(
    finding_id="f-1",
    rule_id="HEURISTIC-HARDCODED-CREDENTIAL",
    title="Potential hardcoded credential",
    severity="high",
    confidence="medium",
    description="Review a credential-like assignment.",
    remediation="Move secrets out of source.",
    source_scanner="RepoSentinel Heuristic",
    file_path="config.py",
    detection_type="heuristic",
):
    return {
        "id": finding_id,
        "title": title,
        "rule_id": rule_id,
        "severity": severity,
        "confidence": confidence,
        "description": description,
        "remediation": remediation,
        "source_scanner": source_scanner,
        "file_path": file_path,
        "line_number": 1,
        "redacted_evidence": "[REDACTED]",
        "detection_type": detection_type,
    }


def plan(items, paths=None, budget=5):
    graph = {
        "nodes": [
            {"id": f"finding-{item['id']}", "node_type": "finding"}
            for item in items
        ],
        "edges": [],
        "attack_paths": paths or [],
    }
    return build_remediation_plan("scan-test", items, graph, budget)


def selected_for(item):
    return plan([item]).selected_recommendations[0]


def test_hardcoded_credential_guidance_and_redaction():
    item = finding(
        title="password=plain-text-secret-value",
        file_path="config-password=another-secret.py",
    )
    recommendation = selected_for(item)

    assert "secret manager" in recommendation.recommended_action
    assert "rotate" in recommendation.recommended_action
    assert "plain-text-secret-value" not in str(recommendation.model_dump())
    assert "another-secret" not in str(recommendation.model_dump())


def test_debug_mode_guidance():
    recommendation = selected_for(finding(
        rule_id="HEURISTIC-DEBUG-ENABLED",
        title="Debug mode explicitly enabled",
    ))
    assert "Disable debug mode in production" in recommendation.recommended_action
    assert any("production" in step for step in recommendation.verification_steps)


def test_tls_guidance():
    recommendation = selected_for(finding(
        rule_id="HEURISTIC-TLS-VERIFY-DISABLED",
        title="TLS certificate verification disabled",
    ))
    assert "Enable certificate verification" in recommendation.recommended_action


def test_dynamic_code_guidance():
    recommendation = selected_for(finding(
        rule_id="reposentinel-dangerous-eval",
        title="Use of eval() requires review",
        source_scanner="Semgrep",
        detection_type="scanner",
    ))
    assert "dynamic evaluation" in recommendation.recommended_action.lower()
    assert any("interpreted as code" in step for step in recommendation.verification_steps)


def test_dependency_guidance_uses_observed_version_without_inventing_fix():
    recommendation = selected_for(finding(
        finding_id="dep-1",
        rule_id="GHSA-example",
        title="GHSA-example: example-package",
        source_scanner="OSV-Scanner",
        detection_type="scanner",
        description=(
            "Known issue. Package: example-package Version: 1.2.3. "
            "Ecosystem: PyPI. Related advisory IDs: GHSA-example."
        ),
        file_path="requirements.txt",
    ))
    assert "example-package 1.2.3" in recommendation.recommended_action
    assert "No fixed version is inferred" in recommendation.recommended_action
    assert "1.2.4" not in recommendation.recommended_action


def test_generic_guidance_is_evidence_based():
    recommendation = selected_for(finding(
        rule_id="CUSTOM-RULE",
        title="Unrecognized issue",
        remediation="Review only after validation.",
    ))
    assert recommendation.recommended_action == "Review only after validation."
    assert "does not match" in recommendation.rationale


def test_recommendation_ids_and_order_are_stable():
    items = [
        finding(finding_id="z", severity="low"),
        finding(finding_id="a", severity="low"),
    ]
    first = plan(items)
    second = plan(list(reversed(items)))
    assert [item.id for item in first.ranked_recommendations] == [
        item.id for item in second.ranked_recommendations
    ]
    assert [item.rank for item in first.ranked_recommendations] == [1, 2]


def test_unrelated_finding_does_not_claim_path_coverage():
    items = [finding(finding_id="real")]
    graph_path = [{"id": "p-1", "node_ids": ["finding-similar-title"]}]
    result = plan(items, graph_path)
    assert result.ranked_recommendations[0].covered_path_ids == []
    assert result.selected_recommendations == []
    assert result.path_coverage_after.unaddressed_paths == 1


def test_paths_associate_by_explicit_finding_node_id_only():
    items = [finding(finding_id="f-1")]
    graph_path = [{"id": "p-1", "node_ids": ["finding-f-1"]}]
    result = plan(items, graph_path)
    assert result.ranked_recommendations[0].covered_path_ids == ["p-1"]
    assert result.path_coverage_after.candidate_covered_paths == 1


def test_path_can_associate_through_explicit_has_finding_graph_edge():
    item = finding(finding_id="edge-case")
    graph = {
        "nodes": [
            {"id": "finding-edge-case", "node_type": "finding"},
            {"id": "component-config", "node_type": "component"},
        ],
        "edges": [{
            "source": "component-config",
            "target": "finding-edge-case",
            "edge_type": "has_finding",
        }],
        "attack_paths": [{
            "id": "p-via-component",
            "node_ids": ["component-config"],
            "evidence_type": "modeled",
        }],
    }
    result = build_remediation_plan("edge-scan", [item], graph)
    assert result.ranked_recommendations[0].covered_path_ids == ["p-via-component"]


def test_greedy_selection_maximizes_distinct_path_coverage_within_budget():
    items = [
        finding(finding_id="a", severity="high"),
        finding(finding_id="b", severity="critical"),
        finding(finding_id="c", severity="medium"),
    ]
    paths = [
        {"id": "p-1", "node_ids": ["finding-a", "finding-b"]},
        {"id": "p-2", "node_ids": ["finding-a"]},
        {"id": "p-3", "node_ids": ["finding-c"]},
    ]
    result = plan(items, paths, budget=2)
    assert len(result.selected_recommendations) == 2
    assert result.path_coverage_after.covered_path_ids == ["p-1", "p-2", "p-3"]
    assert result.selected_recommendations[0].related_finding_ids == ["a"]


def test_empty_findings_and_paths_are_valid():
    result = plan([])
    assert result.ranked_recommendations == []
    assert result.selected_recommendations == []
    assert result.path_coverage_before.modeled_paths == 0
    assert "could not be calculated" in result.limitations[-1]


def test_recommendation_for_finding_without_path_is_ranked_when_paths_exist():
    items = [finding(finding_id="off-path", severity="critical")]
    result = plan(items, [{"id": "p-1", "node_ids": ["finding-other"]}])
    assert result.selected_recommendations == []
    assert result.ranked_recommendations[0].related_finding_ids == ["off-path"]
    assert result.path_coverage_after.unaddressed_paths == 1


def test_unknown_scan_returns_404_and_existing_endpoints_remain_available():
    assert client.get("/api/scans/not-a-scan/remediation").status_code == 404
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/scanners").status_code == 200
    assert client.get("/api/scans/not-a-scan/attack-graph").status_code == 404
    assert client.get("/api/scans/not-a-scan/findings").status_code == 404


def test_remediation_route_returns_structured_plan_and_rejects_bad_budget():
    scan_id = "remediation-route-test"
    SCAN_STORE[scan_id] = {"findings": [finding(finding_id="route-finding")]}
    try:
        response = client.get(f"/api/scans/{scan_id}/remediation?budget=2")
        assert response.status_code == 200
        payload = response.json()
        assert payload["scan_id"] == scan_id
        assert payload["budget"] == 2
        assert len(payload["selected_recommendations"]) == 1
        assert "not verified patches" in " ".join(payload["limitations"])
        assert client.get(f"/api/scans/{scan_id}/remediation?budget=0").status_code == 422
        assert client.get(f"/api/scans/{scan_id}/remediation?budget=26").status_code == 422
    finally:
        SCAN_STORE.pop(scan_id, None)
