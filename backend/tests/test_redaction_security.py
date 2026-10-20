import json
import subprocess

from app.core.attack_graph import build_attack_graph
from app.core.finding_normalizer import normalize_finding, redact_evidence
from app.core.remediation import build_remediation_plan


def test_normalizer_redacts_assignments_bearer_private_key_and_truncates():
    values = ["SYNTH_API_KEY_456789", "SYNTH_PASSWORD_987654", "SYNTH_BEARER_ABC123", "SYNTH_PRIVATE_KEY_MATERIAL"]
    evidence = (
        f'api_key="{values[0]}" password="{values[1]}" '
        f"Authorization: Bearer {values[2]}\n"
        "-----BEGIN PRIVATE KEY-----\n"
        f"{values[3]}\n"
        "-----END PRIVATE KEY-----"
    )
    finding = normalize_finding(
        {"title": f"password={values[1]}", "rule_id": "TEST", "file_path": "src/config.py",
         "description": f"Scanner reported {values[0]}", "evidence": evidence,
         "remediation": f"Rotate {values[2]}", "severity": "high"},
        source_scanner="Synthetic", detection_type="scanner",
    )
    serialized = json.dumps(finding.model_dump())
    for value in values:
        assert value not in serialized
    long_evidence = redact_evidence("x" * 600)
    assert len(long_evidence) == 500


def test_redacted_value_does_not_leak_into_graph_or_remediation_response():
    secret = "SYNTH_GRAPH_SECRET_765432"
    finding = {
        "id": "synthetic-1", "title": f"password={secret}",
        "rule_id": "HEURISTIC-HARDCODED-CREDENTIAL", "severity": "high",
        "confidence": "high", "file_path": "config.py", "description": f"secret={secret}",
        "redacted_evidence": "[REDACTED]", "remediation": f"rotate {secret}",
        "source_scanner": "RepoSentinel Heuristic", "detection_type": "heuristic",
    }
    graph = build_attack_graph("synthetic", [finding])
    plan = build_remediation_plan("synthetic", [finding], graph.model_dump())
    public = json.dumps({"graph": graph.model_dump(), "plan": plan.model_dump()})
    assert secret not in public
    assert "modeled" in public
    assert "not verified patches" in public


def test_synthetic_secret_in_generic_remediation_is_redacted():
    secret = "SYNTH_REMEDIATION_SECRET_998877"
    finding = {
        "id": "generic-synthetic", "title": "Custom review item",
        "rule_id": "CUSTOM-RULE", "severity": "medium", "confidence": "low",
        "file_path": "src/review.py", "description": "Review this custom finding.",
        "redacted_evidence": "[REDACTED]", "remediation": f"Do not print {secret} in logs.",
        "source_scanner": "Synthetic", "detection_type": "scanner",
    }
    plan = build_remediation_plan("generic-scan", [finding], {"nodes": [], "edges": [], "attack_paths": []})
    assert secret not in json.dumps(plan.model_dump())


def test_gitleaks_scanner_output_is_redacted_before_finding_creation(monkeypatch, tmp_path):
    import app.scanners.gitleaks as gitleaks
    from app.core.archive_handler import SourceFile

    secret = "SYNTH_GITLEAKS_SECRET_54321"
    monkeypatch.setattr(gitleaks.shutil, "which", lambda _name: "local-gitleaks")

    def fake_run(command, **_kwargs):
        report = command[command.index("--report-path") + 1]
        report_path = __import__("pathlib").Path(report)
        report_path.write_text(json.dumps([{
            "Description": f"password={secret}", "RuleID": "generic-api-key",
            "File": "source/app.py", "StartLine": 1,
        }]), encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(gitleaks.subprocess, "run", fake_run)
    findings = gitleaks.scan_with_gitleaks([
        SourceFile("app.py", f'password="{secret}"', 1)
    ])
    assert len(findings) == 1
    assert secret not in json.dumps([finding.model_dump() for finding in findings])
