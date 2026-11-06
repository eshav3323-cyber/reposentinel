from app.core.finding_normalizer import normalize_finding
from app.models.findings import Finding


def _base_raw(**overrides):
    raw = {
        "title": "Potential security issue",
        "rule_id": "TEST-001",
        "severity": "high",
        "file_path": "src/app.py",
        "line_number": 12,
        "description": "Security issue requires review.",
        "evidence": "sample evidence",
        "remediation": "Fix the issue before deployment.",
        "confidence": "medium",
    }
    raw.update(overrides)
    return raw


def test_hardcoded_secret_explanation_is_user_friendly():
    finding = normalize_finding(
        _base_raw(
            title="Potential hardcoded credential",
            rule_id="HEURISTIC-HARDCODED-CREDENTIAL",
            file_path="src/config.py",
            evidence="password='demo-secret'",
            description="A credential-like assignment contains a literal value.",
        ),
        source_scanner="RepoSentinel Heuristic",
        detection_type="heuristic",
    )

    assert "stored in code" in finding.explanation.simple_title.lower()
    assert "secret" in finding.explanation.what_it_means.lower()
    assert finding.explanation.how_to_fix
    assert finding.severity == "high"


def test_vulnerable_dependency_explanation_is_specific():
    finding = normalize_finding(
        _base_raw(
            title="GHSA-123: requests",
            rule_id="GHSA-123",
            file_path="requirements.txt",
            description="Package: requests Version: 2.27.1. Ecosystem: PyPI. Related advisory IDs: GHSA-123.",
            evidence="Dependency: requests Version: 2.27.1",
            remediation="Upgrade requests to a fixed version.",
            severity="high",
        ),
        source_scanner="OSV-Scanner",
        detection_type="scanner",
    )

    assert "known vulnerability" in finding.explanation.simple_title.lower()
    assert "dependency" in finding.explanation.what_it_means.lower()
    assert "upgrade" in " ".join(finding.explanation.how_to_fix).lower()


def test_unsafe_code_explanation_targets_risky_configuration():
    finding = normalize_finding(
        _base_raw(
            title="TLS certificate verification disabled",
            rule_id="HEURISTIC-TLS-VERIFY-DISABLED",
            description="A recognizable TLS verification-disabling setting was found.",
            evidence="verify = False",
            remediation="Enable certificate verification.",
        ),
        source_scanner="RepoSentinel Heuristic",
        detection_type="heuristic",
    )

    assert "risky configuration" in finding.explanation.simple_title.lower()
    assert "tls" in finding.explanation.what_it_means.lower()
    assert any("secure default" in step.lower() for step in finding.explanation.how_to_fix)


def test_patient_data_endpoint_explanation_is_data_protection_focused():
    finding = normalize_finding(
        _base_raw(
            title="Patient records endpoint allows unrestricted access",
            rule_id="PATIENT-ACCESS-001",
            file_path="api/patient_records.py",
            description="A health data endpoint exposes patient records without a clear access check.",
            evidence="patient_id=request.args.get('id')",
            remediation="Add an authorization check before exposing patient records.",
        ),
        source_scanner="Semgrep",
        detection_type="scanner",
    )

    assert "healthcare" in finding.explanation.simple_title.lower() or "patient" in finding.explanation.simple_title.lower()
    assert "patient" in finding.explanation.what_it_means.lower()
    assert "authorization" in " ".join(finding.explanation.how_to_fix).lower()


def test_excessive_permissions_explanation_is_specific():
    finding = normalize_finding(
        _base_raw(
            title="Excessive permissions granted to service account",
            rule_id="PERMISSION-EXCESSIVE",
            file_path="infra/role.yaml",
            description="The service role has broader permissions than needed.",
            evidence="role: admin",
            remediation="Reduce the service account permissions to least privilege.",
        ),
        source_scanner="Semgrep",
        detection_type="scanner",
    )

    assert "access" in finding.explanation.simple_title.lower() or "permission" in finding.explanation.simple_title.lower()
    assert "least" in " ".join(finding.explanation.how_to_fix).lower()


def test_unknown_vulnerability_category_uses_safe_fallback():
    finding = normalize_finding(
        _base_raw(
            title="Custom issue with no specific pattern",
            rule_id="CUSTOM-999",
            description="A custom rule flagged a pattern without a known categories.",
            evidence="",
            remediation="Review and validate the rule output.",
        ),
        source_scanner="RepoSentinel Heuristic",
        detection_type="heuristic",
    )

    assert "potential security issue" in finding.explanation.simple_title.lower()
    assert "review" in finding.explanation.what_it_means.lower()
    assert len(finding.explanation.possible_impact) >= 2


def test_missing_evidence_still_generates_plain_language_explanation():
    finding = normalize_finding(
        _base_raw(
            title="Issue without evidence",
            rule_id="MISSING-EVIDENCE-1",
            evidence="",
            description="The scanner flagged a condition but did not include supporting evidence.",
        ),
        source_scanner="Gitleaks",
        detection_type="scanner",
    )

    assert finding.explanation is not None
    assert finding.explanation.what_it_means
    assert finding.redacted_evidence == ""


def test_original_technical_details_are_preserved_with_explanation():
    raw = _base_raw(
        title="Debug mode explicitly enabled",
        rule_id="HEURISTIC-DEBUG-ENABLED",
        description="Debug mode is enabled in configuration.",
        remediation="Disable debug mode before production.",
    )
    finding = normalize_finding(raw, source_scanner="RepoSentinel Heuristic", detection_type="heuristic")

    assert finding.description == raw["description"]
    assert finding.remediation == raw["remediation"]
    assert finding.explanation is not None


def test_severity_and_api_compatibility_are_unchanged():
    raw = _base_raw(
        title="Potential SQL query string concatenation",
        rule_id="HEURISTIC-SQL-STRING-CONCAT",
        severity="medium",
        description="SQL-like text appears to be combined with a variable.",
    )
    finding = normalize_finding(raw, source_scanner="RepoSentinel Heuristic", detection_type="heuristic")
    payload = finding.model_dump()

    assert finding.severity == "medium"
    assert payload["severity"] == "medium"
    assert payload["explanation"]["simple_title"]
    assert payload["id"]
