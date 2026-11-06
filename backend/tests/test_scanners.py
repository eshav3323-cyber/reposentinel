
from app.core.archive_handler import SourceFile
from app.scanners.heuristic import scan_source_files


def make_source(content: str, path: str = "app.py") -> SourceFile:
    return SourceFile(
        path=path,
        content=content,
        line_count=len(content.splitlines()),
    )


def test_detects_credential_like_assignment():
    findings = scan_source_files([
        make_source('api_key = "DEMO_EXAMPLE_KEY_12345"')
    ])

    assert any(
        f.rule_id == "HEURISTIC-HARDCODED-CREDENTIAL"
        for f in findings
    )


def test_redacts_credential_from_evidence():
    findings = scan_source_files([
        make_source('password = "DEMO_SECRET_VALUE_12345"')
    ])

    finding = next(
        f for f in findings
        if f.rule_id == "HEURISTIC-HARDCODED-CREDENTIAL"
    )

    assert "DEMO_SECRET_VALUE_12345" not in finding.redacted_evidence
    assert "[REDACTED]" in finding.redacted_evidence


def test_detects_debug_setting():
    findings = scan_source_files([
        make_source("DEBUG = True")
    ])

    assert any(
        f.rule_id == "HEURISTIC-DEBUG-ENABLED"
        for f in findings
    )


def test_detects_disabled_tls_verification():
    findings = scan_source_files([
        make_source("requests.get(url, verify=False)")
    ])

    assert any(
        f.rule_id == "HEURISTIC-TLS-VERIFY-DISABLED"
        for f in findings
    )


def test_detects_candidate_sql_concatenation():
    findings = scan_source_files([
        make_source('query = "SELECT * FROM users WHERE id = " + user_id')
    ])

    assert any(
        f.rule_id == "HEURISTIC-SQL-STRING-CONCAT"
        for f in findings
    )


def test_detects_real_requests_verify_false():
    findings = scan_source_files([
        make_source('requests.get(url, verify=False)')
    ])

    assert any(f.rule_id == "HEURISTIC-TLS-VERIFY-DISABLED" for f in findings)


def test_detects_ssl_certificate_none_assignment():
    findings = scan_source_files([
        make_source('context.verify_mode = ssl.CERT_NONE')
    ])

    assert any(f.rule_id == "HEURISTIC-TLS-VERIFY-DISABLED" for f in findings)


def test_ignores_tls_keywords_in_comments_and_docs():
    findings = scan_source_files([
        make_source("# verify=False is used in the example below\n# TLS certificate verification is disabled in docs\nprint('safe')")
    ])

    assert not any(f.rule_id == "HEURISTIC-TLS-VERIFY-DISABLED" for f in findings)

    findings = scan_source_files([
        make_source('"""TLS certificate verification is disabled in the docs example. verify=False. """\nprint("safe")')
    ])

    assert not any(f.rule_id == "HEURISTIC-TLS-VERIFY-DISABLED" for f in findings)


def test_ignores_semgrep_rule_yaml_files():
    findings = scan_source_files([
        make_source('pattern: DEBUG = True\nmessage: "debug is enabled"', 'app/scanners/semgrep_rules.yml')
    ])

    assert findings == []


def test_detects_real_debug_config_but_ignores_rule_definitions():
    findings = scan_source_files([
        make_source('DEBUG = True\n', 'app/settings.py')
    ])
    assert any(f.rule_id == 'HEURISTIC-DEBUG-ENABLED' for f in findings)

    findings = scan_source_files([
        make_source('pattern: DEBUG = True\nmessage: "Debug mode is explicitly enabled."', 'app/scanners/semgrep_rules.yml')
    ])
    assert findings == []


def test_ignores_synthetic_test_credentials_in_fixture_paths():
    findings = scan_source_files([
        make_source('api_key = "DEMO_EXAMPLE_KEY_12345"', 'backend/tests/evaluation/fixtures/credential/vulnerable/config.py')
    ])
    assert not any(f.rule_id == "HEURISTIC-HARDCODED-CREDENTIAL" for f in findings)


def test_finding_has_expected_schema():
    findings = scan_source_files([
        make_source("DEBUG = True", "config.py")
    ])

    finding = findings[0]

    assert finding.file_path == "config.py"
    assert finding.line_number == 1
    assert finding.severity in {"critical", "high", "medium", "low", "info"}
    assert finding.confidence in {"high", "medium", "low"}
    assert finding.detection_type == "heuristic"
    assert finding.source_scanner == "RepoSentinel Heuristic"


def test_safe_source_has_no_findings():
    findings = scan_source_files([
        make_source("print('Hello, healthcare security!')")
    ])

    assert findings == []
