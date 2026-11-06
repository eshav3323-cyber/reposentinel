from app.core.finding_normalizer import normalize_finding
from app.core.scan_storage import _deduplicate_saved_findings
from app.routes.scans import deduplicate_findings


def _make_finding(*, title, rule_id, file_path, line_number, source_scanner, severity="high"):
    return normalize_finding(
        {
            "title": title,
            "rule_id": rule_id,
            "severity": severity,
            "file_path": file_path,
            "line_number": line_number,
            "description": "Security issue requires review.",
            "evidence": "sample evidence",
            "remediation": "Fix the issue before deployment.",
            "confidence": "medium",
        },
        source_scanner=source_scanner,
        detection_type="scanner",
    )


def test_deduplicate_findings_collapses_same_issue_across_scanners():
    first = _make_finding(
        title="Potential hardcoded credential",
        rule_id="HEURISTIC-SECRET",
        file_path="src/config.py",
        line_number=12,
        source_scanner="RepoSentinel Heuristic",
    )
    second = _make_finding(
        title="Potential hardcoded credential",
        rule_id="GITLEAKS-SECRET",
        file_path="src/config.py",
        line_number=12,
        source_scanner="Gitleaks",
    )

    deduped = deduplicate_findings([first, second])

    assert len(deduped) == 1
    assert deduped[0].file_path == "src/config.py"
    assert deduped[0].line_number == 12


def test_deduplicate_findings_keeps_distinct_issues_in_same_file():
    first = _make_finding(
        title="Potential hardcoded credential",
        rule_id="HEURISTIC-SECRET",
        file_path="src/config.py",
        line_number=12,
        source_scanner="RepoSentinel Heuristic",
    )
    second = _make_finding(
        title="TLS verification disabled",
        rule_id="HEURISTIC-TLS",
        file_path="src/config.py",
        line_number=12,
        source_scanner="RepoSentinel Heuristic",
    )

    deduped = deduplicate_findings([first, second])

    assert len(deduped) == 2
    assert {finding.title for finding in deduped} == {
        "Potential hardcoded credential",
        "TLS verification disabled",
    }


def test_storage_deduplication_reduces_repeated_findings_before_persistence():
    first = _make_finding(
        title="Potential SQL injection",
        rule_id="SQL-001",
        file_path="app/db.py",
        line_number=18,
        source_scanner="Semgrep",
    )
    second = _make_finding(
        title="Potential SQL injection",
        rule_id="SQL-001",
        file_path="app/db.py",
        line_number=18,
        source_scanner="Semgrep",
    )

    deduped = _deduplicate_saved_findings([first.model_dump(), second.model_dump()])

    assert len(deduped) == 1
    assert deduped[0]["rule_id"] == "SQL-001"
