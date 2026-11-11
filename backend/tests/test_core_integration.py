from pathlib import Path

import pytest

from app.core.archive_handler import SourceFile
from app.scanners.reposentinel_core import integration
from app.scanners.reposentinel_core.integration import (
    RepoSentinelCoreScanError,
    _stage_source_files,
    scan_with_reposentinel_core,
)


def test_core_stages_windows_paths_and_normalizes_finding_paths(monkeypatch):
    observed = {}

    class FakeCore:
        def scan_repository(self, repository_path):
            root = Path(repository_path)
            observed["root"] = root
            observed["content"] = (root / "src" / "config.py").read_text(
                encoding="utf-8"
            )
            return {
                "findings": [
                    {
                        "rule_id": "CORE-SECRET",
                        "title": "Potential hardcoded credential",
                        "description": "A credential-like value was found.",
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "cwe": "CWE-798",
                        "file_path": "src\\config.py",
                        "line_number": 1,
                        "evidence": 'password = "LIVE_SUPER_SECRET_12345"',
                        "recommendation": "Rotate the exposed credential.",
                    }
                ]
            }

    monkeypatch.setattr(integration, "RepoSentinelCore", FakeCore)

    findings = scan_with_reposentinel_core(
        [SourceFile(r"src\config.py", 'password = "LIVE_SUPER_SECRET_12345"\n', 1)]
    )

    assert observed["content"] == 'password = "LIVE_SUPER_SECRET_12345"\n'
    assert not observed["root"].exists()
    assert len(findings) == 1
    finding = findings[0]
    assert finding.file_path == "src/config.py"
    assert finding.source_scanner == "RepoSentinel Core"
    assert finding.detection_type == "scanner"
    assert finding.severity == "high"
    assert "CWE-798" in finding.description
    assert "LIVE_SUPER_SECRET_12345" not in str(finding.model_dump())
    assert "[REDACTED]" in finding.redacted_evidence


def test_core_adapter_preserves_existing_static_analysis_rules():
    findings = scan_with_reposentinel_core(
        [
            SourceFile(
                r"src\database.py",
                'user_id = input("Enter ID")\n'
                'query = f"SELECT * FROM users WHERE id = {user_id}"\n'
                "cursor.execute(query)\n",
                3,
            )
        ]
    )

    assert any(finding.rule_id == "RSC-AST-SQL-001" for finding in findings)
    assert all(finding.file_path == "src/database.py" for finding in findings)
    assert all(finding.source_scanner == "RepoSentinel Core" for finding in findings)


@pytest.mark.parametrize(
    "path",
    [
        "",
        "../outside.py",
        r"..\outside.py",
        "/outside.py",
        r"C:\outside.py",
        "src//empty.py",
    ],
)
def test_core_rejects_invalid_paths_before_invoking_engine(monkeypatch, path):
    def unexpected_core():
        raise AssertionError("Invalid source paths must be rejected before scanning.")

    monkeypatch.setattr(integration, "RepoSentinelCore", unexpected_core)

    with pytest.raises(RepoSentinelCoreScanError):
        scan_with_reposentinel_core([SourceFile(path, "value = 1\n", 1)])


def test_core_rejects_symlinked_staging_parent(monkeypatch, tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    linked_directory = root / "linked"
    linked_directory.mkdir()
    real_is_symlink = Path.is_symlink

    def detect_link(path):
        if path == linked_directory:
            return True
        return real_is_symlink(path)

    monkeypatch.setattr(Path, "is_symlink", detect_link)

    with pytest.raises(RepoSentinelCoreScanError, match="symbolic link"):
        _stage_source_files(
            [SourceFile("linked/escape.py", "value = 1\n", 1)],
            root,
        )

    assert not (linked_directory / "escape.py").exists()


def test_core_validates_all_paths_before_writing_any_file(tmp_path):
    root = tmp_path / "source"

    with pytest.raises(RepoSentinelCoreScanError, match="unsafe relative path"):
        _stage_source_files(
            [
                SourceFile("safe.py", "value = 1\n", 1),
                SourceFile("../outside.py", "value = 2\n", 1),
            ],
            root,
        )

    assert not (root / "safe.py").exists()
