import json
import subprocess

from app.core.archive_handler import SourceFile
from app.scanners.osv_scanner import scan_with_osv


def test_osv_adapter_normalizes_synthetic_local_report_without_network(monkeypatch):
    monkeypatch.setattr("app.scanners.osv_scanner._find_osv_executable", lambda: "local-osv-stub")

    def fake_run(command, **_kwargs):
        report = command[command.index("--output-file") + 1]
        payload = {
            "results": [{
                "source": {"path": "requirements.txt"},
                "packages": [{
                    "package": {"name": "example-health-lib", "version": "0.1.0", "ecosystem": "PyPI"},
                    "vulnerabilities": [{"id": "SYNTHETIC-ADVISORY-1", "summary": "Synthetic fixture advisory only."}],
                }],
            }],
        }
        with open(report, "w", encoding="utf-8") as output:
            json.dump(payload, output)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr("app.scanners.osv_scanner.subprocess.run", fake_run)
    findings = scan_with_osv([
        SourceFile("requirements.txt", "example-health-lib==0.1.0\n", 1)
    ])
    assert len(findings) == 1
    assert findings[0].rule_id == "SYNTHETIC-ADVISORY-1"
    assert findings[0].file_path == "requirements.txt"
    assert "example-health-lib" in findings[0].description
