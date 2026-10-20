import json
import sys
from pathlib import Path
from subprocess import CompletedProcess

from app.core.archive_handler import SourceFile
from app.scanners import semgrep_scanner


def test_semgrep_uses_active_python_entrypoint_when_package_is_installed(
    monkeypatch, tmp_path
):
    captured = {}

    monkeypatch.setattr(semgrep_scanner, "distribution", lambda _name: object())

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        report_path = Path(command[command.index("--output") + 1])
        report_path.write_text(
            json.dumps(
                {
                    "results": [
                        {
                            "check_id": "app.scanners.reposentinel-dangerous-eval",
                            "path": "sample.py",
                            "start": {"line": 1},
                            "extra": {
                                "severity": "ERROR",
                                "message": "Use of eval() requires careful security review.",
                            },
                        }
                    ],
                    "errors": [],
                }
            ),
            encoding="utf-8",
        )
        return CompletedProcess(command, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(semgrep_scanner.subprocess, "run", fake_run)
    findings = semgrep_scanner.scan_with_semgrep(
        [SourceFile(path="sample.py", content="value = 1\n", line_count=1)]
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "reposentinel-dangerous-eval"
    assert captured["command"][:3] == [
        sys.executable,
        "-c",
        "from semgrep.console_scripts.entrypoint import main; main()",
    ]
    assert captured["command"][3:5] == ["--legacy", "scan"]
    assert captured["kwargs"]["encoding"] == "utf-8"
    assert captured["kwargs"]["errors"] == "replace"


def test_semgrep_falls_back_to_executable_without_python_package(monkeypatch):
    def no_distribution(_name):
        raise semgrep_scanner.PackageNotFoundError("semgrep")

    monkeypatch.setattr(semgrep_scanner, "distribution", no_distribution)

    assert semgrep_scanner._semgrep_command("semgrep") == ["semgrep"]
