
from pathlib import Path

from .config import DEFAULT_CONFIG, ScannerConfig
from .findings import SecurityFinding
from .rules.base import SecurityRule
from .rules.injection import SQLInjectionRule, CommandInjectionRule
from .rules.secrets import HardcodedSecretRule
from .analyzers.python_ast_analyzer import PythonASTAnalyzer


class RuleEngine:
    def __init__(
        self,
        config: ScannerConfig = DEFAULT_CONFIG,
        rules: list[SecurityRule] | None = None,
    ):
        self.config = config

        self.rules = rules if rules is not None else [
            SQLInjectionRule(),
            CommandInjectionRule(),
            HardcodedSecretRule(),
        ]

        self.python_ast_analyzer = PythonASTAnalyzer()

    def analyze_file(
        self,
        file_path: Path,
        relative_path: str,
        language: str,
    ) -> list[SecurityFinding]:

        if file_path.is_symlink():
            return []

        try:
            if file_path.stat().st_size > self.config.max_file_size_bytes:
                return []

            source_code = file_path.read_text(
                encoding="utf-8-sig",
                errors="replace",
            )

        except (OSError, UnicodeError):
            return []

        findings: list[SecurityFinding] = []

        # Stage 1: Run the pattern-based detection rules.
        for rule in self.rules:
            if language not in rule.languages:
                continue

            findings.extend(
                rule.detect(
                    source_code=source_code,
                    file_path=relative_path,
                    language=language,
                )
            )

        # Stage 2: Run Python AST and local data-flow analysis.
        if language == "Python":
            ast_findings = self.python_ast_analyzer.analyze(
                source_code=source_code,
                file_path=relative_path,
            )

            findings.extend(ast_findings)

        # Stage 3: Remove duplicate findings for the same
        # vulnerability, file and line.
        unique_findings = []
        seen_findings = set()

        for finding in findings:
            finding_key = (
                finding.file_path,
                finding.line_number,
                finding.cwe,
            )

            if finding_key in seen_findings:
                continue

            seen_findings.add(finding_key)
            unique_findings.append(finding)

        return unique_findings
