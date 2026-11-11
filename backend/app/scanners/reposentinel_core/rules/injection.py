import re

from .base import SecurityRule
from ..findings import SecurityFinding


class SQLInjectionRule(SecurityRule):
    rule_id = "RSC-SQL-001"
    title = "Potential SQL Injection"
    description = (
        "A database execution operation appears to construct its query "
        "using dynamic string interpolation or concatenation. "
        "Untrusted input in such queries may allow SQL injection."
    )
    severity = "HIGH"
    confidence = "MEDIUM"
    cwe = "CWE-89"

    languages = {"Python", "JavaScript", "TypeScript"}

    recommendation = (
        "Use parameterized queries or prepared statements. "
        "Avoid constructing SQL queries by concatenating untrusted input."
    )

    patterns = {
        "Python": [
            re.compile(
                r"""\.execute\s*\(\s*f(?P<quote>['"])""",
                re.IGNORECASE,
            ),
            re.compile(
                r"""\.execute\s*\(\s*['"][^'"]*['"]\s*\+""",
                re.IGNORECASE,
            ),
            re.compile(
                r"""\.execute\s*\(\s*['"][^'"]*['"]\s*%""",
                re.IGNORECASE,
            ),
        ],
        "JavaScript": [
            re.compile(
                r"""\b(?:query|execute)\s*\(\s*`[^`]*\$\{""",
                re.IGNORECASE,
            ),
            re.compile(
                r"""\b(?:query|execute)\s*\(\s*['"][^'"]*['"]\s*\+""",
                re.IGNORECASE,
            ),
        ],
        "TypeScript": [
            re.compile(
                r"""\b(?:query|execute)\s*\(\s*`[^`]*\$\{""",
                re.IGNORECASE,
            ),
            re.compile(
                r"""\b(?:query|execute)\s*\(\s*['"][^'"]*['"]\s*\+""",
                re.IGNORECASE,
            ),
        ],
    }

    def detect(self, source_code, file_path, language):
        findings = []

        for line_number, line in enumerate(
            source_code.splitlines(), start=1
        ):
            if line.lstrip().startswith("#") or (
                language in {"JavaScript", "TypeScript"}
                and line.lstrip().startswith("//")
            ):
                continue

            if any(
                pattern.search(line)
                for pattern in self.patterns.get(language, [])
            ):
                findings.append(
                    SecurityFinding(
                        rule_id=self.rule_id,
                        title=self.title,
                        description=self.description,
                        severity=self.severity,
                        confidence=self.confidence,
                        cwe=self.cwe,
                        file_path=file_path,
                        line_number=line_number,
                        language=language,
                        evidence=(
                            "Dynamic query construction pattern detected. "
                            "Inspect the referenced line and its data sources."
                        ),
                        recommendation=self.recommendation,
                    )
                )

        return findings


class CommandInjectionRule(SecurityRule):
    rule_id = "RSC-CMD-001"
    title = "Potential Command Injection"
    description = (
        "A system command execution operation appears to use a shell "
        "or dynamically constructed command. If untrusted input reaches "
        "this operation, command injection may be possible."
    )
    severity = "HIGH"
    confidence = "MEDIUM"
    cwe = "CWE-78"

    languages = {"Python"}

    recommendation = (
        "Avoid shell execution when possible. Use subprocess with an "
        "argument list and shell=False. Validate untrusted arguments."
    )

    shell_pattern = re.compile(
        r"""subprocess\.(?:run|Popen|call|check_call|check_output)
        \s*\(.*\bshell\s*=\s*True""",
        re.IGNORECASE | re.VERBOSE,
    )

    dynamic_system_pattern = re.compile(
        r"""os\.system\s*\([^)]*(?:\+|\.format\s*\(|f['"])""",
        re.IGNORECASE,
    )

    def detect(self, source_code, file_path, language):
        if language != "Python":
            return []

        findings = []

        for line_number, line in enumerate(
            source_code.splitlines(), start=1
        ):
            if line.lstrip().startswith("#"):
                continue

            if (
                self.shell_pattern.search(line)
                or self.dynamic_system_pattern.search(line)
            ):
                findings.append(
                    SecurityFinding(
                        rule_id=self.rule_id,
                        title=self.title,
                        description=self.description,
                        severity=self.severity,
                        confidence=self.confidence,
                        cwe=self.cwe,
                        file_path=file_path,
                        line_number=line_number,
                        language=language,
                        evidence=(
                            "Dynamic or shell-based command execution "
                            "pattern detected. Verify whether untrusted "
                            "input can reach this operation."
                        ),
                        recommendation=self.recommendation,
                    )
                )

        return findings