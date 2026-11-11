import re

from .base import SecurityRule
from ..findings import SecurityFinding


class HardcodedSecretRule(SecurityRule):
    rule_id = "RSC-SEC-001"
    title = "Potential Hardcoded Secret"

    description = (
        "A variable associated with credentials, tokens or API keys "
        "appears to contain a literal string value. Hardcoded secrets "
        "can be exposed through source repositories."
    )

    severity = "HIGH"
    confidence = "MEDIUM"
    cwe = "CWE-798"

    languages = {"Python", "JavaScript", "TypeScript"}

    recommendation = (
        "Move credentials into environment variables or a dedicated "
        "secret manager. Rotate any credential that has been exposed."
    )

    assignment_pattern = re.compile(
        r"""(?ix)
        \b
        (?P<name>
            api[_-]?key |
            secret[_-]?key |
            access[_-]?token |
            auth[_-]?token |
            password |
            passwd |
            client[_-]?secret |
            private[_-]?key
        )
        \b
        \s*[:=]\s*
        (?P<quote>['"])
        (?P<value>[^'"]+)
        (?P=quote)
        """
    )

    placeholders = {
        "",
        "password",
        "your_password",
        "your-password",
        "your_api_key",
        "your-api-key",
        "changeme",
        "change_me",
        "change-me",
        "example",
        "placeholder",
        "replace_me",
        "replace-me",
        "xxx",
        "test",
        "dummy",
        "none",
        "null",
    }

    def detect(self, source_code, file_path, language):
        if language not in self.languages:
            return []

        findings = []

        for line_number, line in enumerate(
            source_code.splitlines(), start=1
        ):
            stripped = line.lstrip()

            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            match = self.assignment_pattern.search(line)

            if not match:
                continue

            variable_name = match.group("name")
            value = match.group("value").strip()

            if value.lower() in self.placeholders:
                continue

            if len(value) < 6:
                continue

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
                        f"Credential-like variable '{variable_name}' "
                        "has a literal value. The value is intentionally "
                        "redacted."
                    ),
                    recommendation=self.recommendation,
                )
            )

        return findings