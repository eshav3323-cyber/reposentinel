from abc import ABC, abstractmethod

from ..findings import SecurityFinding


class SecurityRule(ABC):
    rule_id: str
    title: str
    description: str
    severity: str
    confidence: str
    cwe: str
    languages: set[str]
    recommendation: str

    @abstractmethod
    def detect(
        self,
        source_code: str,
        file_path: str,
        language: str,
    ) -> list[SecurityFinding]:
        """
        Analyze source code and return security findings.
        """
        raise NotImplementedError