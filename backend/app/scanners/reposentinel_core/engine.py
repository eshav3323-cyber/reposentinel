from pathlib import Path

from .config import DEFAULT_CONFIG, ScannerConfig
from .models import RepositoryReport
from .repository_analyzer import RepositoryAnalyzer
from .rule_engine import RuleEngine


class RepoSentinelCore:
    """
    Independent repository analysis and initial vulnerability detection.

    The engine inspects source code without executing the target repository.
    """

    def __init__(self, config: ScannerConfig = DEFAULT_CONFIG):
        self.config = config
        self.analyzer = RepositoryAnalyzer(config)
        self.rule_engine = RuleEngine(config)

    def scan_repository(self, repository_path: str | Path) -> dict:
        report: RepositoryReport = self.analyzer.analyze(
            repository_path
        )

        root = Path(report.repository_path)
        findings = []

        for file_metadata in report.files:
            source_path = root / file_metadata.path

            file_findings = self.rule_engine.analyze_file(
                file_path=source_path,
                relative_path=file_metadata.path,
                language=file_metadata.language,
            )

            findings.extend(
                finding.to_dict() for finding in file_findings
            )

        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
        }

        for finding in findings:
            severity = finding["severity"]

            if severity in severity_counts:
                severity_counts[severity] += 1

        return {
            "scanner": "RepoSentinel Core",
            "version": "0.2.0",
            "status": "completed",
            "scan_type": "repository_security_analysis",
            "report": report.to_dict(),
            "findings": findings,
            "findings_summary": {
                "total": len(findings),
                "severity_counts": severity_counts,
            },
        }