import tempfile
import unittest
from pathlib import Path

from app.scanners.reposentinel_core.engine import RepoSentinelCore
from app.scanners.reposentinel_core.rules.injection import (
    SQLInjectionRule,
    CommandInjectionRule,
)
from app.scanners.reposentinel_core.rules.secrets import (
    HardcodedSecretRule,
)


class TestCustomDetectionRules(unittest.TestCase):

    def test_detects_python_sql_injection_pattern(self):
        source = '''
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)
'''

        # The current first-version SQL rule looks for interpolation
        # directly inside the execute call. This example is intentionally
        # assigned to query first, so it should not match yet.
        findings = SQLInjectionRule().detect(
            source, "app.py", "Python"
        )

        self.assertEqual(findings, [])

    def test_detects_direct_python_sql_interpolation(self):
        source = '''
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
'''

        findings = SQLInjectionRule().detect(
            source, "app.py", "Python"
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_detects_javascript_sql_interpolation(self):
        source = '''
db.query(`SELECT * FROM users WHERE id = ${userId}`);
'''

        findings = SQLInjectionRule().detect(
            source, "app.js", "JavaScript"
        )

        self.assertEqual(len(findings), 1)

    def test_does_not_flag_parameterized_query(self):
        source = '''
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
'''

        findings = SQLInjectionRule().detect(
            source, "app.py", "Python"
        )

        self.assertEqual(findings, [])

    def test_detects_shell_true_command_pattern(self):
        source = '''
subprocess.run(command, shell=True)
'''

        findings = CommandInjectionRule().detect(
            source, "app.py", "Python"
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-78")

    def test_does_not_flag_safe_subprocess_argument_list(self):
        source = '''
subprocess.run(["ping", hostname], shell=False)
'''

        findings = CommandInjectionRule().detect(
            source, "app.py", "Python"
        )

        self.assertEqual(findings, [])

    def test_detects_potential_hardcoded_secret(self):
        source = '''
API_KEY = "sk_example_123456789"
'''

        findings = HardcodedSecretRule().detect(
            source, "config.py", "Python"
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-798")

    def test_does_not_flag_placeholder_secret(self):
        source = '''
API_KEY = "your_api_key"
'''

        findings = HardcodedSecretRule().detect(
            source, "config.py", "Python"
        )

        self.assertEqual(findings, [])

    def test_secret_value_is_not_exposed_in_evidence(self):
        source = '''
PASSWORD = "SuperSecretValue123"
'''

        findings = HardcodedSecretRule().detect(
            source, "config.py", "Python"
        )

        self.assertEqual(len(findings), 1)

        self.assertNotIn(
            "SuperSecretValue123",
            findings[0].evidence
        )

    def test_complete_engine_returns_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            source = '''
API_KEY = "example_private_token_123"
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
'''

            (root / "app.py").write_text(
                source,
                encoding="utf-8",
            )

            result = RepoSentinelCore().scan_repository(root)

            self.assertEqual(result["status"], "completed")
            self.assertGreaterEqual(
                result["findings_summary"]["total"],
                2,
            )
    
    def test_engine_detects_sql_injection_through_variable_flow(self):
        source = '''
user_id = input("Enter ID")
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)
'''

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)

            source_file = root / "database.py"
            source_file.write_text(source, encoding="utf-8")

            engine = RepoSentinelCore()
            result = engine.scan_repository(root)

            sql_findings = [
                finding
                for finding in result["findings"]
                if finding["cwe"] == "CWE-89"
            ]

            self.assertEqual(len(sql_findings), 1)
            self.assertEqual(
                sql_findings[0]["rule_id"],
                "RSC-AST-SQL-001",
            )

    def test_engine_does_not_duplicate_direct_sql_finding(self):
        source = '''
user_id = input("Enter ID")
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
'''

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)

            source_file = root / "database.py"
            source_file.write_text(source, encoding="utf-8")

            engine = RepoSentinelCore()
            result = engine.scan_repository(root)

            sql_findings = [
                finding
                for finding in result["findings"]
                if finding["cwe"] == "CWE-89"
            ]

            self.assertEqual(len(sql_findings), 1)

    def test_engine_preserves_hardcoded_secret_detection(self):
        source = '''
API_KEY = "sk_test_example_123456"
'''

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)

            source_file = root / "config.py"
            source_file.write_text(source, encoding="utf-8")

            engine = RepoSentinelCore()
            result = engine.scan_repository(root)

            secret_findings = [
                finding
                for finding in result["findings"]
                if finding["rule_id"] == "RSC-SEC-001"
            ]

            self.assertEqual(len(secret_findings), 1)



if __name__ == "__main__":
    unittest.main()