
import unittest

from app.scanners.reposentinel_core.analyzers.python_ast_analyzer import (
    PythonASTAnalyzer,
)


class TestPythonASTChainedAssignments(unittest.TestCase):

    def analyze(self, source: str):
        analyzer = PythonASTAnalyzer()
        return analyzer.analyze(
            source,
            "chained_assignment_test.py",
        )

    def test_tainted_chained_assignment_reaches_first_target(self):
        source = """
first_id = second_id = input("Enter user ID")

cursor.execute(
    f"SELECT * FROM users WHERE id = {first_id}"
)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_tainted_chained_assignment_reaches_second_target(self):
        source = """
first_id = second_id = input("Enter user ID")

cursor.execute(
    f"SELECT * FROM users WHERE id = {second_id}"
)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_all_chained_targets_preserve_taint(self):
        source = """
first_id = second_id = third_id = input("Enter user ID")

cursor.execute(
    f"SELECT * FROM users WHERE id = {first_id}"
)

cursor.execute(
    f"SELECT * FROM users WHERE id = {second_id}"
)

cursor.execute(
    f"SELECT * FROM users WHERE id = {third_id}"
)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 3)

        for finding in findings:
            self.assertEqual(finding.cwe, "CWE-89")

    def test_safe_chained_assignment_does_not_create_finding(self):
        source = """
first_id = second_id = "safe-user"

cursor.execute(
    f"SELECT * FROM users WHERE id = {first_id}"
)

cursor.execute(
    f"SELECT * FROM users WHERE id = {second_id}"
)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 0)

    def test_safe_chained_reassignment_clears_previous_taint(self):
        source = """
first_id = second_id = input("Enter user ID")

first_id = second_id = "safe-user"

cursor.execute(
    f"SELECT * FROM users WHERE id = {first_id}"
)

cursor.execute(
    f"SELECT * FROM users WHERE id = {second_id}"
)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 0)

    def test_chained_assignment_preserves_conditional_expression_taint(self):
        source = """
user_id = input("Enter user ID")
use_user = True

first_id = second_id = (
    user_id if use_user else "safe-user"
)

cursor.execute(
    f"SELECT * FROM users WHERE id = {first_id}"
)

cursor.execute(
    f"SELECT * FROM users WHERE id = {second_id}"
)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 2)

        for finding in findings:
            self.assertEqual(finding.cwe, "CWE-89")


if __name__ == "__main__":
    unittest.main()

