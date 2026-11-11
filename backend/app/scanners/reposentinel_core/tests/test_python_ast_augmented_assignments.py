
import unittest

from app.scanners.reposentinel_core.analyzers.python_ast_analyzer import (
    PythonASTAnalyzer,
)


class TestPythonASTAugmentedAssignments(unittest.TestCase):

    def analyze(self, source: str):
        analyzer = PythonASTAnalyzer()
        return analyzer.analyze(
            source,
            "augmented_assignment_test.py",
        )

    def test_tainted_right_operand_of_addition_reaches_sql_sink(self):
        source = """
query = "SELECT * FROM users WHERE id = "
user_id = input("Enter user ID")

query += user_id

cursor.execute(query)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_tainted_left_operand_preserves_taint_after_addition(self):
        source = """
query = input("Enter query")

query += " AND active = 1"

cursor.execute(query)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_tainted_value_preserves_taint_after_multiplication(self):
        source = """
query = input("Enter query")

query *= 2

cursor.execute(query)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_safe_augmented_addition_does_not_create_finding(self):
        source = """
query = "SELECT * FROM users WHERE id = "

query += "safe-user"

cursor.execute(query)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 0)

    def test_safe_reassignment_clears_previous_augmented_taint(self):
        source = """
query = "SELECT * FROM users WHERE id = "
query += input("Enter user ID")

query = "SELECT * FROM users WHERE id = safe-user"

cursor.execute(query)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 0)

    def test_tainted_augmented_assignment_reaches_multiple_sinks(self):
        source = """
query = "SELECT * FROM users WHERE id = "
query += input("Enter user ID")

cursor.execute(query)
cursor.execute(query)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 2)

        for finding in findings:
            self.assertEqual(finding.cwe, "CWE-89")


if __name__ == "__main__":
    unittest.main()
