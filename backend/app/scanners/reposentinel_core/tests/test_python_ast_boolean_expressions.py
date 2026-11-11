
import unittest

from app.scanners.reposentinel_core.analyzers.python_ast_analyzer import (
    PythonASTAnalyzer,
)


class TestPythonASTBooleanExpressions(unittest.TestCase):

    def analyze(self, source: str):
        analyzer = PythonASTAnalyzer()
        return analyzer.analyze(
            source,
            "boolean_expression_test.py",
        )

    def test_tainted_left_operand_of_or_reaches_sql_sink(self):
        source = """
user_id = input("Enter user ID")

query = user_id or "safe-user"

cursor.execute(
    f"SELECT * FROM users WHERE id = {query}"
)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_tainted_right_operand_of_or_reaches_sql_sink(self):
        source = """
user_id = input("Enter user ID")

query = "safe-user" or user_id

cursor.execute(
    f"SELECT * FROM users WHERE id = {query}"
)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_tainted_right_operand_of_and_reaches_sql_sink(self):
        source = """
user_id = input("Enter user ID")

query = "enabled" and user_id

cursor.execute(
    f"SELECT * FROM users WHERE id = {query}"
)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_tainted_left_operand_of_and_reaches_sql_sink(self):
        source = """
user_id = input("Enter user ID")

query = user_id and "safe-user"

cursor.execute(
    f"SELECT * FROM users WHERE id = {query}"
)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_nested_boolean_expression_preserves_taint(self):
        source = """
user_id = input("Enter user ID")
enabled = True

query = (enabled and user_id) or "safe-user"

cursor.execute(
    f"SELECT * FROM users WHERE id = {query}"
)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_safe_boolean_operands_do_not_create_finding(self):
        source = """
first_value = "safe-user"
second_value = "another-safe-user"

query = first_value and second_value

cursor.execute(
    f"SELECT * FROM users WHERE id = {query}"
)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 0)

    def test_not_operator_does_not_preserve_string_taint(self):
        source = """
user_id = input("Enter user ID")

query = not user_id

cursor.execute(
    f"SELECT * FROM users WHERE id = {query}"
)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
