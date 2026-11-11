
import unittest

from app.scanners.reposentinel_core.analyzers.python_ast_analyzer import (
    PythonASTAnalyzer,
)


class TestPythonASTConditionalExpressions(unittest.TestCase):

    def analyze(self, source: str):
        analyzer = PythonASTAnalyzer()
        return analyzer.analyze(
            source,
            "conditional_expression_test.py",
        )

    def test_tainted_true_branch_reaches_sql_sink(self):
        source = """
user_id = input("Enter user ID")
use_user = True

query = (
    f"SELECT * FROM users WHERE id = {user_id}"
    if use_user
    else "SELECT * FROM users"
)

cursor.execute(query)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_tainted_false_branch_reaches_sql_sink(self):
        source = """
user_id = input("Enter user ID")
use_user = False

query = (
    "SELECT * FROM users"
    if use_user
    else f"SELECT * FROM users WHERE id = {user_id}"
)

cursor.execute(query)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_tainted_values_in_both_branches_reach_sql_sink(self):
        source = """
first_id = input("Enter first ID")
second_id = input("Enter second ID")
use_first = True

query = (
    f"SELECT * FROM users WHERE id = {first_id}"
    if use_first
    else f"SELECT * FROM users WHERE id = {second_id}"
)

cursor.execute(query)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_safe_values_in_both_branches_do_not_create_finding(self):
        source = """
use_first = True

query = (
    "SELECT * FROM users WHERE id = 10"
    if use_first
    else "SELECT * FROM users WHERE id = 20"
)

cursor.execute(query)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 0)

    def test_nested_conditional_expression_preserves_taint(self):
        source = """
user_id = input("Enter user ID")
first_condition = True
second_condition = False

query = (
    (
        f"SELECT * FROM users WHERE id = {user_id}"
        if first_condition
        else "SELECT * FROM users"
    )
    if second_condition
    else "SELECT * FROM users"
)

cursor.execute(query)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_safe_reassignment_clears_conditional_expression_taint(self):
        source = """
user_id = input("Enter user ID")
use_user = True

query = (
    f"SELECT * FROM users WHERE id = {user_id}"
    if use_user
    else "SELECT * FROM users"
)

query = "SELECT * FROM users"

cursor.execute(query)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
