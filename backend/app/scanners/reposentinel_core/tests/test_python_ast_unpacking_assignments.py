
import unittest

from app.scanners.reposentinel_core.analyzers.python_ast_analyzer import (
    PythonASTAnalyzer,
)


class TestPythonASTUnpackingAssignments(unittest.TestCase):

    def analyze(self, source: str):
        analyzer = PythonASTAnalyzer()
        return analyzer.analyze(
            source,
            "unpacking_assignment_test.py",
        )

    def test_tainted_tuple_unpacking_reaches_sql_sink(self):
        source = """
user_id, role = (input("Enter user ID"), "admin")

cursor.execute(
    f"SELECT * FROM users WHERE id = {user_id}"
)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_tainted_list_unpacking_reaches_sql_sink(self):
        source = """
[user_id, role] = [input("Enter user ID"), "admin"]

cursor.execute(
    f"SELECT * FROM users WHERE id = {user_id}"
)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_tainted_second_unpacking_target_reaches_sql_sink(self):
        source = """
role, user_id = ("admin", input("Enter user ID"))

cursor.execute(
    f"SELECT * FROM users WHERE id = {user_id}"
)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_nested_tuple_unpacking_preserves_taint(self):
        source = """
(role, (user_id, status)) = (
    "admin",
    (input("Enter user ID"), "active")
)

cursor.execute(
    f"SELECT * FROM users WHERE id = {user_id}"
)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_starred_unpacking_preserves_taint(self):
        source = """
first, *remaining = (
    "safe-value",
    input("Enter user ID"),
    "another-value"
)

cursor.execute(
    f"SELECT * FROM users WHERE id = {remaining[0]}"
)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_safe_tuple_unpacking_does_not_create_finding(self):
        source = """
user_id, role = ("safe-user", "admin")

cursor.execute(
    f"SELECT * FROM users WHERE id = {user_id}"
)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 0)

    def test_safe_reassignment_after_unpacking_clears_taint(self):
        source = """
user_id, role = (input("Enter user ID"), "admin")

user_id, role = ("safe-user", "admin")

cursor.execute(
    f"SELECT * FROM users WHERE id = {user_id}"
)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 0)

    def test_unpacking_from_tainted_input_preserves_taint(self):
        source = """
records = input("Enter records")
user_id, role = records

cursor.execute(
    f"SELECT * FROM users WHERE id = {user_id}"
)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_underscore_unpacking_target_does_not_affect_other_target(self):
        source = """
_, user_id = ("ignored", input("Enter user ID"))

cursor.execute(
    f"SELECT * FROM users WHERE id = {user_id}"
)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")


if __name__ == "__main__":
    unittest.main()
