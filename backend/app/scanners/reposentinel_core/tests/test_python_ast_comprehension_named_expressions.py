
import unittest

from app.scanners.reposentinel_core.analyzers.python_ast_analyzer import (
    PythonASTAnalyzer,
)


class TestPythonASTComprehensionNamedExpressions(unittest.TestCase):

    def analyze(self, source: str):
        analyzer = PythonASTAnalyzer()
        return analyzer.analyze(
            source,
            "comprehension_named_expression_test.py",
        )

    def test_tainted_walrus_target_from_list_comprehension_reaches_later_sink(self):
        source = """
user_ids = input("Enter user IDs")

[
    (captured_id := user_id)
    for user_id in user_ids
]

cursor.execute(
    f"SELECT * FROM users WHERE id = {captured_id}"
)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_tainted_walrus_target_in_filter_reaches_later_sink(self):
        source = """
user_ids = input("Enter user IDs")

[
    user_id
    for user_id in user_ids
    if (captured_id := user_id)
]

cursor.execute(
    f"SELECT * FROM users WHERE id = {captured_id}"
)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_tainted_walrus_target_from_nested_comprehension_reaches_later_sink(self):
        source = """
rows = input("Enter rows")

[
    [
        (captured_id := user_id)
        for user_id in row
    ]
    for row in rows
]

cursor.execute(
    f"SELECT * FROM users WHERE id = {captured_id}"
)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_safe_walrus_target_does_not_create_finding(self):
        source = """
user_ids = ["safe-user", "another-safe-user"]

[
    (captured_id := user_id)
    for user_id in user_ids
]

cursor.execute(
    f"SELECT * FROM users WHERE id = {captured_id}"
)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 0)

    def test_walrus_target_does_not_leak_comprehension_variable(self):
        source = """
user_ids = input("Enter user IDs")
user_id = "safe-user"

[
    (captured_value := user_id)
    for user_id in user_ids
]

cursor.execute(
    f"SELECT * FROM users WHERE id = {user_id}"
)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 0)

    def test_tainted_walrus_target_from_dictionary_comprehension_reaches_sink(self):
        source = """
user_ids = input("Enter user IDs")

{
    user_id: (captured_id := user_id)
    for user_id in user_ids
}

cursor.execute(
    f"SELECT * FROM users WHERE id = {captured_id}"
)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_safe_walrus_assignment_clears_previous_taint(self):
        source = """
captured_id = input("Enter an ID")

[
    (captured_id := user_id)
    for user_id in ["safe-user"]
]

cursor.execute(
    f"SELECT * FROM users WHERE id = {captured_id}"
)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
