import unittest

from app.scanners.reposentinel_core.analyzers.python_ast_analyzer import (
    PythonASTAnalyzer,
)


class TestPythonASTComprehensions(unittest.TestCase):

    def analyze(self, source: str):
        analyzer = PythonASTAnalyzer()
        return analyzer.analyze(
            source,
            "comprehension_test.py",
        )

    def test_tainted_list_comprehension_target_reaches_sql_sink(self):
        source = """
user_ids = input("Enter user IDs")

[
    cursor.execute(
        f"SELECT * FROM users WHERE id = {user_id}"
    )
    for user_id in user_ids
]
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_tainted_set_comprehension_target_reaches_sql_sink(self):
        source = """
user_ids = input("Enter user IDs")

{
    cursor.execute(
        f"SELECT * FROM users WHERE id = {user_id}"
    )
    for user_id in user_ids
}
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_tainted_dictionary_comprehension_value_reaches_sql_sink(self):
        source = """
user_ids = input("Enter user IDs")

{
    user_id: cursor.execute(
        f"SELECT * FROM users WHERE id = {user_id}"
    )
    for user_id in user_ids
}
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_tainted_dictionary_comprehension_key_reaches_sql_sink(self):
        source = """
user_ids = input("Enter user IDs")

{
    cursor.execute(
        f"SELECT * FROM users WHERE id = {user_id}"
    ): user_id
    for user_id in user_ids
}
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_tainted_generator_expression_target_reaches_sql_sink(self):
        source = """
user_ids = input("Enter user IDs")

(
    cursor.execute(
        f"SELECT * FROM users WHERE id = {user_id}"
    )
    for user_id in user_ids
)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_taint_flows_through_nested_comprehension_generators(self):
        source = """
rows = input("Enter rows")

[
    cursor.execute(
        f"SELECT * FROM users WHERE id = {user_id}"
    )
    for row in rows
    for user_id in row
]
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_tainted_comprehension_target_reaches_sink_after_filter(self):
        source = """
user_ids = input("Enter user IDs")

[
    cursor.execute(
        f"SELECT * FROM users WHERE id = {user_id}"
    )
    for user_id in user_ids
    if user_id
]
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_destructured_comprehension_target_preserves_taint(self):
        source = """
records = input("Enter records")

[
    cursor.execute(
        f"SELECT * FROM users WHERE id = {user_id}"
    )
    for user_id, role in records
]
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_safe_comprehension_does_not_create_finding(self):
        source = """
user_ids = ["safe-user", "another-safe-user"]

[
    cursor.execute(
        f"SELECT * FROM users WHERE id = {user_id}"
    )
    for user_id in user_ids
]
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 0)

    def test_comprehension_target_does_not_leak_into_outer_scope(self):
        source = """
user_id = "safe-user"

[
    value
    for user_id in input("Enter user IDs")
    for value in [user_id]
]

cursor.execute(
    f"SELECT * FROM users WHERE id = {user_id}"
)
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 0)

    def test_nested_list_comprehension_tracks_inner_target(self):
        source = """
rows = input("Enter rows")

[
    [
        cursor.execute(
            f"SELECT * FROM users WHERE id = {user_id}"
        )
        for user_id in row
    ]
    for row in rows
]
"""
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")


if __name__ == "__main__":
    unittest.main()
