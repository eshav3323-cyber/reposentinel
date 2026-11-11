
import unittest

from app.scanners.reposentinel_core.analyzers.python_ast_analyzer import (
    PythonASTAnalyzer,
)


class TestPythonASTMatchControlFlow(unittest.TestCase):

    def analyze(self, source: str):
        analyzer = PythonASTAnalyzer()
        return analyzer.analyze(
            source,
            "match_test.py",
        )

    def test_tainted_assignment_in_case_reaches_sql_sink(self):
        source = '''
user_id = "safe"

match action:
    case "search":
        user_id = input("Enter ID")
    case _:
        user_id = "safe"

cursor.execute(
    f"SELECT * FROM users WHERE id = {user_id}"
)
'''
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_safe_assignments_in_all_cases_do_not_create_finding(self):
        source = '''
user_id = input("Enter ID")

match action:
    case "search":
        user_id = "safe"
    case "update":
        user_id = "admin"
    case _:
        user_id = "guest"

cursor.execute(
    f"SELECT * FROM users WHERE id = {user_id}"
)
'''
        findings = self.analyze(source)

        self.assertEqual(len(findings), 0)

    def test_tainted_assignment_in_one_of_multiple_cases_is_detected(self):
        source = '''
user_id = "safe"

match action:
    case "create":
        user_id = "safe"
    case "update":
        user_id = input("Enter ID")
    case "delete":
        user_id = "admin"
    case _:
        user_id = "guest"

cursor.execute(
    f"SELECT * FROM users WHERE id = {user_id}"
)
'''
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_tainted_case_followed_by_safe_case_is_not_lost(self):
        source = '''
user_id = "safe"

match action:
    case "search":
        user_id = input("Enter ID")
    case "update":
        user_id = "admin"
    case _:
        user_id = "guest"

cursor.execute(
    f"SELECT * FROM users WHERE id = {user_id}"
)
'''
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_tainted_assignment_inside_case_reaches_sink_inside_same_case(self):
        source = '''
match action:
    case "search":
        user_id = input("Enter ID")
        cursor.execute(
            f"SELECT * FROM users WHERE id = {user_id}"
        )
    case _:
        pass
'''
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_case_without_matching_default_preserves_initial_state(self):
        source = '''
user_id = input("Enter ID")

match action:
    case "search":
        user_id = "safe"

cursor.execute(
    f"SELECT * FROM users WHERE id = {user_id}"
)
'''
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_unrelated_case_variable_does_not_taint_sql_query(self):
        source = '''
user_id = "safe"

match action:
    case "search":
        other_value = input("Enter value")
    case _:
        other_value = "safe"

cursor.execute(
    f"SELECT * FROM users WHERE id = {user_id}"
)
'''
        findings = self.analyze(source)

        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
