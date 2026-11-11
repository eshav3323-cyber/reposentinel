import unittest

from app.scanners.reposentinel_core.analyzers.python_ast_analyzer import (
    PythonASTAnalyzer,
)


class TestPythonASTExceptionControlFlow(unittest.TestCase):
    """Tests taint tracking through Python exception-handling blocks."""

    def analyze(self, source: str):
        return PythonASTAnalyzer().analyze(
            source_code=source,
            file_path="exception_test.py",
        )

    def test_tainted_assignment_in_try_reaches_sql_sink(self):
        source = '''
user_id = "safe"

try:
    user_id = input("Enter ID")
except Exception:
    user_id = "safe"

cursor.execute(
    f"SELECT * FROM users WHERE id = {user_id}"
)
'''
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_tainted_assignment_in_except_reaches_sql_sink(self):
        source = '''
user_id = "safe"

try:
    user_id = "safe"
except Exception:
    user_id = input("Enter ID")

cursor.execute(
    f"SELECT * FROM users WHERE id = {user_id}"
)
'''
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_safe_assignment_in_finally_clears_previous_taint(self):
        source = '''
user_id = input("Enter ID")

try:
    pass
finally:
    user_id = "safe"

cursor.execute(
    f"SELECT * FROM users WHERE id = {user_id}"
)
'''
        findings = self.analyze(source)

        self.assertEqual(findings, [])

    def test_tainted_assignment_in_finally_reaches_sql_sink(self):
        source = '''
user_id = "safe"

try:
    pass
finally:
    user_id = input("Enter ID")

cursor.execute(
    f"SELECT * FROM users WHERE id = {user_id}"
)
'''
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_tainted_assignment_in_try_reaches_sql_sink_in_else(self):
        source = '''
user_id = "safe"

try:
    user_id = input("Enter ID")
except Exception:
    user_id = "safe"
else:
    cursor.execute(
        f"SELECT * FROM users WHERE id = {user_id}"
    )
'''
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_safe_try_and_except_paths_do_not_create_finding(self):
        source = '''
user_id = "safe"

try:
    user_id = "safe"
except Exception:
    user_id = "another_safe_value"

cursor.execute(
    f"SELECT * FROM users WHERE id = {user_id}"
)
'''
        findings = self.analyze(source)

        self.assertEqual(findings, [])

    def test_tainted_assignment_in_finally_is_not_lost_after_except(self):
        source = '''
user_id = "safe"

try:
    user_id = "safe"
except Exception:
    user_id = "safe"
finally:
    user_id = input("Enter ID")

cursor.execute(
    f"SELECT * FROM users WHERE id = {user_id}"
)
'''
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")


if __name__ == "__main__":
    unittest.main()