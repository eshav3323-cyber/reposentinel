
import unittest

from app.scanners.reposentinel_core.analyzers.python_ast_analyzer import (
    PythonASTAnalyzer,
)


class TestPythonASTAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = PythonASTAnalyzer()

    def test_detects_user_input_flowing_into_sql_query(self):
        source = '''
user_id = input("Enter user ID")
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)
'''

        findings = self.analyzer.analyze(source, "app.py")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "RSC-AST-SQL-001")
        self.assertEqual(findings[0].severity, "HIGH")

    def test_detects_request_parameter_flowing_into_sql(self):
        source = '''
user_id = request.args.get("id")
query = "SELECT * FROM users WHERE id = " + user_id
cursor.execute(query)
'''

        findings = self.analyzer.analyze(source, "app.py")

        self.assertEqual(len(findings), 1)

    def test_detects_user_input_with_string_format(self):
        source = '''
user_id = input()
query = "SELECT * FROM users WHERE id = {}".format(user_id)
cursor.execute(query)
'''

        findings = self.analyzer.analyze(source, "app.py")

        self.assertEqual(len(findings), 1)

    def test_does_not_flag_parameterized_query(self):
        source = '''
user_id = input()
cursor.execute(
    "SELECT * FROM users WHERE id = ?",
    (user_id,)
)
'''

        findings = self.analyzer.analyze(source, "app.py")

        self.assertEqual(findings, [])

    def test_does_not_flag_constant_query(self):
        source = '''
query = "SELECT * FROM users"
cursor.execute(query)
'''

        findings = self.analyzer.analyze(source, "app.py")

        self.assertEqual(findings, [])

    def test_does_not_flag_unrelated_dynamic_string(self):
        source = '''
user_id = input()
message = f"Hello {user_id}"
print(message)
'''

        findings = self.analyzer.analyze(source, "app.py")

        self.assertEqual(findings, [])

    def test_handles_invalid_python_source(self):
        source = '''
def broken_function(
    print("missing closing parenthesis"
'''

        findings = self.analyzer.analyze(source, "app.py")

        self.assertEqual(findings, [])

    def test_tracks_simple_variable_alias(self):
        source = '''
user_id = input()
copied_id = user_id
query = f"SELECT * FROM users WHERE id = {copied_id}"
cursor.execute(query)
'''

        findings = self.analyzer.analyze(source, "app.py")

        self.assertEqual(len(findings), 1)

    def test_finding_contains_correct_file_path(self):
        source = '''
user_id = input()
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)
'''

        findings = self.analyzer.analyze(
            source,
            "src/database.py",
        )

        self.assertEqual(findings[0].file_path, "src/database.py")

    def test_finding_contains_execution_line_number(self):
        source = '''user_id = input()
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)
'''

        findings = self.analyzer.analyze(source, "app.py")

        self.assertEqual(findings[0].line_number, 3)

    def test_analyzer_can_scan_multiple_files_sequentially(self):
        vulnerable_source = '''
user_id = input()
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)
'''

        safe_source = '''
query = "SELECT * FROM users"
cursor.execute(query)
'''

        first = self.analyzer.analyze(
            vulnerable_source,
            "first.py",
        )

        second = self.analyzer.analyze(
            safe_source,
            "second.py",
        )

        self.assertEqual(len(first), 1)
        self.assertEqual(len(second), 0)


if __name__ == "__main__":
    unittest.main()
