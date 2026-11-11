
import unittest

from app.scanners.reposentinel_core.analyzers.python_ast_analyzer import (
    PythonASTAnalyzer,
)


class TestPythonASTContextManagers(unittest.TestCase):

    def analyze(self, source: str):
        analyzer = PythonASTAnalyzer()
        return analyzer.analyze(
            source,
            "context_manager_test.py",
        )

    def test_tainted_context_value_reaches_sql_sink_inside_with(self):
        source = '''
with acquire_resource(input("Enter user ID")) as user_id:
    cursor.execute(
        f"SELECT * FROM users WHERE id = {user_id}"
    )
'''
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_tainted_context_value_remains_after_with_block(self):
        source = '''
with acquire_resource(input("Enter user ID")) as user_id:
    print("Resource acquired")

cursor.execute(
    f"SELECT * FROM users WHERE id = {user_id}"
)
'''
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_taint_flows_through_nested_context_managers(self):
        source = '''
with outer_resource(input("Enter user ID")) as outer_value:
    with inner_resource(outer_value) as user_id:
        cursor.execute(
            f"SELECT * FROM users WHERE id = {user_id}"
        )
'''
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_async_context_manager_tracks_tainted_value(self):
        source = '''
async def process():
    async with acquire_resource(input("Enter user ID")) as user_id:
        cursor.execute(
            f"SELECT * FROM users WHERE id = {user_id}"
        )
'''
        findings = self.analyze(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_safe_context_value_does_not_create_finding(self):
        source = '''
with acquire_resource("safe-user") as user_id:
    cursor.execute(
        f"SELECT * FROM users WHERE id = {user_id}"
    )
'''
        findings = self.analyze(source)

        self.assertEqual(len(findings), 0)

    def test_safe_reassignment_inside_with_clears_previous_taint(self):
        source = '''
user_id = input("Enter user ID")

with acquire_resource("safe-resource") as resource:
    user_id = "safe-user"

cursor.execute(
    f"SELECT * FROM users WHERE id = {user_id}"
)
'''
        findings = self.analyze(source)

        self.assertEqual(len(findings), 0)

    def test_context_manager_without_as_target_does_not_taint_unrelated_variable(self):
        source = '''
user_id = "safe-user"

with acquire_resource(input("Enter value")):
    print("Resource acquired")

cursor.execute(
    f"SELECT * FROM users WHERE id = {user_id}"
)
'''
        findings = self.analyze(source)

        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
