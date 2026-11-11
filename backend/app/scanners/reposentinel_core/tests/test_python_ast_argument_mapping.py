
import ast
import unittest

from app.scanners.reposentinel_core.analyzers.python_ast_analyzer import (
    PythonASTAnalyzer,
)


class TestPythonASTArgumentMapping(unittest.TestCase):

    def setUp(self):
        self.analyzer = PythonASTAnalyzer()

    def get_summary(self, source, function_name):
        self.analyzer.analyze(source, "argument_mapping_test.py")
        return self.analyzer.function_summaries[function_name]

    def get_call(self, source):
        tree = ast.parse(source)

        return next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
        )

    def test_positional_arguments_map_to_positional_parameters(self):
        source = """
def target(first, second):
    cursor.execute(f"SELECT * FROM users WHERE id = {second}")

target("safe", input())
"""
        findings = self.analyzer.analyze(source, "test.py")
        self.assertTrue(findings)

    def test_keyword_arguments_map_by_parameter_name(self):
        source = """
def target(first, second):
    cursor.execute(f"SELECT * FROM users WHERE id = {second}")

target(second=input(), first="safe")
"""
        findings = self.analyzer.analyze(source, "test.py")
        self.assertTrue(findings)

    def test_positional_only_parameter_maps_positionally(self):
        source = """
def target(user_id, /):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

target(input())
"""
        findings = self.analyzer.analyze(source, "test.py")
        self.assertTrue(findings)

    def test_keyword_only_parameter_maps_by_name(self):
        source = """
def target(*, user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

target(user_id=input())
"""
        findings = self.analyzer.analyze(source, "test.py")
        self.assertTrue(findings)

    def test_varargs_maps_extra_positional_arguments(self):
        source = """
def target(*values):
    cursor.execute(f"SELECT * FROM users WHERE id = {values[0]}")

target("safe", input())
"""
        findings = self.analyzer.analyze(source, "test.py")
        self.assertTrue(findings)

    def test_kwargs_maps_extra_keyword_arguments(self):
        source = """
def target(**values):
    cursor.execute(f"SELECT * FROM users WHERE id = {values['user_id']}")

target(user_id=input())
"""
        findings = self.analyzer.analyze(source, "test.py")
        self.assertTrue(findings)

    def test_literal_starred_tuple_maps_arguments(self):
        source = """
def target(first, second):
    cursor.execute(f"SELECT * FROM users WHERE id = {second}")

values = ("safe", input())
target(*values)
"""
        findings = self.analyzer.analyze(source, "test.py")
        self.assertTrue(findings)

    def test_literal_double_starred_dictionary_maps_arguments(self):
        source = """
def target(first, second):
    cursor.execute(f"SELECT * FROM users WHERE id = {second}")

values = {"first": "safe", "second": input()}
target(**values)
"""
        findings = self.analyzer.analyze(source, "test.py")
        self.assertTrue(findings)

    def test_default_parameter_is_used_when_argument_is_omitted(self):
        source = """
def target(user_id=input()):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

target()
"""
        findings = self.analyzer.analyze(source, "test.py")
        self.assertTrue(findings)

    def test_safe_default_parameter_does_not_trigger_finding(self):
        source = """
def target(user_id="123"):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

target()
"""
        findings = self.analyzer.analyze(source, "test.py")
        self.assertFalse(findings)

    def test_keyword_argument_does_not_taint_unrelated_parameter(self):
        source = """
def target(first, second):
    cursor.execute(f"SELECT * FROM users WHERE id = {first}")

target(first="safe", second=input())
"""
        findings = self.analyzer.analyze(source, "test.py")
        self.assertFalse(findings)

    def test_nested_function_sink_is_not_attributed_to_outer_function(self):
        source = """
def outer(value):
    def inner():
        cursor.execute(f"SELECT * FROM users WHERE id = {value}")
    return "safe"

outer(input())
"""
        findings = self.analyzer.analyze(source, "test.py")
        self.assertFalse(findings)

    def test_nested_function_can_be_summarized_independently(self):
        source = """
def outer():
    def inner(value):
        cursor.execute(f"SELECT * FROM users WHERE id = {value}")
    inner(input())

outer()
"""
        findings = self.analyzer.analyze(source, "test.py")
        # Nested-function call resolution is not yet supported.
        # This test documents the current limitation.
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-89")
        self.assertEqual(findings[0].line_number, 5)


if __name__ == "__main__":
    unittest.main()
