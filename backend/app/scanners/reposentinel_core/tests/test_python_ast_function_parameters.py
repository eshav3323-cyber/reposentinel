
import ast
import unittest

from app.scanners.reposentinel_core.analyzers.python_ast_analyzer import (
    PythonASTAnalyzer,
    FunctionParameters,
)


class TestPythonFunctionParameterModel(unittest.TestCase):

    def setUp(self):
        # Avoid depending on the analyzer's normal scan initialization.
        self.analyzer = PythonASTAnalyzer.__new__(PythonASTAnalyzer)

    def get_function_parameters(self, source):
        tree = ast.parse(source)

        function = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        )

        return self.analyzer._collect_function_parameters(function.args)

    def test_collects_positional_only_parameters(self):
        parameters = self.get_function_parameters(
            """
def fetch(user_id, account_id, /):
    pass
"""
        )

        self.assertEqual(
            parameters.positional_only,
            ("user_id", "account_id"),
        )

    def test_collects_positional_or_keyword_parameters(self):
        parameters = self.get_function_parameters(
            """
def fetch(user_id, account_id):
    pass
"""
        )

        self.assertEqual(
            parameters.positional_or_keyword,
            ("user_id", "account_id"),
        )

    def test_collects_var_positional_parameter(self):
        parameters = self.get_function_parameters(
            """
def fetch(user_id, *records):
    pass
"""
        )

        self.assertEqual(parameters.var_positional, "records")

    def test_collects_keyword_only_parameters(self):
        parameters = self.get_function_parameters(
            """
def fetch(user_id, *, table, limit):
    pass
"""
        )

        self.assertEqual(
            parameters.keyword_only,
            ("table", "limit"),
        )

    def test_collects_var_keyword_parameter(self):
        parameters = self.get_function_parameters(
            """
def fetch(user_id, **options):
    pass
"""
        )

        self.assertEqual(parameters.var_keyword, "options")

    def test_collects_all_parameter_categories_together(self):
        parameters = self.get_function_parameters(
            """
def fetch(user_id, /, account_id, *records, table, limit=10, **options):
    pass
"""
        )

        self.assertEqual(parameters.positional_only, ("user_id",))
        self.assertEqual(
            parameters.positional_or_keyword,
            ("account_id",),
        )
        self.assertEqual(parameters.var_positional, "records")
        self.assertEqual(
            parameters.keyword_only,
            ("table", "limit"),
        )
        self.assertEqual(parameters.var_keyword, "options")

    def test_all_names_preserves_parameter_declaration_order(self):
        parameters = self.get_function_parameters(
            """
def fetch(user_id, /, account_id, *records, table, **options):
    pass
"""
        )

        self.assertEqual(
            parameters.all_names,
            (
                "user_id",
                "account_id",
                "records",
                "table",
                "options",
            ),
        )

    def test_handles_function_without_special_parameter_types(self):
        parameters = self.get_function_parameters(
            """
def fetch(user_id, account_id):
    pass
"""
        )

        self.assertEqual(parameters.positional_only, ())
        self.assertEqual(
            parameters.positional_or_keyword,
            ("user_id", "account_id"),
        )
        self.assertIsNone(parameters.var_positional)
        self.assertEqual(parameters.keyword_only, ())
        self.assertIsNone(parameters.var_keyword)

    def test_handles_async_function_parameters(self):
        parameters = self.get_function_parameters(
            """
async def fetch(user_id, *, table):
    pass
"""
        )

        self.assertEqual(
            parameters.positional_or_keyword,
            ("user_id",),
        )
        self.assertEqual(parameters.keyword_only, ("table",))


if __name__ == "__main__":
    unittest.main()
