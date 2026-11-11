import hashlib
import tempfile
import unittest
from pathlib import Path

from app.scanners.reposentinel_core.analyzers.python_ast_analyzer import (
    PythonASTAnalyzer,
)
from app.scanners.reposentinel_core.config import ScannerConfig
from app.scanners.reposentinel_core.engine import RepoSentinelCore
from app.scanners.reposentinel_core.repository_analyzer import (
    RepositoryAnalyzer,
)


class TestRepositoryAnalyzer(unittest.TestCase):

    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_directory.name)

    def tearDown(self):
        self.temp_directory.cleanup()

    def create_file(self, relative_path, content):
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def test_detects_python_file(self):
        self.create_file("app.py", b"print('hello')")

        report = RepositoryAnalyzer().analyze(self.root)

        self.assertEqual(report.analyzed_files, 1)
        self.assertEqual(report.language_counts["Python"], 1)

    def test_detects_javascript_file(self):
        self.create_file("app.js", b"console.log('hello')")

        report = RepositoryAnalyzer().analyze(self.root)

        self.assertEqual(report.analyzed_files, 1)
        self.assertEqual(report.language_counts["JavaScript"], 1)

    def test_detects_typescript_file(self):
        self.create_file("app.ts", b"const value: number = 10;")

        report = RepositoryAnalyzer().analyze(self.root)

        self.assertEqual(report.analyzed_files, 1)
        self.assertEqual(report.language_counts["TypeScript"], 1)

    def test_ignores_node_modules(self):
        self.create_file("app.js", b"console.log('hello')")
        self.create_file(
            "node_modules/package/index.js",
            b"console.log('ignored')"
        )

        report = RepositoryAnalyzer().analyze(self.root)

        self.assertEqual(report.analyzed_files, 1)
        self.assertEqual(
            report.skipped_reasons["ignored_directory"],
            1
        )

    def test_skips_unsupported_extension(self):
        self.create_file("notes.txt", b"Some text")

        report = RepositoryAnalyzer().analyze(self.root)

        self.assertEqual(report.analyzed_files, 0)
        self.assertEqual(
            report.skipped_reasons["unsupported_extension"],
            1
        )

    def test_skips_binary_files(self):
        self.create_file("image.py", b"\x00\x01\x02\x03")

        report = RepositoryAnalyzer().analyze(self.root)

        self.assertEqual(report.analyzed_files, 0)
        self.assertEqual(
            report.skipped_reasons["binary_file"],
            1
        )

    def test_skips_oversized_files(self):
        config = ScannerConfig(max_file_size_bytes=5)

        self.create_file("large.py", b"123456789")

        report = RepositoryAnalyzer(config).analyze(self.root)

        self.assertEqual(report.analyzed_files, 0)
        self.assertEqual(
            report.skipped_reasons["file_too_large"],
            1
        )

    def test_generates_correct_sha256(self):
        content = b"print('RepoSentinel')"
        self.create_file("app.py", content)

        report = RepositoryAnalyzer().analyze(self.root)

        expected_hash = hashlib.sha256(content).hexdigest()

        self.assertEqual(report.files[0].sha256, expected_hash)

    def test_rejects_nonexistent_repository(self):
        invalid_path = self.root / "does_not_exist"

        with self.assertRaises(ValueError):
            RepositoryAnalyzer().analyze(invalid_path)

    def test_engine_returns_structured_report(self):
        self.create_file("app.py", b"print('test')")

        result = RepoSentinelCore().scan_repository(self.root)

        self.assertEqual(result["scanner"], "RepoSentinel Core")
        self.assertEqual(result["version"], "0.2.0")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(
            result["report"]["analyzed_files"],
            1
        )
    def test_file_count_limit_truncates_scan(self):
        config = ScannerConfig(max_files=1)

        self.create_file("first.py", b"print('first')")
        self.create_file("second.py", b"print('second')")

        report = RepositoryAnalyzer(config).analyze(self.root)

        self.assertEqual(report.analyzed_files, 1)
        self.assertTrue(report.scan_truncated)
        self.assertEqual(
            report.truncation_reason,
            "maximum_file_limit_reached"
        )

    def test_skips_symbolic_link(self):
        target = self.create_file("target.py", b"print('target')")
        link = self.root / "linked.py"

        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("Symbolic links are unavailable on this system.")

        report = RepositoryAnalyzer().analyze(self.root)

        self.assertEqual(report.analyzed_files, 1)
        self.assertEqual(
            report.skipped_reasons.get("symbolic_link"),
            1
        )

    def test_rejects_symbolic_link_as_repository_root(self):
        target = self.root / "actual_repository"
        target.mkdir()

        link = self.root / "repository_link"

        try:
            link.symlink_to(target, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("Directory symbolic links are unavailable.")

        with self.assertRaises(ValueError):
            RepositoryAnalyzer().analyze(link)

    def test_function_parameter_taint_reaches_sql_sink(self):
        source = """
def execute_query(user_id):
    query = f\"SELECT * FROM users WHERE id = {user_id}\"
    cursor.execute(query)

user_id = input()
execute_query(user_id)
"""

        findings = PythonASTAnalyzer().analyze(source, "app.py")

        self.assertTrue(any(finding.cwe == "CWE-89" for finding in findings))

    def test_function_return_value_taint_reaches_sql_sink(self):
        source = """
def build_query(user_id):
    return f\"SELECT * FROM users WHERE id = {user_id}\"

user_id = input()
query = build_query(user_id)
cursor.execute(query)
"""

        findings = PythonASTAnalyzer().analyze(source, "app.py")

        self.assertTrue(any(finding.cwe == "CWE-89" for finding in findings))

    def test_multiple_function_parameters_are_handled_conservatively(self):
        source = """
def build_query(user_id, tenant_id):
    return f\"SELECT * FROM {tenant_id} WHERE id = {user_id}\"

user_id = input()
tenant_id = "public"
query = build_query(user_id, tenant_id)
cursor.execute(query)
"""

        findings = PythonASTAnalyzer().analyze(source, "app.py")

        self.assertTrue(any(finding.cwe == "CWE-89" for finding in findings))

    def test_safe_function_calls_do_not_trigger_sql_finding(self):
        source = """
def safe_lookup(user_id):
    return str(user_id)

user_id = input()
value = safe_lookup(user_id)
print(value)
"""

        findings = PythonASTAnalyzer().analyze(source, "app.py")

        self.assertEqual(findings, [])

    def test_recursive_function_calls_are_protected(self):
        source = """
def loop(value):
    return loop(value)

user_id = input()
loop(user_id)
"""

        findings = PythonASTAnalyzer().analyze(source, "app.py")

        self.assertEqual(findings, [])

    def test_function_call_with_renamed_callee_parameter_is_detected(self):
        source = """
def execute_query(user_id):
    query = f\"SELECT * FROM users WHERE id = {user_id}\"
    cursor.execute(query)

customer_id = input()
execute_query(customer_id)
"""

        findings = PythonASTAnalyzer().analyze(source, "app.py")

        self.assertTrue(any(finding.cwe == "CWE-89" for finding in findings))

    def test_unused_tainted_parameter_does_not_trigger_sql_finding(self):
        source = """
def execute_query(user_id, department):
    query = f\"SELECT * FROM users WHERE id = {user_id}\"
    cursor.execute(query)

safe_id = \"123\"
department = input()
execute_query(safe_id, department)
"""

        findings = PythonASTAnalyzer().analyze(source, "app.py")

        self.assertEqual(findings, [])

    def test_constant_argument_passed_to_vulnerable_function_is_safe(self):
        source = """
def execute_query(user_id):
    query = f\"SELECT * FROM users WHERE id = {user_id}\"
    cursor.execute(query)

execute_query(\"123\")
"""

        findings = PythonASTAnalyzer().analyze(source, "app.py")

        self.assertEqual(findings, [])

    def test_keyword_argument_mapping_uses_formal_parameter(self):
        source = """
def execute_query(user_id):
    query = f\"SELECT * FROM users WHERE id = {user_id}\"
    cursor.execute(query)

customer_id = input()
execute_query(user_id=customer_id)
"""

        findings = PythonASTAnalyzer().analyze(source, "app.py")

        self.assertTrue(any(finding.cwe == "CWE-89" for finding in findings))

    def test_return_value_taint_with_renamed_caller_variable_is_propagated(self):
        source = """
def build_query(user_id):
    return f\"SELECT * FROM users WHERE id = {user_id}\"

customer_id = input()
query = build_query(customer_id)
cursor.execute(query)
"""

        findings = PythonASTAnalyzer().analyze(source, "app.py")

        self.assertTrue(any(finding.cwe == "CWE-89" for finding in findings))

    def test_constant_return_is_not_marked_tainted(self):
        source = """
def build_query(user_id):
    return \"SELECT * FROM users\"

customer_id = input()
query = build_query(customer_id)
print(query)
"""

        findings = PythonASTAnalyzer().analyze(source, "app.py")

        self.assertEqual(findings, [])

    def test_defined_but_never_called_function_is_not_reported(self):
        source = """
def execute_query(user_id):
    query = f\"SELECT * FROM users WHERE id = {user_id}\"
    cursor.execute(query)

value = \"123\"
"""

        findings = PythonASTAnalyzer().analyze(source, "app.py")

        self.assertEqual(findings, [])

    def test_duplicate_findings_are_removed(self):
        source = """
def build_query(user_id):
    return f\"SELECT * FROM users WHERE id = {user_id}\"

user_id = input()
query = build_query(user_id)
cursor.execute(query)
"""

        findings = PythonASTAnalyzer().analyze(source, "app.py")
        cwe_matches = [finding for finding in findings if finding.cwe == "CWE-89"]

        self.assertEqual(len(cwe_matches), 1)


if __name__ == "__main__":
    unittest.main()