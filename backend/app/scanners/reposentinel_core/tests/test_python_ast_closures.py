
from app.scanners.reposentinel_core.analyzers.python_ast_analyzer import (
    PythonASTAnalyzer,
)


def analyze(source: str):
    analyzer = PythonASTAnalyzer()
    return analyzer.analyze(
        source_code=source,
        file_path="closure_test.py",
    )


def test_nested_function_detects_tainted_captured_variable():
    source = '''
def outer():
    user_id = input("Enter user ID")

    def inner():
        cursor.execute(
            f"SELECT * FROM users WHERE id = {user_id}"
        )

    inner()

outer()
'''
    findings = analyze(source)

    assert len(findings) == 1
    assert findings[0].cwe == "CWE-89"


def test_nested_function_does_not_flag_safe_captured_variable():
    source = '''
def outer():
    user_id = 100

    def inner():
        cursor.execute(
            f"SELECT * FROM users WHERE id = {user_id}"
        )

    inner()

outer()
'''
    findings = analyze(source)

    assert findings == []


def test_nested_function_is_not_analyzed_when_never_called():
    source = '''
def outer():
    user_id = input("Enter user ID")

    def inner():
        cursor.execute(
            f"SELECT * FROM users WHERE id = {user_id}"
        )

outer()
'''
    findings = analyze(source)

    assert findings == []


def test_local_variable_shadowing_does_not_inherit_outer_taint():
    source = '''
def outer():
    user_id = input("Enter user ID")

    def inner():
        user_id = 100

        cursor.execute(
            f"SELECT * FROM users WHERE id = {user_id}"
        )

    inner()

outer()
'''
    findings = analyze(source)

    assert findings == []


def test_deeply_nested_function_can_capture_outer_variable():
    source = '''
def outer():
    user_id = input("Enter user ID")

    def middle():
        def inner():
            cursor.execute(
                f"SELECT * FROM users WHERE id = {user_id}"
            )

        inner()

    middle()

outer()
'''
    findings = analyze(source)

    assert len(findings) == 1
    assert findings[0].cwe == "CWE-89"
