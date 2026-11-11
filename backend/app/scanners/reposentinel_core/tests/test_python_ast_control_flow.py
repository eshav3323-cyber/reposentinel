from app.scanners.reposentinel_core.analyzers.python_ast_analyzer import (
    PythonASTAnalyzer,
)


def scan(source_code: str):
    analyzer = PythonASTAnalyzer()
    return analyzer.analyze(
        source_code=source_code,
        file_path="control_flow_test.py",
    )


def test_detects_tainted_value_assigned_inside_if():
    source = """
user_id = "10"

if condition:
    user_id = input()

query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)
"""

    findings = scan(source)

    assert len(findings) == 1
    assert findings[0].cwe == "CWE-89"


def test_detects_tainted_value_from_one_if_else_branch():
    source = """
if condition:
    user_id = input()
else:
    user_id = "10"

query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)
"""

    findings = scan(source)

    assert len(findings) == 1


def test_detects_tainted_value_assigned_inside_for_loop():
    source = """
user_id = "10"

for item in items:
    user_id = input()

query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)
"""

    findings = scan(source)

    assert len(findings) == 1


def test_detects_tainted_value_assigned_inside_while_loop():
    source = """
user_id = "10"

while condition:
    user_id = input()

query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)
"""

    findings = scan(source)

    assert len(findings) == 1


def test_safe_reassignment_clears_previous_taint():
    source = """
user_id = input()
user_id = "10"

query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)
"""

    findings = scan(source)

    assert len(findings) == 0


def test_tainted_reassignment_updates_variable_state():
    source = """
user_id = "10"
user_id = input()

query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)
"""

    findings = scan(source)

    assert len(findings) == 1


def test_strip_does_not_automatically_remove_taint():
    source = """
user_id = input().strip()

query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)
"""

    findings = scan(source)

    assert len(findings) == 1


def test_unknown_sanitizer_function_does_not_automatically_remove_taint():
    source = """
user_id = sanitize(input())

query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)
"""

    findings = scan(source)

    assert len(findings) == 1


def test_parameterized_query_is_not_flagged():
    source = """
user_id = input()

cursor.execute(
    "SELECT * FROM users WHERE id = ?",
    (user_id,)
)
"""

    findings = scan(source)

    assert len(findings) == 0