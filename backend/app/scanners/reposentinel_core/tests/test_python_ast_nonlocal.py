
from app.scanners.reposentinel_core.analyzers.python_ast_analyzer import (
    PythonASTAnalyzer,
)


def analyze(source: str):
    analyzer = PythonASTAnalyzer()
    return analyzer.analyze(
        source_code=source,
        file_path="nonlocal_test.py",
    )


def test_nonlocal_tainted_assignment_reaches_sql_sink():
    source = '''
def outer():
    user_id = "safe"

    def update():
        nonlocal user_id
        user_id = input("Enter ID")

    def execute_query():
        cursor.execute(
            f"SELECT * FROM users WHERE id = {user_id}"
        )

    update()
    execute_query()

outer()
'''
    findings = analyze(source)

    assert len(findings) == 1
    assert findings[0].cwe == "CWE-89"


def test_nonlocal_safe_assignment_does_not_create_finding():
    source = '''
def outer():
    user_id = input("Enter ID")

    def update():
        nonlocal user_id
        user_id = "safe"

    def execute_query():
        cursor.execute(
            f"SELECT * FROM users WHERE id = {user_id}"
        )

    update()
    execute_query()

outer()
'''
    findings = analyze(source)

    assert findings == []


def test_nonlocal_assignment_without_call_does_not_create_finding():
    source = '''
def outer():
    user_id = "safe"

    def update():
        nonlocal user_id
        user_id = input("Enter ID")

    def execute_query():
        cursor.execute(
            f"SELECT * FROM users WHERE id = {user_id}"
        )

    execute_query()

outer()
'''
    findings = analyze(source)

    assert findings == []


def test_nonlocal_assignment_propagates_through_multiple_scopes():
    source = '''
def outer():
    user_id = "safe"

    def middle():
        def update():
            nonlocal user_id
            user_id = input("Enter ID")

        update()

    def execute_query():
        cursor.execute(
            f"SELECT * FROM users WHERE id = {user_id}"
        )

    middle()
    execute_query()

outer()
'''
    findings = analyze(source)

    assert len(findings) == 1
    assert findings[0].cwe == "CWE-89"


def test_nonlocal_assignment_does_not_change_unrelated_variable():
    source = '''
def outer():
    user_id = input("Enter ID")

    def another():
        user_id = "safe"
        cursor.execute(
            f"SELECT * FROM users WHERE id = {user_id}"
        )

    another()

outer()
'''
    findings = analyze(source)

    assert findings == []
