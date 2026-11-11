
from app.scanners.reposentinel_core.analyzers.python_ast_analyzer import (
    PythonASTAnalyzer,
)


def analyze(source: str):
    analyzer = PythonASTAnalyzer()
    return analyzer.analyze(
        source_code=source,
        file_path="global_test.py",
    )


def test_global_tainted_assignment_reaches_sql_sink():
    source = '''
user_id = "safe"

def update():
    global user_id
    user_id = input("Enter ID")

def execute_query():
    cursor.execute(
        f"SELECT * FROM users WHERE id = {user_id}"
    )

update()
execute_query()
'''
    findings = analyze(source)

    assert len(findings) == 1
    assert findings[0].cwe == "CWE-89"


def test_global_safe_assignment_clears_previous_taint():
    source = '''
user_id = input("Enter ID")

def update():
    global user_id
    user_id = "safe"

def execute_query():
    cursor.execute(
        f"SELECT * FROM users WHERE id = {user_id}"
    )

update()
execute_query()
'''
    findings = analyze(source)

    assert findings == []


def test_global_assignment_without_function_call_does_not_create_finding():
    source = '''
user_id = "safe"

def update():
    global user_id
    user_id = input("Enter ID")

def execute_query():
    cursor.execute(
        f"SELECT * FROM users WHERE id = {user_id}"
    )

execute_query()
'''
    findings = analyze(source)

    assert findings == []


def test_global_assignment_propagates_through_nested_function_calls():
    source = '''
user_id = "safe"

def outer():
    def middle():
        def update():
            global user_id
            user_id = input("Enter ID")

        update()

    middle()

def execute_query():
    cursor.execute(
        f"SELECT * FROM users WHERE id = {user_id}"
    )

outer()
execute_query()
'''
    findings = analyze(source)

    assert len(findings) == 1
    assert findings[0].cwe == "CWE-89"


def test_local_variable_does_not_modify_global_variable():
    source = '''
user_id = "safe"

def another():
    user_id = input("Enter ID")

def execute_query():
    cursor.execute(
        f"SELECT * FROM users WHERE id = {user_id}"
    )

another()
execute_query()
'''
    findings = analyze(source)

    assert findings == []
