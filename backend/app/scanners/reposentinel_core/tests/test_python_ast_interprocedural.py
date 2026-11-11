
from app.scanners.reposentinel_core.analyzers.python_ast_analyzer import (
    PythonASTAnalyzer,
)


def analyze(source: str):
    analyzer = PythonASTAnalyzer()
    return analyzer.analyze(
        source_code=source,
        file_path="interprocedural_test.py",
    )


def test_taint_passes_through_one_function_wrapper():
    source = '''
def execute_query(query):
    cursor.execute(query)

def wrapper(query):
    execute_query(query)

user_input = input()
query = f"SELECT * FROM users WHERE id = {user_input}"
wrapper(query)
'''
    findings = analyze(source)

    assert len(findings) == 1
    assert findings[0].cwe == "CWE-89"


def test_taint_passes_through_multiple_function_wrappers():
    source = '''
def execute_query(query):
    cursor.execute(query)

def second_wrapper(query):
    execute_query(query)

def first_wrapper(query):
    second_wrapper(query)

user_input = input()
query = f"SELECT * FROM users WHERE id = {user_input}"
first_wrapper(query)
'''
    findings = analyze(source)

    assert len(findings) == 1
    assert findings[0].cwe == "CWE-89"


def test_forward_defined_function_call_is_analyzed():
    source = '''
def wrapper(query):
    execute_query(query)

def execute_query(query):
    cursor.execute(query)

user_input = input()
query = f"SELECT * FROM users WHERE id = {user_input}"
wrapper(query)
'''
    findings = analyze(source)

    assert len(findings) == 1
    assert findings[0].cwe == "CWE-89"


def test_taint_passes_through_nested_return_and_sink_chain():
    source = '''
def execute_query(query):
    cursor.execute(query)

def build_query(user_id):
    return f"SELECT * FROM users WHERE id = {user_id}"

def wrapper(user_id):
    query = build_query(user_id)
    execute_query(query)

wrapper(input())
'''
    findings = analyze(source)

    assert len(findings) == 1
    assert findings[0].cwe == "CWE-89"


def test_safe_argument_does_not_trigger_interprocedural_finding():
    source = '''
def execute_query(query):
    cursor.execute(query)

def wrapper(query):
    execute_query(query)

wrapper("SELECT * FROM users WHERE id = 10")
'''
    findings = analyze(source)

    assert findings == []


def test_unrelated_tainted_argument_does_not_trigger_finding():
    source = '''
def execute_query(query):
    cursor.execute(query)

def wrapper(query, label):
    execute_query(query)

wrapper(
    "SELECT * FROM users WHERE id = 10",
    input()
)
'''
    findings = analyze(source)

    assert findings == []
