
from app.scanners.reposentinel_core.analyzers.python_ast_analyzer import (
    PythonASTAnalyzer,
)


def analyze(source: str):
    analyzer = PythonASTAnalyzer()
    return analyzer.analyze(
        source_code=source,
        file_path="scope_resolution_test.py",
    )


def test_top_level_function_is_detected():
    source = '''
def execute_query(query):
    cursor.execute(query)

execute_query(input())
'''
    findings = analyze(source)

    assert len(findings) == 1
    assert findings[0].cwe == "CWE-89"


def test_nested_function_is_analyzed_when_called():
    source = '''
def outer():
    def inner(query):
        cursor.execute(query)

    inner(input())

outer()
'''
    findings = analyze(source)

    assert len(findings) == 1
    assert findings[0].cwe == "CWE-89"


def test_same_function_name_in_different_scopes_does_not_collide():
    source = '''
def outer():
    def process(data):
        cursor.execute(data)

    process(input())


def another():
    def process(data):
        print(data)

    process("safe")


outer()
another()
'''
    findings = analyze(source)

    assert len(findings) == 1
    assert findings[0].cwe == "CWE-89"


def test_unrelated_nested_function_does_not_create_finding():
    source = '''
def outer():
    def process(data):
        cursor.execute(data)

    process("SELECT * FROM users")
    
outer()
'''
    findings = analyze(source)

    assert findings == []


def test_same_name_top_level_functions_are_not_silently_merged():
    source = '''
def process(data):
    cursor.execute(data)


def wrapper(data):
    process(data)


def process(data):
    print(data)


wrapper(input())
'''
    findings = analyze(source)

    assert findings == []


def test_nested_function_is_not_attributed_to_outer_function():
    source = '''
def outer():
    def inner(data):
        cursor.execute(data)

    print("safe")

outer()
'''
    findings = analyze(source)

    assert findings == []
