import ast
from dataclasses import dataclass, field
from typing import TypeAlias
from ..findings import SecurityFinding

VariableState: TypeAlias = tuple[bool, bool]
FunctionKey: TypeAlias = tuple[str, ...]

@dataclass(frozen=True)
class FunctionParameters:
    """Describes the different parameter categories supported by Python."""
    positional_only: tuple[str, ...] = ()
    positional_or_keyword: tuple[str, ...] = ()
    var_positional: str | None = None
    keyword_only: tuple[str, ...] = ()
    var_keyword: str | None = None

    @property
    def all_names(self) -> tuple[str, ...]:
        names = list(self.positional_only)
        names.extend(self.positional_or_keyword)
        if self.var_positional is not None:
            names.append(self.var_positional)
        names.extend(self.keyword_only)
        if self.var_keyword is not None:
            names.append(self.var_keyword)
        return tuple(names)

    @property
    def positional_names(self) -> tuple[str, ...]:
        return self.positional_only + self.positional_or_keyword

    @property
    def keyword_names(self) -> tuple[str, ...]:
        return self.positional_or_keyword + self.keyword_only

@dataclass
class FunctionSummary:
    params: list[str]
    parameter_model: FunctionParameters | None = None
    parameter_defaults: dict[int, ast.expr] = field(default_factory=dict)
    sink_params: set[str] = field(default_factory=set)
    sink_param_positions: set[int] = field(default_factory=set)
    return_param_positions: set[int] = field(default_factory=set)
    sink_line_numbers: set[int] = field(default_factory=set)
    returns_tainted: bool = False
    has_tainted_sink: bool = False
    closure_sink_variables: dict[str, set[int]] = field(default_factory=dict)
    nonlocal_writes: dict[str, VariableState] = field(default_factory=dict)
    nonlocal_write_param_positions: dict[str, set[int]] = field(default_factory=dict)
    global_writes: dict[str, VariableState] = field(default_factory=dict)
    global_write_param_positions: dict[str, set[int]] = field(default_factory=dict)
    global_sink_variables: dict[str, set[int]] = field(default_factory=dict)
    depth: int = 0

class PythonASTAnalyzer(ast.NodeVisitor):
    """
    Conservative Python AST and local data-flow analyzer.
    Tracks user input through assignments, branches, loops, match/case,
    context managers, exception handling, function arguments, return values,
    closures, nonlocal assignments and global assignments.
    The analyzer never executes inspected source code.
    """
    INPUT_CALLS = {"input"}
    INPUT_ACCESSORS = {
        "request.args.get",
        "request.form.get",
        "request.values.get",
        "request.json.get",
        "request.data.get",
        "request.query_params.get",
        "request.GET.get",
        "request.POST.get",
    }
    SQL_SINKS = {"execute", "executemany", "query", "raw"}

    def __init__(self):
        self.variable_state: dict[str, VariableState] = {}
        self.variable_param_sources: dict[str, set[int]] = {}
        self.function_summaries: dict[FunctionKey, FunctionSummary] = {}
        self.function_nodes: dict[FunctionKey, ast.AST] = {}
        self.function_node_keys: dict[int, FunctionKey] = {}
        self.function_stack: set[FunctionKey] = set()
        self.function_depth = 0
        self.max_function_depth = 8
        self._summary_mode = False
        self._active_scope_path: FunctionKey = ()
        self._active_local_names: set[str] = set()
        self._active_nonlocal_names: set[str] = set()
        self._active_global_names: set[str] = set()
        self._summary_nonlocal_writes: dict[str, VariableState] = {}
        self._summary_nonlocal_write_sources: dict[str, set[int]] = {}
        self._summary_global_writes: dict[str, VariableState] = {}
        self._summary_global_write_sources: dict[str, set[int]] = {}
        self.findings: list[SecurityFinding] = []
        self.file_path = ""

    #*&#x20;---------------------------------------------------------*

    #*&#x20;Main entry point*

    #*&#x20;---------------------------------------------------------*

    def analyze(self, source_code: str, file_path: str) -> list[SecurityFinding]:
        self.variable_state = {}
        self.variable_param_sources = {}
        self.function_summaries = {}
        self.function_nodes = {}
        self.function_node_keys = {}
        self.function_stack = set()
        self.function_depth = 0
        self._summary_mode = False
        self._active_scope_path = ()
        self._active_local_names = set()
        self._active_nonlocal_names = set()
        self._active_global_names = set()
        self._summary_nonlocal_writes = {}
        self._summary_nonlocal_write_sources = {}
        self._summary_global_writes = {}
        self._summary_global_write_sources = {}
        self.findings = []
        self.file_path = file_path
        try:
            syntax_tree = ast.parse(source_code)
        except (SyntaxError, ValueError, TypeError):
            return []
        self._build_function_registry(syntax_tree)
        self._build_function_summaries()
        self.visit(syntax_tree)
        return self.findings

    #*&#x20;---------------------------------------------------------*

    #*&#x20;Scope-aware function registry*

    #*&#x20;---------------------------------------------------------*

    def _build_function_registry(self, syntax_tree: ast.Module) -> None:
        self.function_nodes = {}
        self.function_node_keys = {}
        self._collect_scope_definitions(syntax_tree.body, ())

    def _collect_scope_definitions(
        self,
        statements: list[ast.stmt],
        scope_path: FunctionKey,
    ) -> None:
        direct_functions: dict[str, ast.AST] = {}
        direct_classes: dict[str, ast.ClassDef] = {}

        def scan_children(node: ast.AST) -> None:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    direct_functions[child.name] = child
                    continue
                if isinstance(child, ast.ClassDef):
                    direct_classes[child.name] = child
                    continue
                scan_children(child)
        for statement in statements:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                direct_functions[statement.name] = statement
            elif isinstance(statement, ast.ClassDef):
                direct_classes[statement.name] = statement
            else:
                scan_children(statement)
        for name, node in direct_functions.items():
            key = scope_path + (name,)
            self.function_nodes[key] = node
            self.function_node_keys[id(node)] = key
        for name, node in direct_functions.items():
            self._collect_scope_definitions(
                node.body,
                scope_path + (name,),
            )
        for name, class_node in direct_classes.items():
            self._collect_scope_definitions(
                class_node.body,
                scope_path + (name,),
            )

    def _resolve_function_key(
        self,
        call_name: str,
        scope_path: FunctionKey | None = None,
    ) -> FunctionKey | None:
        if not call_name or "." in call_name:
            return None
        current_scope = (
            self._active_scope_path if scope_path is None else scope_path
        )
        while True:
            candidate = current_scope + (call_name,)
            if candidate in self.function_nodes:
                return candidate
            if not current_scope:
                break
            current_scope = current_scope[:-1]
        return None

    def _resolve_function_summary(
        self,
        call_name: str,
        scope_path: FunctionKey | None = None,
    ) -> FunctionSummary | None:
        key = self._resolve_function_key(call_name, scope_path)
        if key is None:
            return None
        return self.function_summaries.get(key)

    #*&#x20;---------------------------------------------------------*

    #*&#x20;Function summary construction*

    #*&#x20;---------------------------------------------------------*

    def _build_function_summaries(self) -> None:
        self.function_summaries = {}
        for key, node in self.function_nodes.items():
            parameter_model = self._collect_function_parameters(node.args)
            self.function_summaries[key] = FunctionSummary(
                params=list(parameter_model.all_names),
                parameter_model=parameter_model,
            )
        if not self.function_nodes:
            return
        max_iterations = min(32, max(4, len(self.function_nodes) * 2 + 2))
        for _ in range(max_iterations):
            updated_summaries = {
                key: self._summarize_function(node, key)
                for key, node in self.function_nodes.items()
            }
            changed = any(
                key not in self.function_summaries
                or self._summary_signature(self.function_summaries[key])
                != self._summary_signature(updated)
                for key, updated in updated_summaries.items()
            )
            self.function_summaries.update(updated_summaries)
            if not changed:
                break

    @staticmethod
    def _summary_signature(summary: FunctionSummary) -> tuple:
        return (
            tuple(summary.params),
            frozenset(summary.sink_param_positions),
            frozenset(summary.return_param_positions),
            frozenset(summary.sink_line_numbers),
            frozenset(
                (name, frozenset(lines))
                for name, lines in summary.closure_sink_variables.items()
            ),
            frozenset(
                (
                    name,
                    state,
                    frozenset(
                        summary.nonlocal_write_param_positions.get(name, set())
                    ),
                )
                for name, state in summary.nonlocal_writes.items()
            ),
            frozenset(
                (
                    name,
                    state,
                    frozenset(
                        summary.global_write_param_positions.get(name, set())
                    ),
                )
                for name, state in summary.global_writes.items()
            ),
            frozenset(
                (name, frozenset(lines))
                for name, lines in summary.global_sink_variables.items()
            ),
            summary.returns_tainted,
            summary.has_tainted_sink,
        )

    #*&#x20;---------------------------------------------------------*

    #*&#x20;Scope handling*

    #*&#x20;---------------------------------------------------------*

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if not self._summary_mode:
            self._visit_function_scope(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        if not self._summary_mode:
            self._visit_function_scope(node)

    def _visit_function_scope(self, node) -> None:
        """Analyze a function body in an isolated local scope.
        Function summaries handle call-site-specific parameter propagation.
        This traversal separately detects sources and sinks that occur directly
        inside the function body, including async functions and context managers.
        """
        function_key = self.function_node_keys.get(id(node))
        if function_key is None:
            function_key = self._active_scope_path + (
                getattr(node, "name", ""),
            )
        if function_key in self.function_stack:
            return
        if self.function_depth >= self.max_function_depth:
            return
        parent_scope = self._active_scope_path
        # Decorators and defaults are evaluated in the defining scope.
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in node.args.defaults:
            self.visit(default)
        for default in node.args.kw_defaults:
            if default is not None:
                self.visit(default)
        outer_state = self.variable_state.copy()
        outer_param_sources = {
            name: sources.copy()
            for name, sources in self.variable_param_sources.items()
        }
        parameter_model = self._collect_function_parameters(node.args)
        local_names, _ = self._collect_scope_names(node)
        nonlocal_names = self._collect_nonlocal_names(node)
        global_names = self._collect_global_names(node)
        # Do not assume every function argument is tainted. The summary engine
        # applies actual argument taint at call sites; this pass tracks explicit
        # sources such as input() within the function itself.
        self.variable_state = {
            name: (False, False)
            for name in parameter_model.all_names
        }
        self.variable_param_sources = {
            name: set()
            for name in parameter_model.all_names
        }
        outer_local_names = self._active_local_names
        outer_nonlocal_names = self._active_nonlocal_names
        outer_global_names = self._active_global_names
        self.function_stack.add(function_key)
        self.function_depth += 1
        self._active_scope_path = function_key
        self._active_local_names = local_names
        self._active_nonlocal_names = nonlocal_names
        self._active_global_names = global_names
        try:
            for statement in node.body:
                self.visit(statement)
            self._sync_nonlocal_writes_from_state()
            self._sync_global_writes_from_state()
        finally:
            self._active_scope_path = parent_scope
            self._active_local_names = outer_local_names
            self._active_nonlocal_names = outer_nonlocal_names
            self._active_global_names = outer_global_names
            self.function_stack.discard(function_key)
            self.function_depth = max(0, self.function_depth - 1)
            self.variable_state = outer_state
            self.variable_param_sources = outer_param_sources

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        if self._summary_mode:
            return
        for decorator in node.decorator_list:
            self.visit(decorator)
        for base in node.bases:
            self.visit(base)
        outer_state = self.variable_state.copy()
        outer_sources = self.variable_param_sources.copy()
        outer_scope = self._active_scope_path
        self.variable_state = {}
        self.variable_param_sources = {}
        self._active_scope_path = outer_scope + (node.name,)
        try:
            for statement in node.body:
                self.visit(statement)
        finally:
            self._active_scope_path = outer_scope
            self.variable_state = outer_state
            self.variable_param_sources = outer_sources

    #*&#x20;---------------------------------------------------------*

    #*&#x20;Assignments and variable tracking*

    #*&#x20;---------------------------------------------------------*

    def visit_Assign(self, node: ast.Assign) -> None:
        value_state = self._get_expression_state(node.value)
        value_sources = self._expression_param_sources(node.value)
        self.visit(node.value)
        for target in node.targets:
            self._assign_target(target, value_state, value_sources)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.visit(node.annotation)
        if node.value is not None:
            value_state = self._get_expression_state(node.value)
            value_sources = self._expression_param_sources(node.value)
            self.visit(node.value)
            self._assign_target(node.target, value_state, value_sources)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        previous_state = self._get_expression_state(node.target)
        value_state = self._get_expression_state(node.value)
        value_sources = self._expression_param_sources(node.value)
        self.visit(node.value)
        combined_state = (
            previous_state[0] or value_state[0],
            previous_state[1]
            or value_state[1]
            or isinstance(node.op, (ast.Add, ast.Mod)),
        )
        target_sources: set[int] = set()
        if isinstance(node.target, ast.Name):
            target_sources = self.variable_param_sources.get(
                node.target.id, set()
            ).copy()
        target_sources.update(value_sources)
        self._assign_target(node.target, combined_state, target_sources)

    def _assign_target(
        self,
        target: ast.expr,
        state: VariableState,
        param_sources: set[int] | None = None,
    ) -> None:
        if isinstance(target, ast.Name):
            sources = set(param_sources or set())
            self.variable_state[target.id] = state
            self.variable_param_sources[target.id] = sources
            if self._summary_mode and target.id in self._active_nonlocal_names:
                self._summary_nonlocal_writes[target.id] = state
                self._summary_nonlocal_write_sources[target.id] = sources.copy()
            if self._summary_mode and target.id in self._active_global_names:
                self._summary_global_writes[target.id] = state
                self._summary_global_write_sources[target.id] = sources.copy()
        elif isinstance(target, ast.Starred):
            self._assign_target(target.value, state, param_sources)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._assign_target(element, state, param_sources)

    #*&#x20;---------------------------------------------------------*

    #*&#x20;Nonlocal and global write propagation*

    #*&#x20;---------------------------------------------------------*

    def _apply_callee_nonlocal_writes(
        self,
        call_node: ast.Call,
        summary: FunctionSummary,
    ) -> None:
        for name, written_state in summary.nonlocal_writes.items():
            source_positions = summary.nonlocal_write_param_positions.get(
                name, set()
            )
            actual_state = written_state
            actual_sources: set[int] = set()
            if source_positions:
                actual_state = (False, False)
                for formal_index, argument in self._call_argument_map(
                    call_node, summary
                ):
                    if formal_index not in source_positions:
                        continue
                    argument_state = self._get_expression_state(argument)
                    actual_state = (
                        actual_state[0] or argument_state[0],
                        actual_state[1] or argument_state[1],
                    )
                    actual_sources.update(
                        self._expression_param_sources(argument)
                    )
            self.variable_state[name] = actual_state
            self.variable_param_sources[name] = actual_sources.copy()
            if self._summary_mode and name not in self._active_local_names:
                self._summary_nonlocal_writes[name] = actual_state
                self._summary_nonlocal_write_sources[name] = actual_sources.copy()

    def _apply_callee_global_writes(
        self,
        call_node: ast.Call,
        summary: FunctionSummary,
    ) -> None:
        for name, written_state in summary.global_writes.items():
            source_positions = summary.global_write_param_positions.get(
                name, set()
            )
            actual_state = written_state
            actual_sources: set[int] = set()
            if source_positions:
                actual_state = (False, False)
                for formal_index, argument in self._call_argument_map(
                    call_node, summary
                ):
                    if formal_index not in source_positions:
                        continue
                    argument_state = self._get_expression_state(argument)
                    actual_state = (
                        actual_state[0] or argument_state[0],
                        actual_state[1] or argument_state[1],
                    )
                    actual_sources.update(
                        self._expression_param_sources(argument)
                    )
            self.variable_state[name] = actual_state
            self.variable_param_sources[name] = actual_sources.copy()
            if self._summary_mode:
                self._summary_global_writes[name] = actual_state
                self._summary_global_write_sources[name] = actual_sources.copy()

    def _sync_nonlocal_writes_from_state(self) -> None:
        for name in self._active_nonlocal_names:
            if name in self.variable_state:
                self._summary_nonlocal_writes[name] = self.variable_state[name]
                self._summary_nonlocal_write_sources[name] = (
                    self.variable_param_sources.get(name, set()).copy()
                )

    def _sync_global_writes_from_state(self) -> None:
        for name in self._active_global_names:
            if name in self.variable_state:
                self._summary_global_writes[name] = self.variable_state[name]
                self._summary_global_write_sources[name] = (
                    self.variable_param_sources.get(name, set()).copy()
                )

    #*&#x20;---------------------------------------------------------*

    #*&#x20;Conditional branches*

    #*&#x20;---------------------------------------------------------*

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        initial_state = self.variable_state.copy()
        initial_sources = self.variable_param_sources.copy()
        self.variable_state = initial_state.copy()
        self.variable_param_sources = initial_sources.copy()
        for statement in node.body:
            self.visit(statement)
        true_state = self.variable_state.copy()
        true_sources = self.variable_param_sources.copy()
        self.variable_state = initial_state.copy()
        self.variable_param_sources = initial_sources.copy()
        for statement in node.orelse:
            self.visit(statement)
        false_state = self.variable_state.copy()
        false_sources = self.variable_param_sources.copy()
        if not node.orelse:
            false_state = initial_state
            false_sources = initial_sources.copy()
        self.variable_state = self._merge_states(true_state, false_state)
        self.variable_param_sources = self._merge_param_sources(
            true_sources, false_sources
        )
        self._sync_nonlocal_writes_from_state()
        self._sync_global_writes_from_state()

    #*&#x20;---------------------------------------------------------*

    #*&#x20;Match/case control-flow analysis*

    #*&#x20;---------------------------------------------------------*

    def visit_Match(self, node: ast.Match) -> None:
        subject_state = self._get_expression_state(node.subject)
        subject_sources = self._expression_param_sources(node.subject)
        self.visit(node.subject)
        initial_state = self.variable_state.copy()
        initial_sources = {
            name: sources.copy()
            for name, sources in self.variable_param_sources.items()
        }
        branch_states: list[dict[str, VariableState]] = []
        branch_sources: list[dict[str, set[int]]] = []
        has_unconditional_irrefutable_case = False
        for case in node.cases:
            self.variable_state = initial_state.copy()
            self.variable_param_sources = {
                name: sources.copy()
                for name, sources in initial_sources.items()
            }
            self.visit(case.pattern)
            captured_names = self._collect_match_capture_names(case.pattern)
            for name in captured_names:
                self.variable_state[name] = subject_state
                self.variable_param_sources[name] = subject_sources.copy()
            if case.guard is not None:
                self.visit(case.guard)
            for statement in case.body:
                self.visit(statement)
            branch_states.append(self.variable_state.copy())
            branch_sources.append({
                name: sources.copy()
                for name, sources in self.variable_param_sources.items()
            })
            if (
                case.guard is None
                and self._is_irrefutable_match_pattern(case.pattern)
            ):
                has_unconditional_irrefutable_case = True
        if not has_unconditional_irrefutable_case:
            branch_states.append(initial_state)
            branch_sources.append(initial_sources)
        if branch_states:
            self.variable_state = self._merge_states(*branch_states)
            self.variable_param_sources = self._merge_param_sources(
                *branch_sources
            )
        else:
            self.variable_state = initial_state
            self.variable_param_sources = initial_sources
        self._sync_nonlocal_writes_from_state()
        self._sync_global_writes_from_state()

    @staticmethod
    def _collect_match_capture_names(pattern: ast.pattern) -> set[str]:
        captured_names: set[str] = set()

        def collect(current: ast.pattern) -> None:
            if isinstance(current, ast.MatchAs):
                if current.name is not None:
                    captured_names.add(current.name)
                if current.pattern is not None:
                    collect(current.pattern)
            elif isinstance(current, ast.MatchStar):
                if current.name is not None:
                    captured_names.add(current.name)
            elif isinstance(current, ast.MatchSequence):
                for child in current.patterns:
                    collect(child)
            elif isinstance(current, ast.MatchMapping):
                for child in current.patterns:
                    collect(child)
                if current.rest is not None:
                    captured_names.add(current.rest)
            elif isinstance(current, ast.MatchClass):
                for child in current.patterns:
                    collect(child)
                for child in current.kwd_patterns:
                    collect(child)
            elif isinstance(current, ast.MatchOr):
                for child in current.patterns:
                    collect(child)
        collect(pattern)
        return captured_names

    @staticmethod
    def _is_irrefutable_match_pattern(pattern: ast.pattern) -> bool:
        if isinstance(pattern, ast.MatchAs):
            return (
                pattern.pattern is None
                or PythonASTAnalyzer._is_irrefutable_match_pattern(
                    pattern.pattern
                )
            )
        if isinstance(pattern, ast.MatchOr):
            return any(
                PythonASTAnalyzer._is_irrefutable_match_pattern(child)
                for child in pattern.patterns
            )
        return False

    #*&#x20;---------------------------------------------------------*

    #*&#x20;Exception control-flow analysis*

    #*&#x20;---------------------------------------------------------*

    def visit_Try(self, node: ast.Try) -> None:
        initial_state = self.variable_state.copy()
        initial_sources = self.variable_param_sources.copy()
        self.variable_state = initial_state.copy()
        self.variable_param_sources = initial_sources.copy()
        for statement in node.body:
            self.visit(statement)
        successful_state = self.variable_state.copy()
        successful_sources = self.variable_param_sources.copy()
        for statement in node.orelse:
            self.visit(statement)
        successful_state = self.variable_state.copy()
        successful_sources = self.variable_param_sources.copy()
        handler_states: list[dict[str, VariableState]] = []
        handler_sources: list[dict[str, set[int]]] = []
        for handler in node.handlers:
            self.variable_state = self._merge_states(
                initial_state,
                self._state_after_try_body(
                    node, initial_state, initial_sources
                ),
            )
            self.variable_param_sources = self._merge_param_sources(
                initial_sources,
                self._sources_after_try_body(
                    node, initial_state, initial_sources
                ),
            )
            if handler.type is not None:
                self.visit(handler.type)
            if handler.name:
                self.variable_state[handler.name] = (False, False)
                self.variable_param_sources[handler.name] = set()
            for statement in handler.body:
                self.visit(statement)
            if handler.name:
                self.variable_state.pop(handler.name, None)
                self.variable_param_sources.pop(handler.name, None)
            handler_states.append(self.variable_state.copy())
            handler_sources.append(self.variable_param_sources.copy())
        possible_states = [successful_state] + handler_states
        possible_sources = [successful_sources] + handler_sources
        self.variable_state = self._merge_states(*possible_states)
        self.variable_param_sources = self._merge_param_sources(
            *possible_sources
        )
        for statement in node.finalbody:
            self.visit(statement)
        self._sync_nonlocal_writes_from_state()
        self._sync_global_writes_from_state()

    def _state_after_try_body(
        self,
        node: ast.Try,
        initial_state: dict[str, VariableState],
        initial_sources: dict[str, set[int]],
    ) -> dict[str, VariableState]:
        saved_state = self.variable_state
        saved_sources = self.variable_param_sources
        saved_summary_mode = self._summary_mode
        try:
            self.variable_state = initial_state.copy()
            self.variable_param_sources = initial_sources.copy()
            for statement in node.body:
                self.visit(statement)
            return self.variable_state.copy()
        finally:
            self.variable_state = saved_state
            self.variable_param_sources = saved_sources
            self._summary_mode = saved_summary_mode

    def _sources_after_try_body(
        self,
        node: ast.Try,
        initial_state: dict[str, VariableState],
        initial_sources: dict[str, set[int]],
    ) -> dict[str, set[int]]:
        saved_state = self.variable_state
        saved_sources = self.variable_param_sources
        saved_summary_mode = self._summary_mode
        try:
            self.variable_state = initial_state.copy()
            self.variable_param_sources = initial_sources.copy()
            for statement in node.body:
                self.visit(statement)
            return self.variable_param_sources.copy()
        finally:
            self.variable_state = saved_state
            self.variable_param_sources = saved_sources
            self._summary_mode = saved_summary_mode

    def visit_TryStar(self, node: ast.TryStar) -> None:
        self.visit_Try(node)

    #*&#x20;---------------------------------------------------------*

    #*&#x20;Loops*

    #*&#x20;---------------------------------------------------------*

    def visit_For(self, node: ast.For) -> None:
        iterable_state = self._get_expression_state(node.iter)
        iterable_sources = self._expression_param_sources(node.iter)
        self.visit(node.iter)
        initial_state = self.variable_state.copy()
        initial_sources = self.variable_param_sources.copy()
        self.variable_state = initial_state.copy()
        self.variable_param_sources = initial_sources.copy()
        self._assign_target(node.target, iterable_state, iterable_sources)
        for statement in node.body:
            self.visit(statement)
        for statement in node.orelse:
            self.visit(statement)
        loop_state = self.variable_state.copy()
        loop_sources = self.variable_param_sources.copy()
        self.variable_state = self._merge_states(initial_state, loop_state)
        self.variable_param_sources = self._merge_param_sources(
            initial_sources, loop_sources
        )
        self._sync_nonlocal_writes_from_state()
        self._sync_global_writes_from_state()

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.visit_For(node)

    def visit_While(self, node: ast.While) -> None:
        self.visit(node.test)
        initial_state = self.variable_state.copy()
        initial_sources = self.variable_param_sources.copy()
        self.variable_state = initial_state.copy()
        self.variable_param_sources = initial_sources.copy()
        for statement in node.body:
            self.visit(statement)
        for statement in node.orelse:
            self.visit(statement)
        loop_state = self.variable_state.copy()
        loop_sources = self.variable_param_sources.copy()
        self.variable_state = self._merge_states(initial_state, loop_state)
        self.variable_param_sources = self._merge_param_sources(
            initial_sources, loop_sources
        )
        self._sync_nonlocal_writes_from_state()
        self._sync_global_writes_from_state()

    #*&#x20;---------------------------------------------------------*

    #*&#x20;Context manager analysis*

    #*&#x20;---------------------------------------------------------*

    def visit_With(self, node: ast.With) -> None:
        """
        Analyze a synchronous with statement.
        Each context expression is evaluated in order. Its abstract
        taint state is assigned to the corresponding optional_vars
        target, if one exists.
        Python variables assigned by `as` remain available after the
        with block, so the resulting state is preserved afterward.
        """
        for item in node.items:
            context_state = self._get_expression_state(item.context_expr)
            context_sources = self._expression_param_sources(
                item.context_expr
            )
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self._assign_target(
                    item.optional_vars,
                    context_state,
                    context_sources,
                )
        for statement in node.body:
            self.visit(statement)
        self._sync_nonlocal_writes_from_state()
        self._sync_global_writes_from_state()

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        """
        Analyze an asynchronous with statement using the same
        conservative taint propagation as a synchronous with statement.
        """
        for item in node.items:
            context_state = self._get_expression_state(item.context_expr)
            context_sources = self._expression_param_sources(
                item.context_expr
            )
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self._assign_target(
                    item.optional_vars,
                    context_state,
                    context_sources,
                )
        for statement in node.body:
            self.visit(statement)
        self._sync_nonlocal_writes_from_state()
        self._sync_global_writes_from_state()

    #*&#x20;---------------------------------------------------------*

    #*&#x20;SQL sink detection and function calls*

    #*&#x20;---------------------------------------------------------*

    def _visit_comprehension_generators(
        self,
        generators: list[ast.comprehension],
    ) -> None:
        """Visit comprehension clauses with isolated target-variable state.
        The first iterable is evaluated in the enclosing scope. Each target is
        then assigned the abstract state of its iterable before filters and
        later generators are analyzed. The caller restores the outer scope.
        """
        for generator in generators:
            iterable_state = self._get_expression_state(generator.iter)
            iterable_sources = self._expression_param_sources(generator.iter)
            self.visit(generator.iter)
            self._assign_target(
                generator.target,
                iterable_state,
                iterable_sources,
            )
            for condition in generator.ifs:
                self.visit(condition)

    @staticmethod
    def _collect_named_expression_targets(node: ast.AST) -> set[str]:
        """Collect walrus targets belonging to the containing scope.
        Nested comprehensions are deliberately traversed because assignment
        expressions in them bind to the containing scope of the outermost
        comprehension. Nested functions, classes, and lambdas are separate
        scopes and are therefore not traversed.
        """
        targets: set[str] = set()

        class NamedExpressionTargetVisitor(ast.NodeVisitor):

            def visit_NamedExpr(self, child: ast.NamedExpr) -> None:
                if isinstance(child.target, ast.Name):
                    targets.add(child.target.id)
                self.visit(child.value)

            def visit_FunctionDef(self, child: ast.FunctionDef) -> None:
                return

            def visit_AsyncFunctionDef(self, child: ast.AsyncFunctionDef) -> None:
                return

            def visit_ClassDef(self, child: ast.ClassDef) -> None:
                return

            def visit_Lambda(self, child: ast.Lambda) -> None:
                return
        NamedExpressionTargetVisitor().visit(node)
        return targets

    def _visit_comprehension(self, node: ast.AST) -> None:
        """Analyze comprehensions while preserving PEP 572 outer bindings.
        Iteration variables are local to the comprehension. Assignment
        expression targets, however, bind in the containing scope (and nested
        comprehension walrus targets bind to that same scope). Preserve only
        those target states when restoring the surrounding environment.
        """
        outer_state = self.variable_state.copy()
        outer_sources = {
            name: sources.copy()
            for name, sources in self.variable_param_sources.items()
        }
        named_expression_targets = self._collect_named_expression_targets(node)
        named_expression_states: dict[str, VariableState] = {}
        named_expression_sources: dict[str, set[int]] = {}
        try:
            self._visit_comprehension_generators(node.generators)
            if isinstance(node, ast.DictComp):
                self.visit(node.key)
                self.visit(node.value)
            else:
                self.visit(node.elt)
            for name in named_expression_targets:
                if name in self.variable_state:
                    named_expression_states[name] = self.variable_state[name]
                    named_expression_sources[name] = (
                        self.variable_param_sources.get(name, set()).copy()
                    )
        finally:
            # Restore ordinary names so comprehension iteration targets do
            # not leak, then reapply names explicitly assigned with :=.
            self.variable_state = outer_state
            self.variable_param_sources = outer_sources
            for name, state in named_expression_states.items():
                self.variable_state[name] = state
                self.variable_param_sources[name] = (
                    named_expression_sources.get(name, set()).copy()
                )

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        """Track assignment expressions using ordinary assignment semantics."""
        value_state = self._get_expression_state(node.value)
        value_sources = self._expression_param_sources(node.value)
        self.visit(node.value)
        self._assign_target(node.target, value_state, value_sources)

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._visit_comprehension(node)

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._visit_comprehension(node)

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._visit_comprehension(node)

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._visit_comprehension(node)

    def visit_Call(self, node: ast.Call) -> None:
        call_name = self._get_name(node.func)
        method_name = call_name.rsplit(".", 1)[-1]
        if self._summary_mode:
            summary = self._resolve_function_summary(call_name)
            if summary is not None:
                self._apply_callee_nonlocal_writes(node, summary)
                self._apply_callee_global_writes(node, summary)
            self.generic_visit(node)
            return
        summary = self._resolve_function_summary(call_name)
        if summary is not None:
            if summary.has_tainted_sink:
                if summary.sink_line_numbers:
                    for line_number in summary.sink_line_numbers:
                        self._add_sql_finding(line_number)
                else:
                    self._add_sql_finding(node.lineno)
            if self._call_influences_sink(node, summary):
                self._add_sql_finding(node.lineno)
            for captured_name, captured_lines in (
                summary.closure_sink_variables.items()
            ):
                captured_state = self.variable_state.get(
                    captured_name, (False, False)
                )
                if captured_state[0] and captured_state[1]:
                    for line_number in captured_lines:
                        self._add_sql_finding(line_number)
            for global_name, global_lines in (
                summary.global_sink_variables.items()
            ):
                global_state = self.variable_state.get(
                    global_name, (False, False)
                )
                if global_state[0] and global_state[1]:
                    for line_number in global_lines:
                        self._add_sql_finding(line_number)
            self._apply_callee_nonlocal_writes(node, summary)
            self._apply_callee_global_writes(node, summary)
        if method_name in self.SQL_SINKS and node.args:
            argument_state = self._get_expression_state(node.args[0])
            if argument_state[0] and argument_state[1]:
                self._add_sql_finding(node.lineno)
        self.generic_visit(node)

    #*&#x20;---------------------------------------------------------*

    #*&#x20;Expression analysis*

    #*&#x20;---------------------------------------------------------*

    def _get_expression_state(self, expression: ast.AST) -> VariableState:
        is_tainted = False
        is_dynamic = False
        pending_nodes = [expression]
        while pending_nodes:
            node = pending_nodes.pop()
            # ``not`` always produces a Boolean value. Its operand's string
            # taint must not flow into the result, although other operands
            # elsewhere in a larger Boolean expression may still be tainted.
            if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
                continue
            pending_nodes.extend(ast.iter_child_nodes(node))
            if isinstance(node, ast.Name):
                state = self.variable_state.get(node.id, (False, False))
                is_tainted = is_tainted or state[0]
                is_dynamic = is_dynamic or state[1]
            elif isinstance(node, ast.Call):
                call_name = self._get_name(node.func)
                if (
                    call_name in self.INPUT_CALLS
                    or call_name in self.INPUT_ACCESSORS
                ):
                    is_tainted = True
                    is_dynamic = True
                else:
                    summary = self._resolve_function_summary(call_name)
                    if summary is not None:
                        if (
                            summary.returns_tainted
                            and not summary.return_param_positions
                        ):
                            is_tainted = True
                            is_dynamic = True
                        elif self._call_influences_return(node, summary):
                            is_tainted = True
                            is_dynamic = True
            elif isinstance(node, ast.JoinedStr):
                is_dynamic = True
            elif isinstance(node, ast.BinOp):
                if isinstance(node.op, (ast.Add, ast.Mod)):
                    is_dynamic = True
            elif isinstance(node, ast.FormattedValue):
                is_dynamic = True
        return is_tainted, is_dynamic

    def _merge_states(
        self,
        *states: dict[str, VariableState],
    ) -> dict[str, VariableState]:
        all_names: set[str] = set()
        for state in states:
            all_names.update(state)
        merged: dict[str, VariableState] = {}
        for name in all_names:
            values = [state.get(name, (False, False)) for state in states]
            merged[name] = (
                any(value[0] for value in values),
                any(value[1] for value in values),
            )
        return merged

    def _merge_param_sources(
        self,
        *states: dict[str, set[int]],
    ) -> dict[str, set[int]]:
        all_names: set[str] = set()
        for state in states:
            all_names.update(state)
        merged: dict[str, set[int]] = {}
        for name in all_names:
            merged[name] = set()
            for state in states:
                merged[name].update(state.get(name, set()))
        return merged

    #*&#x20;---------------------------------------------------------*

    #*&#x20;Function parameter model*

    #*&#x20;---------------------------------------------------------*

    @staticmethod
    def _collect_function_parameters(
        arguments: ast.arguments,
    ) -> FunctionParameters:
        return FunctionParameters(
            positional_only=tuple(arg.arg for arg in arguments.posonlyargs),
            positional_or_keyword=tuple(arg.arg for arg in arguments.args),
            var_positional=(
                arguments.vararg.arg if arguments.vararg is not None else None
            ),
            keyword_only=tuple(arg.arg for arg in arguments.kwonlyargs),
            var_keyword=(
                arguments.kwarg.arg if arguments.kwarg is not None else None
            ),
        )

    #*&#x20;---------------------------------------------------------*

    #*&#x20;Closure and free-variable analysis*

    #*&#x20;---------------------------------------------------------*

    def _collect_scope_names(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> tuple[set[str], set[str]]:

        class ScopeNameVisitor(ast.NodeVisitor):

            def __init__(self):
                self.local_names: set[str] = set()
                self.loaded_names: set[str] = set()
                self.global_names: set[str] = set()
                self.nonlocal_names: set[str] = set()

            def visit_Name(self, child: ast.Name):
                if isinstance(child.ctx, (ast.Store, ast.Del)):
                    self.local_names.add(child.id)
                elif isinstance(child.ctx, ast.Load):
                    self.loaded_names.add(child.id)

            def visit_Global(self, child: ast.Global):
                self.global_names.update(child.names)

            def visit_Nonlocal(self, child: ast.Nonlocal):
                self.nonlocal_names.update(child.names)

            def visit_FunctionDef(self, child: ast.FunctionDef):
                self.local_names.add(child.name)
                for decorator in child.decorator_list:
                    self.visit(decorator)
                for default in child.args.defaults:
                    self.visit(default)
                for default in child.args.kw_defaults:
                    if default is not None:
                        self.visit(default)

            def visit_AsyncFunctionDef(self, child: ast.AsyncFunctionDef):
                self.visit_FunctionDef(child)

            def visit_ClassDef(self, child: ast.ClassDef):
                self.local_names.add(child.name)
                for decorator in child.decorator_list:
                    self.visit(decorator)
                for base in child.bases:
                    self.visit(base)

            def visit_Lambda(self, child: ast.Lambda):
                return

            def visit_Import(self, child: ast.Import):
                for alias in child.names:
                    self.local_names.add(
                        alias.asname or alias.name.split(".")[0]
                    )

            def visit_ImportFrom(self, child: ast.ImportFrom):
                for alias in child.names:
                    if alias.name != "*":
                        self.local_names.add(alias.asname or alias.name)

            def visit_ExceptHandler(self, child: ast.ExceptHandler):
                if child.name:
                    self.local_names.add(child.name)
                if child.type:
                    self.visit(child.type)
                for statement in child.body:
                    self.visit(statement)
        visitor = ScopeNameVisitor()
        parameters = self._collect_function_parameters(node.args)
        visitor.local_names.update(parameters.all_names)
        for statement in node.body:
            visitor.visit(statement)
        local_names = (
            visitor.local_names
            - visitor.global_names
            - visitor.nonlocal_names
        )
        free_names = (
            visitor.loaded_names
            - local_names
            - visitor.global_names
        )
        free_names.update(visitor.nonlocal_names)
        return local_names, free_names

    def _collect_nonlocal_names(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> set[str]:
        names: set[str] = set()
        for child in self._iter_function_scope_nodes(node):
            if isinstance(child, ast.Nonlocal):
                names.update(child.names)
        return names

    def _collect_global_names(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> set[str]:
        names: set[str] = set()
        for child in self._iter_function_scope_nodes(node):
            if isinstance(child, ast.Global):
                names.update(child.names)
        return names

    @staticmethod
    def _expression_name_references(expression: ast.AST) -> set[str]:
        return {
            child.id
            for child in ast.walk(expression)
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load)
        }

    #*&#x20;---------------------------------------------------------*

    #*&#x20;Function summary*

    #*&#x20;---------------------------------------------------------*

    def _summarize_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        function_key: FunctionKey,
    ) -> FunctionSummary:
        parameter_model = self._collect_function_parameters(node.args)
        params = list(parameter_model.all_names)
        local_names, free_names = self._collect_scope_names(node)
        nonlocal_names = self._collect_nonlocal_names(node)
        global_names = self._collect_global_names(node)
        positional_names = parameter_model.positional_names
        positional_defaults = node.args.defaults
        parameter_defaults: dict[int, ast.expr] = {}
        if positional_defaults:
            first_default_index = len(positional_names) - len(positional_defaults)
            for offset, default in enumerate(positional_defaults):
                parameter_defaults[first_default_index + offset] = default
        for offset, default in enumerate(node.args.kw_defaults):
            if default is not None:
                name = parameter_model.keyword_only[offset]
                parameter_defaults[params.index(name)] = default
        outer_state = self.variable_state.copy()
        outer_sources = self.variable_param_sources.copy()
        outer_summary_mode = self._summary_mode
        outer_scope = self._active_scope_path
        outer_local_names = self._active_local_names
        outer_nonlocal_names = self._active_nonlocal_names
        outer_global_names = self._active_global_names
        outer_writes = self._summary_nonlocal_writes
        outer_write_sources = self._summary_nonlocal_write_sources
        outer_global_writes = self._summary_global_writes
        outer_global_write_sources = self._summary_global_write_sources
        self.variable_state = {name: (True, True) for name in params}
        self.variable_param_sources = {
            name: {index} for index, name in enumerate(params)
        }
        self._summary_mode = True
        self._active_scope_path = function_key
        self._active_local_names = local_names
        self._active_nonlocal_names = nonlocal_names
        self._active_global_names = global_names
        self._summary_nonlocal_writes = {}
        self._summary_nonlocal_write_sources = {}
        self._summary_global_writes = {}
        self._summary_global_write_sources = {}
        try:
            for statement in node.body:
                self.visit(statement)
            sink_param_positions: set[int] = set()
            return_param_positions: set[int] = set()
            sink_line_numbers: set[int] = set()
            returns_tainted = False
            has_tainted_sink = False
            closure_sink_variables: dict[str, set[int]] = {}
            global_sink_variables: dict[str, set[int]] = {}
            for child in self._iter_function_scope_nodes(node):
                if isinstance(child, ast.Call):
                    call_name = self._get_name(child.func)
                    method_name = call_name.rsplit(".", 1)[-1]
                    if method_name in self.SQL_SINKS and child.args:
                        expression = child.args[0]
                        expression_state = self._get_expression_state(expression)
                        positions = self._expression_param_positions(expression)
                        referenced_names = self._expression_name_references(
                            expression
                        )
                        captured_names = referenced_names & free_names
                        referenced_globals = referenced_names & global_names
                        if expression_state[0] or positions:
                            sink_param_positions.update(positions)
                            sink_line_numbers.add(child.lineno)
                            if (
                                not positions
                                and not captured_names
                                and not referenced_globals
                            ):
                                has_tainted_sink = True
                        for name in captured_names:
                            closure_sink_variables.setdefault(name, set()).add(
                                child.lineno
                            )
                        for name in referenced_globals:
                            global_sink_variables.setdefault(name, set()).add(
                                child.lineno
                            )
                    callee_summary = self._resolve_function_summary(
                        call_name, function_key
                    )
                    if callee_summary is not None:
                        if callee_summary.has_tainted_sink:
                            has_tainted_sink = True
                            sink_line_numbers.update(
                                callee_summary.sink_line_numbers
                            )
                        for captured_name, captured_lines in (
                            callee_summary.closure_sink_variables.items()
                        ):
                            if captured_name in local_names:
                                captured_state = self.variable_state.get(
                                    captured_name, (False, False)
                                )
                                if captured_state[0] and captured_state[1]:
                                    captured_sources = (
                                        self.variable_param_sources.get(
                                            captured_name, set()
                                        )
                                    )
                                    sink_param_positions.update(captured_sources)
                                    sink_line_numbers.update(captured_lines)
                                    if not captured_sources:
                                        has_tainted_sink = True
                            else:
                                closure_sink_variables.setdefault(
                                    captured_name, set()
                                ).update(captured_lines)
                        for global_name, global_lines in (
                            callee_summary.global_sink_variables.items()
                        ):
                            global_sink_variables.setdefault(
                                global_name, set()
                            ).update(global_lines)
                        for formal_index, argument in self._call_argument_map(
                            child, callee_summary
                        ):
                            if (
                                formal_index
                                in callee_summary.sink_param_positions
                                and self._expression_is_tainted(argument)
                            ):
                                positions = self._expression_param_positions(
                                    argument
                                )
                                sink_param_positions.update(positions)
                                sink_line_numbers.add(child.lineno)
                                if not positions:
                                    has_tainted_sink = True
                elif isinstance(child, ast.Return) and child.value is not None:
                    return_state = self._get_expression_state(child.value)
                    positions = self._expression_param_positions(child.value)
                    if return_state[0] and return_state[1]:
                        returns_tainted = True
                    if positions:
                        return_param_positions.update(positions)
                        returns_tainted = True
            sink_params = {
                params[index]
                for index in sink_param_positions
                if 0 <= index < len(params)
            }
            return FunctionSummary(
                params=params,
                parameter_model=parameter_model,
                parameter_defaults=parameter_defaults,
                sink_params=sink_params,
                sink_param_positions=sink_param_positions,
                return_param_positions=return_param_positions,
                sink_line_numbers=sink_line_numbers,
                returns_tainted=returns_tainted,
                has_tainted_sink=has_tainted_sink,
                closure_sink_variables=closure_sink_variables,
                nonlocal_writes=self._summary_nonlocal_writes.copy(),
                nonlocal_write_param_positions={
                    name: positions.copy()
                    for name, positions
                    in self._summary_nonlocal_write_sources.items()
                },
                global_writes=self._summary_global_writes.copy(),
                global_write_param_positions={
                    name: positions.copy()
                    for name, positions
                    in self._summary_global_write_sources.items()
                },
                global_sink_variables=global_sink_variables,
                depth=self.function_depth,
            )
        finally:
            self._summary_mode = outer_summary_mode
            self._active_scope_path = outer_scope
            self.variable_state = outer_state
            self.variable_param_sources = outer_sources
            self._active_local_names = outer_local_names
            self._active_nonlocal_names = outer_nonlocal_names
            self._active_global_names = outer_global_names
            self._summary_nonlocal_writes = outer_writes
            self._summary_nonlocal_write_sources = outer_write_sources
            self._summary_global_writes = outer_global_writes
            self._summary_global_write_sources = outer_global_write_sources

    @staticmethod
    def _iter_function_scope_nodes(node):
        """Yield this function's nodes without entering nested scopes."""
        stack = list(reversed(node.body))
        while stack:
            current = stack.pop()
            yield current
            if isinstance(
                current,
                (
                    ast.FunctionDef,
                    ast.AsyncFunctionDef,
                    ast.ClassDef,
                    ast.Lambda,
                ),
            ):
                continue
            children = list(ast.iter_child_nodes(current))
            stack.extend(reversed(children))

    #*&#x20;---------------------------------------------------------*

    #*&#x20;Function call argument mapping*

    #*&#x20;---------------------------------------------------------*

    def _call_influences_sink(
        self,
        node: ast.Call,
        summary: FunctionSummary,
    ) -> bool:
        for formal_index, argument in self._call_argument_map(node, summary):
            if (
                formal_index in summary.sink_param_positions
                and self._expression_is_tainted(argument)
            ):
                return True
        return False

    def _call_influences_return(
        self,
        node: ast.Call,
        summary: FunctionSummary,
    ) -> bool:
        for formal_index, argument in self._call_argument_map(node, summary):
            if (
                formal_index in summary.return_param_positions
                and self._expression_is_tainted(argument)
            ):
                return True
        return False

    def _call_argument_map(
        self,
        node: ast.Call,
        summary: FunctionSummary | list[str],
    ) -> list[tuple[int, ast.AST]]:
        if isinstance(summary, list):
            params = summary
            model = FunctionParameters(positional_or_keyword=tuple(params))
            defaults: dict[int, ast.expr] = {}
        else:
            params = summary.params
            model = summary.parameter_model or FunctionParameters(
                positional_or_keyword=tuple(params)
            )
            defaults = summary.parameter_defaults
        mapped: list[tuple[int, ast.AST]] = []
        bound: set[int] = set()
        name_to_index = {name: index for index, name in enumerate(params)}
        positional_indices = [
            name_to_index[name]
            for name in model.positional_names
            if name in name_to_index
        ]
        var_positional_index = (
            name_to_index.get(model.var_positional)
            if model.var_positional is not None else None
        )
        var_keyword_index = (
            name_to_index.get(model.var_keyword)
            if model.var_keyword is not None else None
        )

        def add_binding(
            index: int | None,
            expression: ast.AST,
            allow_multiple: bool = False,
        ) -> None:
            if index is None or (index in bound and not allow_multiple):
                return
            mapped.append((index, expression))
            if not allow_multiple:
                bound.add(index)

        def bind_positional(expression: ast.AST) -> None:
            next_index = next(
                (index for index in positional_indices if index not in bound),
                None,
            )
            if next_index is not None:
                add_binding(next_index, expression)
            elif var_positional_index is not None:
                add_binding(var_positional_index, expression, True)

        def bind_unknown_star(expression: ast.AST) -> None:
            for index in positional_indices:
                add_binding(index, expression)
            add_binding(var_positional_index, expression, True)

        def bind_keyword(name: str, expression: ast.AST) -> None:
            if name in model.positional_only:
                add_binding(var_keyword_index, expression, True)
                return
            index = name_to_index.get(name)
            if index is not None and name in model.keyword_names:
                add_binding(index, expression)
                return
            add_binding(var_keyword_index, expression, True)

        def bind_unknown_kwargs(expression: ast.AST) -> None:
            for name in model.keyword_names:
                add_binding(name_to_index.get(name), expression)
            add_binding(var_keyword_index, expression, True)
        for argument in node.args:
            if isinstance(argument, ast.Starred):
                value = argument.value
                if isinstance(value, (ast.Tuple, ast.List)):
                    for element in value.elts:
                        bind_positional(element)
                else:
                    bind_unknown_star(value)
            else:
                bind_positional(argument)
        for keyword in node.keywords:
            if keyword.arg is not None:
                bind_keyword(keyword.arg, keyword.value)
                continue
            value = keyword.value
            if isinstance(value, ast.Dict):
                for key, dict_value in zip(value.keys, value.values):
                    if isinstance(key, ast.Constant) and isinstance(
                        key.value, str
                    ):
                        bind_keyword(key.value, dict_value)
                    else:
                        bind_unknown_kwargs(dict_value)
            else:
                bind_unknown_kwargs(value)
        for index, default_expression in defaults.items():
            if index not in bound:
                add_binding(index, default_expression)
        return mapped

    def _expression_is_tainted(self, expression: ast.AST) -> bool:
        state = self._get_expression_state(expression)
        return bool(state[0] and state[1])

    def _expression_param_sources(self, expression: ast.AST) -> set[int]:
        positions: set[int] = set()
        pending_nodes = [expression]
        while pending_nodes:
            node = pending_nodes.pop()
            # A Boolean result from ``not`` no longer carries the source
            # identity of the operand that was tested.
            if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
                continue
            pending_nodes.extend(ast.iter_child_nodes(node))
            if isinstance(node, ast.Name):
                positions.update(
                    self.variable_param_sources.get(node.id, set())
                )
            elif isinstance(node, ast.Call):
                call_name = self._get_name(node.func)
                summary = self._resolve_function_summary(call_name)
                if summary is not None:
                    for formal_index, argument in self._call_argument_map(
                        node, summary
                    ):
                        if (
                            formal_index in summary.return_param_positions
                            and self._expression_is_tainted(argument)
                        ):
                            positions.update(
                                self._expression_param_sources(argument)
                            )
        return positions

    def _expression_param_positions(self, expression: ast.AST) -> set[int]:
        return self._expression_param_sources(expression)

    @staticmethod
    def _get_name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = PythonASTAnalyzer._get_name(node.value)
            if parent:
                return f"{parent}.{node.attr}"
        return ""

    def _add_sql_finding(self, line_number: int) -> None:
        if any(
            finding.line_number == line_number and finding.cwe == "CWE-89"
            for finding in self.findings
        ):
            return
        self.findings.append(
            SecurityFinding(
                rule_id="RSC-AST-SQL-001",
                title="Potential SQL Injection Through User Input",
                description=(
                    "Potentially untrusted user input appears to reach "
                    "a dynamically constructed SQL query."
                ),
                severity="HIGH",
                confidence="MEDIUM",
                cwe="CWE-89",
                file_path=self.file_path,
                line_number=line_number,
                language="Python",
                evidence=(
                    "A potentially untrusted value was detected in "
                    "a dynamically constructed SQL statement."
                ),
                recommendation=(
                    "Use parameterized SQL queries and pass user input "
                    "as query parameters instead of building SQL strings."
                ),
            )
        )
