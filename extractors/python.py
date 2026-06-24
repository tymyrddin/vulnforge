"""Python AST extractor for security facts.

Single public entry point: extract(node) -> list[SecurityFact].
Four sub-walkers: subprocess, file path, dangerous sink, environment access.
"""
from __future__ import annotations

import ast
from typing import Any

from extractors import SecurityFact

_SUBPROCESS_FUNCS = frozenset({
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_output",
    "subprocess.check_call",
    "subprocess.Popen",
})

_OS_SHELL_FUNCS = frozenset({
    "os.system",
    "os.popen",
})

_DANGEROUS_SINKS = frozenset({
    "eval", "exec", "compile",
    "pickle.loads", "pickle.load",
    "yaml.load",
    "marshal.loads", "marshal.load",
    "os.system", "os.popen",
})

_ENV_CALL_FUNCS = frozenset({
    "os.getenv",
    "os.environ.get",
    "environ.get",
})


def extract(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[SecurityFact]:
    param_names = _param_names(node)
    facts: list[SecurityFact] = []
    facts.extend(_subprocess_facts(node, param_names))
    facts.extend(_file_path_facts(node, param_names))
    facts.extend(_dangerous_sink_facts(node, param_names))
    facts.extend(_environment_access_facts(node))
    return facts


def _param_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    names: set[str] = set()
    for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
        names.add(arg.arg)
    if node.args.vararg:
        names.add(node.args.vararg.arg)
    if node.args.kwarg:
        names.add(node.args.kwarg.arg)
    return names


def _subprocess_facts(
    node: ast.FunctionDef | ast.AsyncFunctionDef, param_names: set[str]
) -> list[SecurityFact]:
    facts: list[SecurityFact] = []
    seen: set[tuple[Any, str, str]] = set()

    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue

        func_name = ast.unparse(child.func)

        if func_name in _OS_SHELL_FUNCS:
            arg_source = _classify_arg(child.args[0], param_names) if child.args else "unknown"
            key: tuple[Any, str, str] = (True, "string", arg_source)
            if key not in seen:
                seen.add(key)
                facts.append({
                    "type": "subprocess", "shell": True,
                    "argv_style": "string", "arg_source": arg_source,
                })
            continue

        if func_name not in _SUBPROCESS_FUNCS:
            continue

        shell_kwarg = next((kw for kw in child.keywords if kw.arg == "shell"), None)
        if shell_kwarg is None:
            shell: bool | str = "default_false"
        elif isinstance(shell_kwarg.value, ast.Constant):
            shell = bool(shell_kwarg.value.value)
        else:
            shell = "unknown"

        if child.args:
            first = child.args[0]
            if isinstance(first, (ast.List, ast.Tuple)):
                argv_style = "list"
            elif isinstance(first, ast.JoinedStr):
                argv_style = "string"
            elif isinstance(first, ast.Constant) and isinstance(first.value, str):
                argv_style = "string"
            else:
                argv_style = "unknown"
            arg_source = _classify_arg(first, param_names)
        else:
            argv_style = "unknown"
            arg_source = "unknown"

        key = (shell, argv_style, arg_source)
        if key not in seen:
            seen.add(key)
            facts.append({
                "type": "subprocess", "shell": shell,
                "argv_style": argv_style, "arg_source": arg_source,
            })

    return facts


def _classify_arg(node: ast.expr, param_names: set[str]) -> str:
    """Provenance of a value reaching a sink, as far as a single-function AST pass
    can tell. Honest about its own limits: a value it cannot follow is "unknown",
    never "constant". "unknown" means analysis stopped, not that the attacker has no
    influence.

      parameter:NAME      bare parameter, direct identity
      parameter-derived   parameter flows in via interpolation or a collection element
      constant            literal, no parameter can reach it
      unknown             a helper call, a local, or anything else this pass cannot follow
    """
    if isinstance(node, ast.Name):
        return f"parameter:{node.id}" if node.id in param_names else "unknown"
    if isinstance(node, ast.Constant):
        return "constant" if isinstance(node.value, str) else "unknown"
    if isinstance(node, ast.Starred):
        return _classify_arg(node.value, param_names)
    if isinstance(node, ast.JoinedStr):
        # An f-string is parameter-derived when any interpolated value is a parameter.
        for value in node.values:
            if isinstance(value, ast.FormattedValue) and _reaches_parameter(value.value, param_names):
                return "parameter-derived"
        return "constant" if node.values and all(isinstance(v, ast.Constant) for v in node.values) else "unknown"
    if isinstance(node, (ast.List, ast.Tuple)):
        return _aggregate_arg([_classify_arg(e, param_names) for e in node.elts])
    return "unknown"


def _reaches_parameter(node: ast.expr, param_names: set[str]) -> bool:
    return any(
        isinstance(child, ast.Name) and child.id in param_names
        for child in ast.walk(node)
    )


def _aggregate_arg(sources: list[str]) -> str:
    """Provenance of a collection: take the strongest claim across elements, so a
    single attacker-reachable element is not masked by neighbouring constants."""
    if any(s.startswith("parameter:") for s in sources):
        return next(s for s in sources if s.startswith("parameter:"))
    if "parameter-derived" in sources:
        return "parameter-derived"
    if "unknown" in sources:
        return "unknown"
    return "constant"


def _open_fact_type(call: ast.Call, *, is_method: bool) -> str:
    mode_arg_index = 0 if is_method else 1
    mode_str = None
    if len(call.args) > mode_arg_index:
        m = call.args[mode_arg_index]
        if isinstance(m, ast.Constant) and isinstance(m.value, str):
            mode_str = m.value
    if mode_str is None:
        for kw in call.keywords:
            if kw.arg == "mode":
                if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    mode_str = kw.value.value
                break
    if mode_str and any(c in mode_str for c in "wax"):
        return "file_write"
    return "file_read"


def _file_path_facts(
    node: ast.FunctionDef | ast.AsyncFunctionDef, param_names: set[str]
) -> list[SecurityFact]:
    facts: list[SecurityFact] = []
    seen: set[tuple[str, str]] = set()

    _write_methods = frozenset({"write_text", "write_bytes"})
    _read_methods = frozenset({"read_text", "read_bytes"})

    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue

        func = child.func

        if isinstance(func, ast.Name) and func.id == "open":
            path_node: ast.expr | None = child.args[0] if child.args else None
            if path_node is None:
                for kw in child.keywords:
                    if kw.arg == "file":
                        path_node = kw.value
                        break
            if path_node is None:
                continue
            fact_type = _open_fact_type(child, is_method=False)
            path_source = _classify_arg(path_node, param_names)
            key = (fact_type, path_source)
            if key not in seen:
                seen.add(key)
                facts.append({"type": fact_type, "path_source": path_source})

        elif isinstance(func, ast.Attribute):
            method = func.attr
            receiver = func.value

            if method in _write_methods:
                path_source = _classify_arg(receiver, param_names)
                key = ("file_write", path_source)
                if key not in seen:
                    seen.add(key)
                    facts.append({"type": "file_write", "path_source": path_source})

            elif method in _read_methods:
                path_source = _classify_arg(receiver, param_names)
                key = ("file_read", path_source)
                if key not in seen:
                    seen.add(key)
                    facts.append({"type": "file_read", "path_source": path_source})

            elif method == "open":
                fact_type = _open_fact_type(child, is_method=True)
                path_source = _classify_arg(receiver, param_names)
                key = (fact_type, path_source)
                if key not in seen:
                    seen.add(key)
                    facts.append({"type": fact_type, "path_source": path_source})

    return facts


def _dangerous_sink_facts(
    node: ast.FunctionDef | ast.AsyncFunctionDef, param_names: set[str]
) -> list[SecurityFact]:
    facts: list[SecurityFact] = []
    seen: set[tuple[str, str]] = set()

    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue

        name = ast.unparse(child.func)
        arg_source = _classify_arg(child.args[0], param_names) if child.args else "unknown"

        if name in _DANGEROUS_SINKS and (name, arg_source) not in seen:
            seen.add((name, arg_source))
            facts.append({"type": "dangerous_sink", "name": name, "arg_source": arg_source})

        if name in _SUBPROCESS_FUNCS:
            shell_kwarg = next((kw for kw in child.keywords if kw.arg == "shell"), None)
            if (shell_kwarg
                    and isinstance(shell_kwarg.value, ast.Constant)
                    and shell_kwarg.value.value is True):
                sink_name = f"{name}(shell=True)"
                if (sink_name, arg_source) not in seen:
                    seen.add((sink_name, arg_source))
                    facts.append({"type": "dangerous_sink", "name": sink_name, "arg_source": arg_source})

    return facts


def _environment_access_facts(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[SecurityFact]:
    facts: list[SecurityFact] = []
    seen: set[str] = set()

    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            name = ast.unparse(child.func)
            if name in _ENV_CALL_FUNCS and name not in seen:
                seen.add(name)
                facts.append({"type": "environment_access", "call": name})

        elif isinstance(child, ast.Subscript):
            value_name = ast.unparse(child.value)
            if value_name == "os.environ":
                call_name = "os.environ[]"
                if call_name not in seen:
                    seen.add(call_name)
                    facts.append({"type": "environment_access", "call": call_name})

    return facts
