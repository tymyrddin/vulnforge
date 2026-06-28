"""Index stage: parse Python files from the ingest manifest into function-level
slices. Pure AST analysis; no AI.

Each slice captures function signature, body, decorators, intra-file call
graph context, globals referenced, and file-level imports. Output is a
content-addressed manifest mapping slice_id -> slice_ref."""

from __future__ import annotations

import ast
import json
import time
from typing import Any

from audit.log import append as audit_append
from extractors.python import extract as _extract_python_facts
from schema.audit_event import AuditEvent
from store import objects, refs


def run(manifest_ref: str) -> str:
    manifest: dict[str, str] = json.loads(objects.get(manifest_ref))

    slices: dict[str, str] = {}
    py_count = 0

    for file_path, file_hash in sorted(manifest.items()):
        if not file_path.endswith(".py"):
            continue
        py_count += 1
        try:
            source = objects.get(file_hash).decode("utf-8", errors="replace")
            tree = ast.parse(source, filename=file_path)
        except (SyntaxError, ValueError):
            continue
        for slice_id, slice_data in _index_file(file_path, file_hash, source, tree).items():
            blob = json.dumps(slice_data, sort_keys=True, separators=(",", ":")).encode()
            slices[slice_id] = objects.put(blob)

    manifest_bytes = json.dumps(slices, sort_keys=True, separators=(",", ":")).encode()
    slices_manifest_ref = objects.put(manifest_bytes)
    refs.write("index_latest", slices_manifest_ref)
    audit_append(
        AuditEvent(
            timestamp=time.time(),
            stage="index",
            input_refs=(manifest_ref,),
            output_refs=(slices_manifest_ref,),
            model_hash=None,
            seed=None,
            summary=f"{len(slices)} slices from {py_count} Python files",
        )
    )
    return slices_manifest_ref


def _index_file(
    file_path: str,
    file_hash: str,
    source: str,
    tree: ast.Module,
) -> dict[str, dict[str, Any]]:
    source_lines = source.splitlines()
    imports = _file_imports(tree)
    module_names = _module_names(tree)

    funcs: dict[str, dict[str, Any]] = {}
    for qname, node in _collect_functions(tree):
        calls = _calls(node)
        funcs[qname] = {
            "function_name": qname,
            "file_path": file_path,
            "file_hash": file_hash,
            "parameters": _params(node),
            "return_type": ast.unparse(node.returns) if node.returns else None,
            "body": _body(node, source_lines),
            "decorators": [ast.unparse(d) for d in node.decorator_list],
            "calls": calls,
            "globals_used": _globals_used(node, module_names),
            "imports": imports,
            "context": {"callers": [], "callees": []},
            "security_facts": _extract_python_facts(node),
        }

    for caller, data in funcs.items():
        for callee in data["calls"]:
            if callee in funcs:
                funcs[callee]["context"]["callers"].append(caller)
                data["context"]["callees"].append(callee)

    return {f"{file_path}::{qname}": data for qname, data in funcs.items()}


def _collect_functions(
    tree: ast.Module,
) -> list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]]:
    result = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            result.append((node.name, node))
        elif isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    result.append((f"{node.name}.{item.name}", item))
    return result


def _file_imports(tree: ast.Module) -> list[str]:
    out = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            for a in node.names:
                out.append("import " + a.name + (f" as {a.asname}" if a.asname else ""))
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            names = ", ".join(a.name + (f" as {a.asname}" if a.asname else "") for a in node.names)
            out.append(f"from {module} import {names}")
    return out


def _module_names(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    names.add(t.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
        elif isinstance(node, ast.Import):
            for a in node.names:
                names.add(a.asname or a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for a in node.names:
                names.add(a.asname or a.name)
    return names


def _params(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    out = []
    for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
        ann = f": {ast.unparse(arg.annotation)}" if arg.annotation else ""
        out.append(f"{arg.arg}{ann}")
    if node.args.vararg:
        a = node.args.vararg
        out.append(f"*{a.arg}" + (f": {ast.unparse(a.annotation)}" if a.annotation else ""))
    if node.args.kwarg:
        a = node.args.kwarg
        out.append(f"**{a.arg}" + (f": {ast.unparse(a.annotation)}" if a.annotation else ""))
    return out


def _body(node: ast.FunctionDef | ast.AsyncFunctionDef, lines: list[str]) -> str:
    if not node.body:
        return ""
    return "\n".join(lines[node.lineno - 1 : node.end_lineno])


def _calls(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    seen: set[str] = set()
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        if isinstance(child.func, ast.Name):
            seen.add(child.func.id)
        elif isinstance(child.func, ast.Attribute):
            seen.add(ast.unparse(child.func))
    return sorted(seen)


def _globals_used(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    module_names: set[str],
) -> list[str]:
    local: set[str] = {a.arg for a in node.args.posonlyargs + node.args.args + node.args.kwonlyargs}
    if node.args.vararg:
        local.add(node.args.vararg.arg)
    if node.args.kwarg:
        local.add(node.args.kwarg.arg)
    for child in ast.walk(node):
        if isinstance(child, ast.Assign):
            for t in child.targets:
                if isinstance(t, ast.Name):
                    local.add(t.id)
        elif (
            isinstance(child, ast.AnnAssign)
            and isinstance(child.target, ast.Name)
            or isinstance(child, (ast.For, ast.AsyncFor))
            and isinstance(child.target, ast.Name)
            or isinstance(child, ast.NamedExpr)
        ):
            local.add(child.target.id)
    referenced: set[str] = {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}
    return sorted((module_names & referenced) - local)
