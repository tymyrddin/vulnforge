"""Unit tests for extractors.python.extract. No podman, no weights."""
import ast

import pytest

from extractors.python import extract


def _fn(src: str) -> ast.FunctionDef:
    return ast.parse(src).body[0]  # type: ignore[return-value]


def test_subprocess_shell_false():
    facts = extract(_fn("def f(cmd): subprocess.run(cmd, shell=False)"))
    assert any(f["type"] == "subprocess" and f["shell"] is False for f in facts)


def test_subprocess_shell_true():
    facts = extract(_fn("def f(cmd): subprocess.run(cmd, shell=True)"))
    assert any(f["type"] == "subprocess" and f["shell"] is True for f in facts)


def test_subprocess_shell_unknown():
    facts = extract(_fn("def f(cmd, s): subprocess.run(cmd, shell=s)"))
    assert any(f["type"] == "subprocess" and f["shell"] == "unknown" for f in facts)


def test_subprocess_shell_default():
    facts = extract(_fn("def f(cmd): subprocess.run(cmd)"))
    assert any(f["type"] == "subprocess" and f["shell"] == "default_false" for f in facts)


def test_subprocess_argv_list():
    facts = extract(_fn("def f(): subprocess.run(['ls', '-la'])"))
    assert any(f["type"] == "subprocess" and f["argv_style"] == "list" for f in facts)


def test_subprocess_argv_string():
    facts = extract(_fn("def f(): subprocess.run('ls -la', shell=True)"))
    assert any(f["type"] == "subprocess" and f["argv_style"] == "string" for f in facts)


def test_os_system_is_shell_true():
    facts = extract(_fn("def f(cmd): os.system(cmd)"))
    assert any(f["type"] == "subprocess" and f["shell"] is True for f in facts)


def test_file_write_from_parameter():
    facts = extract(_fn("def f(path): open(path, 'w')"))
    assert any(
        f["type"] == "file_write" and f["path_source"] == "parameter:path"
        for f in facts
    )


def test_file_read_from_parameter():
    facts = extract(_fn("def f(path): open(path, 'r')"))
    assert any(
        f["type"] == "file_read" and f["path_source"] == "parameter:path"
        for f in facts
    )


def test_file_read_default_mode():
    facts = extract(_fn("def f(path): open(path)"))
    assert any(f["type"] == "file_read" for f in facts)


def test_write_text_from_parameter():
    facts = extract(_fn("def f(p): p.write_text('hello')"))
    assert any(
        f["type"] == "file_write" and f["path_source"] == "parameter:p"
        for f in facts
    )


def test_path_open_write():
    facts = extract(_fn("def f(p): p.open('wb+')"))
    assert any(f["type"] == "file_write" for f in facts)


def test_dangerous_sink_eval():
    facts = extract(_fn("def f(x): return eval(x)"))
    assert any(f["type"] == "dangerous_sink" and f["name"] == "eval" for f in facts)


def test_dangerous_sink_exec():
    facts = extract(_fn("def f(x): exec(x)"))
    assert any(f["type"] == "dangerous_sink" and f["name"] == "exec" for f in facts)


def test_dangerous_sink_subprocess_shell_true():
    facts = extract(_fn("def f(cmd): subprocess.run(cmd, shell=True)"))
    assert any(
        f["type"] == "dangerous_sink" and "shell=True" in f["name"]
        for f in facts
    )


def test_dangerous_sink_subprocess_shell_false_not_a_sink():
    facts = extract(_fn("def f(cmd): subprocess.run(cmd, shell=False)"))
    assert not any(
        f["type"] == "dangerous_sink" and "shell=True" in f.get("name", "")
        for f in facts
    )


def test_environment_access_getenv():
    facts = extract(_fn("def f(): return os.getenv('HOME')"))
    assert any(f["type"] == "environment_access" and f["call"] == "os.getenv" for f in facts)


def test_environment_access_subscript():
    facts = extract(_fn("def f(): return os.environ['HOME']"))
    assert any(f["type"] == "environment_access" and f["call"] == "os.environ[]" for f in facts)


def test_no_facts_for_clean_function():
    facts = extract(_fn("def f(x, y): return x + y"))
    assert facts == []
