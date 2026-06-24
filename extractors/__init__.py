"""Language-neutral types for security fact extraction.

Each language-specific extractor (extractors/python.py, etc.) returns
list[SecurityFact]. SecurityFact is always a dict with a "type" key.

Fact schemas:

  {"type": "subprocess",        "shell": True|False|"default_false"|"unknown",
                                 "argv_style": "list"|"string"|"unknown",
                                 "arg_source": ARG_SOURCE}

  {"type": "file_write",        "path_source": ARG_SOURCE}
  {"type": "file_read",         "path_source": ARG_SOURCE}

  {"type": "dangerous_sink",    "name": str, "arg_source": ARG_SOURCE}
    Known names: eval, exec, compile, pickle.loads, pickle.load, yaml.load,
    marshal.loads, marshal.load, os.system, os.popen,
    subprocess.run(shell=True), subprocess.call(shell=True),
    subprocess.check_output(shell=True), subprocess.check_call(shell=True),
    subprocess.Popen(shell=True)

  {"type": "environment_access","call": "os.getenv"|"os.environ[]"|
                                         "os.environ.get"|"environ.get"}

shell field semantics:
  True/False      explicit boolean constant in source
  "default_false" shell kwarg absent; relies on stdlib default
  "unknown"       dynamic expression; static analysis cannot resolve

ARG_SOURCE (the provenance of the value reaching a sink) is one of:
  "parameter:NAME"    a bare parameter, direct identity
  "parameter-derived" a parameter flows in via interpolation or a collection element
  "constant"          a literal; no parameter can reach it
  "unknown"           a helper call, a local, or anything the single-function pass
                      cannot follow

"unknown" is the honest answer when static analysis hits a limit; it is
distinct from the absence of a fact, and distinct from "constant". A value the
pass cannot follow is not proof the attacker has no influence over it.
Extractors report facts, not conclusions.
"""
from __future__ import annotations

from typing import Any

SecurityFact = dict[str, Any]
