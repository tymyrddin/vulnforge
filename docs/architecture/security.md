# Security facts and the screen

How facts get extracted from code, and how the screen consumes them. Why the screen exists and why
facts were chosen this way is recorded in
[../decisions/2026-06-24-grounding-screen.md](../decisions/2026-06-24-grounding-screen.md) and
[../decisions/2026-06-18-security-facts.md](../decisions/2026-06-18-security-facts.md).

## Security fact extractor (`extractors/`)

A two-file package. `__init__.py` defines the shared type alias; `python.py` does the AST work.

```
extractors/
  __init__.py   # SecurityFact = dict[str, Any]; schema docstring only
  python.py     # extract(node) -> list[SecurityFact]
```

`extract()` runs four sub-walkers over the function AST:

| Sub-walker | Detects | Fact type |
|---|---|---|
| Subprocess | `subprocess.run/call/check_output/check_call/Popen`, `os.system`, `os.popen` | `subprocess` |
| File path | `open()`, `.open()`, `.write_text/bytes()`, `.read_text/bytes()` | `file_write` / `file_read` |
| Dangerous sink | `eval`, `exec`, `compile`, `pickle.loads`, `yaml.load`, `marshal.loads`, `os.system`, `os.popen`, `subprocess.*(shell=True)` | `dangerous_sink` |
| Environment access | `os.getenv()`, `os.environ[]`, `os.environ.get()`, `environ.get()` | `environment_access` |

Fact schema:

```
{"type": "subprocess",        "shell": True|False|"default_false"|"unknown", "argv_style": "list"|"string"|"unknown", "arg_source": ARG_SOURCE}
{"type": "file_write",        "path_source": ARG_SOURCE}
{"type": "file_read",         "path_source": ARG_SOURCE}
{"type": "dangerous_sink",    "name": str, "arg_source": ARG_SOURCE}
{"type": "environment_access","call": "os.getenv"|"os.environ[]"|"os.environ.get"|"environ.get"}
```

## Shell semantics

For `subprocess` facts, the `shell` field carries one of:

- `True`/`False`: explicit boolean constant in source.
- `"default_false"`: the `shell` kwarg is absent and relies on the stdlib default (weaker than an
  explicit `False`).
- `"unknown"`: a dynamic expression that static analysis cannot resolve.

## arg_source and the _classify_arg coverage frontier

`ARG_SOURCE` is the provenance of the value reaching the sink, computed by the shared `_classify_arg`
helper:

- `"parameter:NAME"`: a bare parameter, direct identity.
- `"parameter-derived"`: a parameter flows in via f-string interpolation or as a collection element.
- `"constant"`: a literal; no parameter can reach it.
- `"unknown"`: a helper call, a local, or anything the single-function pass cannot follow.

`"unknown"` is recorded when the extractor hits a static analysis limit. It differs from absence of a
fact, and from `"constant"`: a value the pass cannot follow is not proof the attacker has no influence
over it. The screen relies on this distinction.

## Screen stage (`stages/screen.py`)

The screen grounds each hypothesis against the slice's security facts, in code, before any payload is
synthesised. It maps the model's proposed attack class onto the facts and asks whether a parameter
actually reaches a sink of the right kind.

### Grounding states

`schema/screen.py` defines the `Grounding` enum:

- `grounded`: a parameter reaches a matching sink. Accept at full confidence.
- `unknown`: a matching sink exists but provenance is unresolved. Accept, but cap confidence at
  `UNKNOWN_CONFIDENCE_CAP` = 0.35.
- `contradicted`: facts rule the mechanism out. Reject.
- `unsupported`: no matching sink. Reject.

### decide_policy and the cap

Two pure functions carry the logic. `_grounding(hyp, facts, imports)` computes the state from an
attack-class predicate table plus `arg_source`, resolving multiple matching sinks by precedence
(grounded > unknown > contradicted > unsupported). `decide_policy()` maps a state to
(accepted, effective_confidence) and applies the cap.

The 0.35 cap is a policy constant, not a calibrated value. The property it enforces is that unknown
ranks below grounded.

Verdicts for rejected hypotheses are stored too, not discarded, so a later run can ask how many
unknown findings ever verify.
