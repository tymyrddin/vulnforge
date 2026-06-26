# The taint-grounding screen stage

## Context

The model proposes attack classes by recall, which is broad and largely
uninformed by whether the class has anywhere in the slice to act. Before the
screen, acceptance depended on the model honouring a prompt rule, and a fact
about a sink was being read as if it proved attacker-controlled data reached
that sink. The system could look more decisive than the analysis warranted.

## Decision

`stages/screen.py` sits between hypothesise and synthesise. It checks, in code,
whether the slice's security facts ground each proposed attack class: does an
operation of the named kind exist, and does a value a caller controls reach it.
The check reads the `arg_source` provenance attached to each sink fact at index
time (`extractors/python.py`), not the prose of the hypothesis. Four things
settled here:

- Source versus sink. A fact about a sink is not evidence that
  attacker-controlled data reaches it. `arg_source` makes the source-to-sink
  link explicit and machine-computed. This was the reviewer's central criticism.
- Prompt versus code. The load-bearing logic moved out of hypothesise prompt
  rule 12 and into the deterministic screen stage. Rule 12 stays as a cheap
  upstream nudge, but acceptance no longer depends on the model honouring it.
- Screen placement. Between hypothesise and synthesise, not hypothesise and
  execute: rejecting before synthesise saves the synthesis model call as well as
  the container launch. The `stages/` run showed it concretely, 61 proposals
  down to 1 synthesise call.
- Confidence semantics. Effective confidence is downstream of grounding policy
  (`decide_policy` in `schema/screen.py`), not the model's number passed
  through.

`schema/screen.py:Grounding` has exactly four values: grounded (a controlled
input reaches a matching sink, accept at the model's confidence), unknown (a
matching sink exists but provenance is unresolved, accept at a capped prior),
contradicted (the facts rule the mechanism out, reject), unsupported (no
matching sink, reject).

The split exists to keep "not tainted" (constant, contradicted) separate from
"taint unresolved" (unknown). A lost trail is the analysis reaching its limit,
not proof the attacker has no influence, so an unknown is kept at a lowered prior
rather than discarded. A class with no detector lands unknown, never unsupported,
so a novel class is penalised rather than silently dropped.

Two extension points are now explicit. The attack-class predicate registry in
`stages/screen.py` (the synonym sets and the sink-name sets they map onto) is a
one-place edit for a new class. The provenance model in `extractors/python.py`
returns `list[SecurityFact]` and today resolves a bare parameter
(`parameter:NAME`), a parameter reaching the sink through an f-string or
collection (`parameter-derived`), and a string literal (`constant`); everything
else lands `unknown`. That return type is the contract a new-language extractor
implements, and that frontier is what richer provenance extends.

## Why

Making the source-to-sink relation consequential in code, rather than advisory
in a prompt, turns recall into something checkable. Collapsing unknown into
either accept-fully or reject would let the system represent more certainty than
the analysis holds; the split preserves the distinction between what is known
and what is unresolved. Adding a new attack class or a new language has a defined
home in the registry and the extractor rather than in prose.

The cap value (0.35) is provisional policy, not a calibrated number: its only
load-bearing property is that unknown ranks below grounded. Whether 0.35 is
right, and whether unknown deserves acceptance at all, is empirical and left
open. [../roadmap/README.md](../roadmap/README.md) tracks this.
