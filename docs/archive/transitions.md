# State transition graph

The "model proposes, code decides" principle enforced at the code level.

```
                    ┌───────────────────────────────────────┐
                    │                                       │
                    ▼                                       │
    ┌──────────┐  hypothesise.py  ┌───────────┐             │
    │ PROPOSED │─────────────────▶│ PROPOSED  │             │
    └──────────┘                  └───────────┘             │
                        │                                   │
                        │ execute.py                        │
                        │ (mark_tested)                     │
                        ▼                                   │
                   ┌──────────┐                             │
                   │ TESTED   │                             │
                   └──────────┘                             │
                    │       │                               │
         verify.py  │       │  verify.py                    │
         (confirm)  │       │  (refute)                     │
                    ▼       ▼                               │
              ┌──────────┐ ┌──────────┐                     │
              │CONFIRMED │ │ REFUTED  │─────────────────────┘
              └──────────┘ └──────────┘
```

Key design wins:

- Only execute.py can mark PROPOSED → TESTED
- Only verify.py can mark TESTED → CONFIRMED or TESTED → REFUTED
- hypothesise.py only ever produces PROPOSED
- Greppable enforcement: literally wrote grep for status=Status.TESTED and you find it here, only here
