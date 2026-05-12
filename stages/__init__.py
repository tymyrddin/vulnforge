"""Pipeline stages. Each stage reads refs from the store, writes refs back, and
appends one audit event. Stages communicate by digest, not in-process state."""
