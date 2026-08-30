# ADR 0001: Preserve invariants at protocol boundaries

Status: accepted

GaugeMesh is a local-first routing mesh, not a general AI platform. Its core
contract is to preserve or explicitly reject identity, authority, budget,
deadline, side-effect, schema, and causal semantics at every adapter boundary.
Infrastructure routing is deterministic and does not call a model.
