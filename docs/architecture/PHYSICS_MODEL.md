# Physics model and software boundary

Physics supplies precise design constraints here; it is not a claim that software
requests obey physical laws.

## Directed graph

The system is a directed attributed graph `G = (V, E)`. Nodes are principals,
clients, GaugeMesh instances, capabilities, MCP servers, models, registries,
approval channels, and credential authorities. Edges are protocol and trust
boundaries. Stable typed IDs identify nodes; display aliases never grant access.

The analogy ends at graph reachability: network nodes are not physical objects.

## Request state and conservation

`RequestContext` is the typed logical state. Tenant, principal (except through an
explicit delegation proof), causal root, side-effect class, schema, trace parent,
and provenance are conserved. Scope, deadline, money, tokens, retries, and
delegated authority may only decrease. Data classification may only stay equal or
become more protective. Causal observations and decisions are append-only.

An adapter is analogous to a gauge transformation only because representation may
change while observable identity remains stable. It is ordinary protocol
translation, not a physical gauge field. The implementation returns a
machine-readable `ConservationReport` and rejects required loss before effects.

## Semantic loss score

Optional translation losses have integer weights. Their sum is the semantic loss
score. Required invariant loss has no finite score and is rejected. This is not
Shannon entropy; no probabilistic information measure is computed.

## Least-action route selection

After hard constraints, each route receives an integer action score:

`latency*wL + cost*wC + failure*wF + semantic_loss*wH + pressure*wQ + exposure*wX + switching*wS`

Inputs are bounded integer snapshots. Candidate order is canonical and ties use
the stable route ID. A model is not consulted. The analogy ends at constrained
deterministic minimization; GaugeMesh does not model a physical trajectory.

## Pressure, dissipation, and hysteresis

Pressure is bounded queued work divided by configured capacity, represented as an
integer scale. Per-tenant bounded queues and deficit round robin propagate
backpressure. Retries dissipate time, token, monetary, and retry budgets; a retry
cannot manufacture budget. Circuit breakers use separate opening and recovery
thresholds plus an open interval, which supplies hysteresis and a switching
penalty.

## Causal cone

A capability lease defines the reachable subgraph allowed by principal, tenant,
scope, side-effect contract, schema, deadline, budget, route policy, and network
policy. An invocation outside that graph fails before execution. “Causal cone” is
only the name for that software reachability bound.

