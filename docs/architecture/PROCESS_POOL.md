# Process and connection isolation

A namespace is never a process identity. `ProcessKey` binds the reviewed server configuration,
exact executable identity, MCP revision, tenant security partition, upstream credential identity,
environment digest, shareability class, and—where required—principal or unique instance partition.

Unknown servers default to `NON_SHAREABLE`. Principal-isolated entries require a principal
partition; non-shareable entries require an instance nonce. The pool has a hard semaphore bound,
reference counts, startup/shutdown/idle limits, and a finite restart budget with generation
tracking. RMCP spawns stdio with an exact executable plus argument array; no shell is involved and
the child transport is cancelled after use.

The current pool core deliberately does not claim production child-tree containment on Windows.
Platform job objects/process groups, stderr and framing caps, idle reaping, and fault-injected orphan
tests remain release gates. The stdio integration test does verify that GaugeMesh owns, cancels, and
joins the direct child it starts.
