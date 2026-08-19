# AETS differential execution v1

Issue #158 connects a compiled AETS QSM to three independent WebAssembly
execution paths without changing the public-only input contract frozen by
Issue #159.

The source-derived artifact remains an expected trace, not an interpreter. An
actual `quotient-seal-small-step` execution must match its complete observable
trace and termination before source-to-target refinement is `MATCH`. The
small-step run then serves as the existing `DifferentialOracle` reference for
the actual `wasmi` and Wasmtime runs.

All four records bind the same module, ABI, host tape, context sequence, and
resource limits. Engine identity is deliberately excluded only from the shared
input hash. Every engine retains its own version, configuration, and caller-
supplied enclosing executable digest.

The aggregate verdict is fail closed:

- `MATCH` requires both source refinement and the three-engine oracle to match.
- `COUNTEREXAMPLE` retains the first typed trace or termination difference.
- `UNRESOLVED` covers parser, unsupported feature, timeout, resource bound, and
  engine failure outcomes; it is never promoted to a successful observation.

Canonical JSON retains the source expectation, source-refinement result, and
all three engine artifacts. No private biosignal, evidence, baseline, or key is
accepted by this layer. Hardware execution remains `NOT_VERIFIED`, and no
priority or world-first claim is made.
