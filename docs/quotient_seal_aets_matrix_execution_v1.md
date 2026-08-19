# AETS adversarial matrix execution v1

Issue #163 executes every canonical case from Issue #164 through the AETS
source expectation, actual QuotientSeal small-step interpreter, wasmi, and
Wasmtime.

The case's `ExecutionLimits` are used exactly. A non-continue public host axis
replaces the outcome of the first host directive while preserving its import
name and every later directive. This deterministic injection point is recorded
in the case artifact. If a case has no host directive, a non-continue host axis
is `UNRESOLVED_NOT_APPLICABLE`, never a successful fault observation; the
unchanged participant runs are still retained.

Source-derived expected traces remain identified as expectations rather than
interpreters. Their public host event and termination are projected from the
same injected tape. Small-step host-fault termination is normalized to the
engine-independent `HOST_TIMEOUT`, `HOST_RECONNECT`, and `HOST_LOSS` codes used
by both external adapters.

Each case stores the complete differential artifact and effective case
verdict. Matrix aggregation prioritizes `UNRESOLVED`, then `COUNTEREXAMPLE`,
then `MATCH`. Canonical JSON follows case-ID order and binds the source matrix
digest and canonical matrix byte hash.

No private biosignal, evidence, baseline, or key enters this evaluator.
Hardware status remains `NOT_VERIFIED`; no priority or world-first claim is
made.
