# K7 reference scalability backend

`quotient-forge-reference` is the production reference binding for the K7
scalability protocol. It deterministically materializes all seven declared
dimensions into a finite `SynthesisProblem` and one explicit `ReleaseMachine`.

The executable does not treat construction as proof. Every candidate is lowered
to the K6-04 product-check normal form and passed to the independent
`quotient-forge-check` security oracle. Only that verdict enters the generated
backend result. Invalid dimensions and checker resource exhaustion cannot become
a verified result.

The `checker_node_count` field is a deterministic upper-bound accounting unit
derived from the materialized product dimensions. It is not presented as an
instrumented count of visited checker nodes. The reference backend makes zero
solver calls.

The binding contract is
`configs/quotient_forge/k7_reference_backend_v1.yaml`; generated JSON belongs
under `artifacts/` and is not committed. The implementation is a synthetic
bounded scalability model, not evidence of deployment performance. Hardware
validation remains `NOT_VERIFIED`.
