# K7 CEGIS scalability backend

quotient-forge-cegis binds the K7 scalability dimensions to the existing Rust
counterexample-guided synthesis implementation. Candidate enumeration and
blocking are performed by quotient-forge-synth::find_feasible; a realizable
candidate is then submitted again to the independent K6-04 product checker.

The result distinguishes COMPLETED, BOUNDED_UNSAT, SOLVER_UNKNOWN, and
INVALID_CASE. Candidate or time exhaustion therefore cannot become a success.
candidate_count originates from the real search statistics.
solver_call_count is zero because this backend uses the internal deterministic
enumerator rather than an external solver. checker_node_count is a declared
product-size upper bound, not an instrumented visited-node count.

The binding is frozen in configs/quotient_forge/k7_cegis_backend_v1.yaml.
Generated outputs belong under artifacts/ and are not committed. This bounded
synthetic backend does not establish deployment scalability; hardware validation
is NOT_VERIFIED.
