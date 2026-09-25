# Optimal Randomized Transducer Code Generation

K9-QL-10 compiles a certificate-bound exact rational policy into a finite public-state release machine.

The generated runtime API accepts only action quotient, public input, and public fault input. Private history is deliberately absent. Exact cumulative tables use rejection sampling with no modulo bias, a configured denominator bound, bounded retries, fail-closed behavior, injected production randomness, and observable random-draw accounting.

Code generation rejects a model/certificate digest mismatch and any nonzero certified optimality gap. The artifact bundle contains the runtime source layout, certificate, exact-distribution metadata, test-vector schema, and manifest. Generated artifacts are returned in memory and are not committed.

Random-bit reporting separates expected draws, expected bits, configured worst-case draws, and rejection probability. Random use depends on the public policy table and public random source, not private history.
