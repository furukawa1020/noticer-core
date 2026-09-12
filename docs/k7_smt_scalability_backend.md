# K7 SMT scalability backend

quotient-forge-smt is the production binding from a K7 case to the existing SMT
adapter. It loads the pinned solver matrix, selects only cvc5 or Z3, derives the
platform-specific executable and fixed argv, and compares the executable SHA-256
with the digest bound by the run lock before starting a process. It also checks
that the reported version contains the version pinned by the matrix.

A missing executable is NOT_RUN. A digest, version, platform, model, or checker
mismatch is not a successful measurement. SAT models are decoded by the solver
adapter and checked independently there, then checked once more at this worker
boundary. UNSAT remains bounded by the declared state and trace limits.

Tests use only missing and intentionally invalid local files; they are not
accepted as measured solver artifacts. Real solver execution requires a pinned
installation and digest supplied by the replication run. Generated results are
not committed, and hardware validation remains NOT_VERIFIED.
