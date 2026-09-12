# K7 QBF scalability backend

quotient-forge-qbf binds a K7 case to the pinned CAQE backend. Before execution,
QbfSolverAdapter verifies the manifest, install receipt, source identity,
platform, executable path, and current binary SHA-256. A missing receipt is
NOT_RUN and a failed installation verification is INVALID_CASE.

The worker compiles the bounded safety game to QDIMACS, invokes CAQE without a
shell under bounded process limits, preserves SAT, bounded UNSAT, unknown,
timeout, and malformed output separately, and decodes a SAT assignment.
check_qbf_candidate then submits the decoded release machine to the independent
product checker. Only an accepted checker decision becomes COMPLETED.

Tests do not substitute a helper process for CAQE. The checked-in test covers the
unavailable fail-closed path; optional CI or a replication environment with a
verified receipt exercises the real solver. Generated QDIMACS and JSON outputs
are not committed. Hardware validation remains NOT_VERIFIED.
