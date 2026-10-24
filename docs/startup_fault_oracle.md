# Startup Fault Injection Oracle

The oracle injects a deterministic crash before each recovery ceremony phase: begin, security authorization, admission, recovery witness, and completion. It restores the authenticated checkpoint and requires convergence to `Complete` without any pre-completion release. The seeded order and canonical artifact are byte-replayable.
