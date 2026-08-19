# AETS adversarial matrix schema v1

Issue #164 freezes the public-only case identity used by the later AETS
adversarial evaluator. This layer describes cases; it does not inject host
faults, execute an engine, minimize a counterexample, or claim experimental
hardware evidence.

The matrix has three independent axes: public scenario, public host outcome,
and resource profile. Every case also carries its canonical `ContextCommand`
sequence, nonzero `ExecutionLimits`, and the public sequence digest validated
against the compiled AETS QSM.

Case identity binds the deterministic 32-byte matrix seed, AETS source, Wasm
module, QSM capsule, QuotientSeal ABI, all three axes, commands, limits, and
public sequence digest. Input case order is erased by lexicographic case-ID
ordering. The matrix digest binds the complete ordered encoding.

The decoder rejects unknown versions, axes, context families, command kinds,
trailing bytes, noncanonical order, duplicate IDs, duplicate axis tuples,
invalid limits, and digest mismatches. `validate_against` independently rebuilds
each `AetsPublicSequence` against the supplied compiled QSM.

No field can carry a private biosignal, evidence value, baseline, or key.
Hardware status remains `NOT_VERIFIED`; no priority or world-first claim is
made.
