# QuotientSeal canonical release path v1

## Scope

K8-13g2 defines a deterministic, public-only receipt chain across the five
stages frozen by K8-13g1. It is a specification-level composition artifact. It
does not claim that reference, wasmi, Wasmtime, sensor, BLE, pump, or TEE
execution occurred. Hardware remains `NOT_VERIFIED`.

## Public input

The input has exactly two variants. `ACTION` carries one public action code;
`COVER` carries none. Supplying no action for `ACTION`, or an action for `COVER`,
is non-canonical and rejected. A single fixed seed makes the receipt chain
reproducible and prevents callers from silently introducing another randomness
source.

No raw PPG, private baseline, K1 raw feature, private token material, replay
state, subject identifier, or arbitrary payload is representable by the typed
input.

## Receipt chain

Each stage receipt binds its zero-based index, module ID, input and output
commitments, predecessor receipt, and the source, QSM capsule, and observer
registry digests already frozen in the composition manifest. The output of one
stage is the input of the next. The first predecessor is the all-zero genesis
value; every later predecessor is the prior receipt digest.

Stage output and receipt commitments include the complete K8-13g1 composition
bytes. Consequently, a manifest change, stage reorder, handoff substitution,
receipt replay at another index, or path-kind change produces a different
chain. Verification regenerates the expected artifact from the typed input and
does not trust stored counts or digests.

## Outcome semantics

The `ACTION` specification declares one authorized terminal action and no cover
outcome. The `COVER` specification declares no authorized action and one cover
outcome. These are expected public semantics, not observations of a physical
actuator. Cross-module adversarial execution and three-engine differential
evidence are added by K8-13g4 and K8-13g5.
