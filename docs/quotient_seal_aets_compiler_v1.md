# AETS P0 QSM compiler v1

Issue #154 adds a deterministic compiler from the validated public AETS source
artifact to a QuotientSeal P0 WebAssembly module and structurally validated
QSM capsule.

The compiler requires an unforgeable `AetsK7Binding` produced by the existing
CAQT verifier and the real QuotientForge codegen manifest. It accepts an exact
public mapping from every AETS `ServiceBinding` to a nonzero QSM service code.
Missing, duplicate, colliding, and extra mappings fail closed.

For each valid public tick, the module emits one fixed-schedule frame. Public
faults are reported only after that frame. Actions are placed with the same
public `ScheduleRandomTape` algorithm used by AETS and only inside the bound
release window. Unknown services and slots outside the frozen schedule report
public failures. Reset, handoff, and public status use the frozen P0 exports.

The generated module is checked by the QuotientSeal ABI validator, lowered to
canonical target IR, bound into a relation certificate, packed into a QSM
capsule, and decoded again before release. Compilation is byte deterministic.

This step does not claim semantic backend acceptance. Robust and resource
certificate sections remain explicitly `NOT_VERIFIED` pending Issue #155,
which performs source-target refinement and three-implementation differential
evaluation. No hardware or priority claim is made.
