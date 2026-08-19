# ATv2 public source and K7 binding v1

Issue #169 freezes the public source boundary used to compile the existing ATv2
frame planner into a Quotient-Sealed Module. It reuses `TokenPlan`,
`PublicContext`, `ScheduleRandomTape`, and `ActionEquivalentTraceShaper` rather
than introducing adapter-owned copies.

The source constructor executes the real trace shaper with a public shape-only
issuer. That issuer emits fixed 236-byte marker frames solely to select cover
or action control flow. Marker bytes are discarded. The canonical artifact
retains each `PublicFrameIdentity`, the cover/action kind, public plan fields,
schedule shape, service set, epoch, policy, and public schedule tape. It never
retains an ATv2 envelope, signing key, encryption key, evidence permit, raw
feature, or private timing.

The K7 binding verifies the caller-provided CAQT certificate against its
`ExpectedContract`, decodes the same certificate, checks generated-runtime
input axes, and requires the runtime manifest to name that exact certificate
digest. The manifest binding then checks the existing
`Atv2FramePlanner` registry entry under P0 and rejects P1 evidence or any
service, epoch, policy, source, certificate, or runtime digest mismatch.

This issue does not compile a QSM or claim source-target refinement; those are
separate Issues #170 and #171. Hardware status remains `NOT_VERIFIED`, and no
priority or world-first claim is made.
