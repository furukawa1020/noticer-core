# AETS public sequence and source reference v1

Issue #159 freezes a public-only lifecycle sequence and source-derived expected
trace for AETS QSM evaluation.

The sequence binds the AETS source, generated module, capsule, QuotientSeal ABI,
resource limits, every `ContextCommand`, and the exact derived `PublicHostTape`.
Only canonical public commands are accepted. Payload tags are fixed to zero;
private histories, evidence values, biosignals, baselines, and keys have no
field in the format.

The evaluator mirrors the frozen engine observable surface: API call/return,
host import, frame, action, public failure, reset, handoff, and post-command
public state. Host-call bounds become `UNRESOLVED`, never success.

The engine identity is deliberately `noticer-aets-source-reference`, and its
configuration says `SOURCE_DERIVED_EXPECTATION_NOT_INTERPRETER`. This artifact
must not be relabeled as `quotient-seal-small-step`. Issue #158 may promote an
independent small-step artifact only after exact trace and termination matching.

Hardware status remains `NOT_VERIFIED`. No priority or world-first claim is
made.
