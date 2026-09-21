# State generation commitment

StateSnapshot canonically binds the authenticated clock slot, external
monotonic-anchor slot, and durable recovery-ledger sequence and head tag to
one epoch and state generation. A distinct authentication key produces the
commitment stored by GenerationAnchor.

Startup accepts local state only when its complete commitment matches the
external anchor. Updates require a verified previous commitment, monotonic
local fields, compare-and-advance of the external revision, and no fallback
when the anchor is unavailable. This detects individual rollback and a
coordinated rollback of all local files while the external anchor remains
current.

The included anchor is deterministic test infrastructure. Real hardware
generation anchors, secure provisioning, atomic power-loss behavior, and
field recovery remain NOT_VERIFIED.
