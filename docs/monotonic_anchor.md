# External monotonic anchor boundary

An authenticated record proves integrity, not freshness. MonotonicAnchor binds
freshness to epoch and state generation. Startup reads the anchor first and
accepts only an exactly matching authenticated record. It never repairs either
side or falls back when the anchor is unavailable.

Updates durably write the record before advancing the anchor. Anchor update
failure poisons the instance; either crash window becomes a startup mismatch.
Recovery is operator-controlled. The included anchor is only a deterministic
test double. Hardware anchors and power-loss behavior remain NOT_VERIFIED.
