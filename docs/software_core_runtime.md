# Software core runtime

The proposed software-only integration API in noticer-k4-demo library connects
an already shaped ATv2 public frame to APLOT fragmentation/reassembly,
cryptographic verification, sealed authorization, and a virtual Menfugu pump.
It reuses existing components; it does not add a privacy definition or token verifier.

Public frame identity must match the parsed envelope header. Slot rollback,
invalid framing, and public binding mismatch fail closed. Cover, rejection,
replay, and transport duplication never start the virtual pump. Public timer
advancement is independent from frame arrival.

FrameReport and VirtualPump are local diagnostics only. Their event sequence
must not be transmitted or treated as an AETP-approved release trace.
Real BLE, hardware-backed attestation, hardware secure clock or monotonic
counter, physical pump control, and field safety evidence remain NOT_VERIFIED.

The public-loss simulation API preserves all twenty logical send slots without
private-dependent retries. Its loss mask and local outcome are not release data.

For restart-safe software operation, use new_with_durable_replay with a
trusted per-epoch ledger path. Ledger open failure aborts startup; the
constructor never falls back to InMemoryReplayStore. The original new
constructor remains an explicit caller-supplied verifier path for tests.

Production-like restart tests should instead use new_with_durable_state with
separate replay-ledger and public-clock paths plus a trusted initial public
slot. Public binding is checked first, then the slot watermark is durably
advanced before cryptographic verification or action execution. A rejected
token therefore cannot roll the stored watermark back. Clock corruption,
epoch mismatch, lock contention, rollback, or write ambiguity aborts startup
or ingestion without a wall-clock or in-memory fallback. The caller must not
derive trusted_initial_slot or NetworkFrame identity from unauthenticated
packet bytes. new_with_durable_replay remains a replay-only integration path;
it does not provide restart-safe public-clock rollback protection.

For authenticated restart state, use new_with_authenticated_durable_state.
It requires an authentication key and explicit state generation, verifies the
clock record before constructing the runtime, and persists the watermark
before token verification or action execution. Authentication, epoch,
generation, rollback, lock, or I/O failure never falls back to the plaintext
or in-memory clock. The key and generation must come from trusted provisioning.
The older new_with_durable_state path remains an explicit plaintext legacy
boundary and does not authenticate filesystem state.

The strongest software integration path is new_with_anchored_durable_state.
It requires an external MonotonicAnchor and refuses startup unless its slot
exactly matches the authenticated record. Frame processing persists the record
and advances the anchor before token verification or action execution. Any
anchor failure is normalized to DurableClock and never falls back to a weaker
backend. The repository test anchor is not a production trust anchor.
Hardware provisioning and recovery remain NOT_VERIFIED.
