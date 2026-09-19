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
Real BLE, hardware-backed attestation, physical pump control, durable replay
storage, and field safety evidence remain NOT_VERIFIED.

The public-loss simulation API preserves all twenty logical send slots without
private-dependent retries. Its loss mask and local outcome are not release data.

For restart-safe software operation, use new_with_durable_replay with a
trusted per-epoch ledger path. Ledger open failure aborts startup; the
constructor never falls back to InMemoryReplayStore. The original new
constructor remains an explicit caller-supplied verifier path for tests.
