# Clock recovery ceremony

Recovery requires a domain-separated Ed25519 permit binding operator domain,
epoch, generation, both observed slots, a nondecreasing target, expiry, and
nonce. Verification uses the existing Noticer crypto boundary. The permit is
consumed before either state update; a partial failure burns it and requires a
new permit. No mismatch is repaired without explicit authorization.

The authenticated record advances before the anchor. A failure between them
remains fail closed on normal startup. The sample ledger and anchor are test
doubles only. Durable permit storage, operator identity proof, hardware roots,
and field recovery procedures remain NOT_VERIFIED.
