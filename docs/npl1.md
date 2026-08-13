# Noticer Provenance Lease v1

## Purpose

NPL1 is the fixed public appraisal result consumed by the production provenance guard. It can be issued only from an opaque `AppraisedProvenance`, never from a raw Assurance Profile or an Android request value.

NPL1 is exactly 256 bytes. It contains no private biosignal measurement, exact acquisition timing/count, personal baseline, sensor serial, BLE address, or stable Android identifier.

## Exact layout

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | profile ID `NPL1` |
| 4 | 1 | version `1` |
| 5 | 3 | flags/reserved, all zero |
| 8 | 8 | lease verifier key ID |
| 16 | 16 | pairwise service alias |
| 32 | 4 | public epoch, big endian |
| 36 | 4 | issued public slot, big endian |
| 40 | 4 | expires public slot, big endian |
| 44 | 8 | ATv2 issuer key ID |
| 52 | 32 | public pipeline measurement hash |
| 84 | 32 | Assurance Profile digest |
| 116 | 32 | policy hash |
| 148 | 32 | collector session public-key hash |
| 180 | 12 | public lease nonce |
| 192 | 64 | Ed25519 signature |

The Ed25519 signature covers:

~~~text
"NOTICER_NPL1_ED25519_V1" || bytes[0..192]
~~~

Unknown profile/version, nonzero reserved bytes, zero required bindings, and inverted lifetime are rejected before signature appraisal.

## Public epoch schedule

Lease issuance is permitted only when:

~~~text
(issued_slot - phase_slot) mod period_slots = 0
~~~

The schedule is public and independent of whether an action is ready. An off-schedule action-correlated renewal attempt is rejected.

The issuer computes expiry as the minimum of:

- `issued_slot + policy.maximum_lifetime_slots`
- the source `AppraisedProvenance` expiry

Therefore a lease cannot extend the appraisal or policy lifetime.

## Validation

The relying party checks, in order:

1. canonical parser constraints
2. lease verifier key ID
3. Ed25519 signature
4. pairwise service alias
5. public epoch
6. ATv2 issuer key ID
7. pipeline hash
8. Assurance Profile digest
9. policy hash
10. collector session public-key hash
11. issued/expires public slot
12. epoch/nonce replay acceptance

Only after all checks does it return sealed `ValidatedProvenanceLease`. Production action-token admission must consume that sealed capability rather than an unvalidated byte array.

## Privacy boundary

The collector-session hash is an ephemeral session-key binding, not a stable device identifier. The service alias is pairwise and epoch-scoped upstream. The lease exposes public slot schedule only, not exact biosignal timing or the private time at which evidence became sufficient.

Lease rejection details remain local. A missing or rejected lease suppresses action authority while the existing AETP cover schedule continues unchanged.
