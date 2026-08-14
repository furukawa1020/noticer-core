# Production ATv2 Provenance Lease Guard

## Status

This document defines the K5-09 production admission boundary. It composes the
existing K1 evidence authority with the K5 NPL1 provenance capability. It does
not claim that provenance proves the biological origin of every PPG sample.

## Authority conjunction

An action-capable production ATv2 frame requires both:

1. An unconsumed typed `EvidencePermit` held inside `EvidenceBridge`.
2. An unconsumed `ValidatedProvenanceLease` produced by NPL1 verification.

`EvidenceBridge::take_production_admission` consumes both inputs and returns a
sealed `ProductionAdmission`. The admission binds the K1 action and policy to
the NPL1 policy, validity interval, appraised assurance profile, service alias,
epoch, pipeline measurement, and ATv2 issuer key.

The default production mode is `ProductionRequired`. The low-level action API
exists only behind the `lab-unattested` Cargo feature. Every binary that enables
that feature records `LAB_UNATTESTED` in its artifact manifest.

## Fail-closed trace behavior

`ProductionTokenIssuer` implements the K4 `FrameIssuer` contract. A missing,
expired, already consumed, downgraded, or mismatched admission does not remove
a scheduled frame and does not emit a distinguishable error frame. The exact
scheduled identity is instead used to issue a canonical 236-byte cover ATv2.

The guard checks bindings in this order before arming:

1. Pairwise service alias.
2. Public epoch.
3. ATv2 issuer key ID.
4. Pipeline measurement.
5. K1, NPL1, and production policy equality.
6. Assurance-profile product-order minimum.

At the selected release slot it checks the K1 and NPL1 validity intervals,
action code, one-use policy, bucket, and release window. The admission is taken
before issuance, so concurrent or repeated action attempts cannot reuse it.

## Tests and non-claims

The integration tests cover one valid action, second-use cover fallback, no
lease, expiry, wrong ATv2 key, assurance downgrade, complete cover scheduling,
BLE fragmentation/reassembly, verifier authorization, and one Menfugu pump
start. NPL1 signature and source-replay rejection remain tested in the NPL1
crate.

This is a software-enforced relying-party boundary. Real Polar collection,
Android certificate-chain validation, StrongBox-backed key custody, hardware
boot appraisal, and physical sample-origin proof remain `NOT_VERIFIED` until
their dedicated K5 issues are completed.
