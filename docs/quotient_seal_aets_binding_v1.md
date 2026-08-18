# AETS public source and K7 binding v1

Issue #153 freezes the first AETS-to-QuotientSeal boundary. It does not yet
compile or execute a QSM module.

## Public-only source artifact

`AetsPublicSourceArtifact` accepts only existing public contract types:

- `ActionSemantics`
- `PublicContext`
- `ScheduleRandomTape`, documented by AETP as public schedule randomness
- `WireServiceAlias`
- `PolicyHash`

The artifact sorts service bindings and reconstructs `ActionSemantics` through
its validating constructor before encoding. Its fixed binary encoding binds
the deployment alias, epoch, policy, channel schedule, public services,
obligations, and schedule tape. No extension map or arbitrary payload field is
available.

The API does not accept a private history, biosignal sample, baseline, raw
feature, evidence value, evidence-ready timestamp, or key.

## K7 binding

The binding performs all of these checks before returning success:

1. Select exactly the canonical AETS entry from the Noticer QSM registry.
2. Require `P0 Public Quotient Only` and reject P1 evidence.
3. Match service alias, epoch, policy hash, and public source digest.
4. Verify the original CAQT bytes with `CertifiedGeneratedPlan`.
5. Parse the real QuotientForge codegen v2 manifest and match its embedded
   certificate digest to the independently verified CAQT digest.
6. Match the codegen manifest, QSM capsule, and observer registry digests.

Changing any bound artifact therefore requires changing the signed or
otherwise authenticated outer registry in the deployment protocol.

## Non-claims

This boundary is a software contract, not a hardware result. Hardware status
remains `NOT_VERIFIED`. This document makes no priority or world-first claim.
