# QuotientSeal release stack profile gate v1

## Purpose

K8-13g3 separates P0 Public Quotient Only from P1 Sealed Admission at the
five-stage composition boundary. A requested P1 path is never silently executed
or reported as P0. Missing, stale, mismatched, or unsupported evidence produces
the typed `PROFILE_UNRESOLVED` verdict with no effective profile.

## P0 gate

P0 requires all five manifest entries to declare P0 and forbids an AEPA P1
authorization. The canonical path must pass K8-13g2 full recomputation before
the profile gate evaluates it.

## P1 gate

P1 permits exactly one P1 stage: AEPA. AETS, ATv2, APLOT, and Menfugu remain P0.
The gate accepts only the sealed `AepaProfileAuthorization` already issued by
the K8-13e strict resource gate after fresh `AepaP1Revalidation`. It checks:

- the authorization declares P1;
- its public step equals the requested stack step;
- its witness digest equals AEPA's manifest equivalence evidence;
- its authorization digest is nonzero.

The existing AEPA constructor has private seal fields and enforces the witness
validity window, strict resource equality, manifest relation binding, and fresh
revalidation before this stack layer can receive an authorization. K8-13g3 does
not duplicate or weaken that proof path.

## Artifact semantics

The artifact binds the composition, canonical path, requested and effective
profiles, public step, verdict, unresolved reason, manifest evidence,
authorization digest, and `NOT_VERIFIED` hardware status. Verification reruns
the path verifier and profile decision and rejects altered stored values.

This is software evidence. It is not evidence of a sensor, BLE link, pump, TEE,
or other physical execution environment.
