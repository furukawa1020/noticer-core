# Atypicality Token v2 protocol

## Protocol role

ATv2 is a fixed-size, signed, encrypted, one-shot action-token construction for
the proposed AETP security notion. It is intentionally split into admission,
public planning, schedule shaping, frame issuance, and verification. A caller
cannot hand a biosignal history or an `EvidencePermit` directly to the issuer.

## High-to-low flow

```text
private biosignal history
        |
        v
EvidenceEngine -> EvidencePermit<G>
        |
        v  consume exactly once
noticer-claim::admit
        |  validate action, policy, cutoff, expiry, claim ceiling
        |  erase evidence-ready slot, evidence expiry, epoch, provenance
        v
AdmittedAction -> TokenPlan -> trace shaper -> TokenIssuer -> 236-byte ATv2
```

The low side stores only public `ActionObligation` and `ClaimBound`. The old
`ActionClaim` and claim-to-release projection path has been removed.

## Canonical 236-byte envelope

| Region | Bytes | Contents |
|---|---:|---|
| Outer header | 60 | magic, version, kind, pairwise alias prefix, key ID, public epoch/bucket/sequence, XChaCha nonce |
| Encrypted inner body | 96 | token ID, action, claim bound, validity window, max uses, policy hash, semantics tag, reserved zero bytes |
| Encrypted signature | 64 | Ed25519 signature over outer header plus inner body |
| AEAD tag | 16 | XChaCha20-Poly1305 authentication tag |
| Total | **236** | fixed for both cover and action frames |

Reserved bytes must be zero. Parsing rejects unknown frame kinds, unknown
actions, malformed claim levels, non-canonical cover bodies, and action bodies
that do not have `max_uses = 1`. The size is below a 244-byte BLE ATT payload.

## Cryptographic construction

The implementation uses standard components rather than claiming them as
novel: HKDF-SHA256, HMAC-SHA256, Ed25519, XChaCha20-Poly1305, and SHA-256.

Keys are derived from a root secret independently for each service and epoch,
with distinct domain strings for signing, AEAD, nonce derivation, and pairwise
service aliasing. The deterministic nonce binds service, epoch, public bucket,
and monotonic sequence. The issuer keeps an atomic nonce/sequence-use set and
rejects reuse. Schedule randomness is a separate type and cannot derive keys.

The outer header is AEAD associated data. The Ed25519 signature binds the outer
header and plaintext body before encryption. Cover tokens carry a canonical
no-op body but remain indistinguishable by length and cadence.

## Claim bounds

`ClaimBound` is the componentwise product of:

- semantic level: none, change cue, state label, diagnosis;
- audience: internal, user, paired actuator, application, public;
- impact: no action, ambient cue, direct prompt, high impact.

Admission requires the selected bound to dominate the action's minimum and to
remain below the local policy ceiling. Verification repeats the minimum-bound
check and requires the policy hash and canonical semantics tag to be allowlisted.

## Versioning

The magic is `NAT2` and the version byte is `2`. Incompatible layouts require a
new version; silent reinterpretation is forbidden. Epoch rotation derives new
keys, aliases, and key IDs. Verifiers reject unknown epochs and mismatched
service bindings.
