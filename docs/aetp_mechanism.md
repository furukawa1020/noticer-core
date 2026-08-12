# Action-Equivalent Trace Shaper (AETS)

## Admission cutoff and semantics erasure

Private permit readiness is consumed before a public cutoff. A candidate ready after the cutoff
is rejected. Successful admission copies only the action obligation; private ready time and all
evidence values disappear. Private-side rejection continues as ordinary cover traffic and does
not emit a reason.

## State machine

```text
PrivateCandidate -> AdmissionGate -> AdmittedAction -> ActionSemantics
                                                        |
PublicContext + RandomTape ------------------------------+
                                                        v
                                               FixedRateShaper
                                                        |
                      NetworkTrace / ServiceTrace / CollusionTrace
```

Persistent Low Side state is limited to public epoch, bucket, slot, service alias, cadence,
admitted semantics, scheduler randomness, and public network state.

## Fixed-rate, fixed-size channel

Each admitted service receives one frame in every public slot. Action absence produces cover,
never silence. K2 plaintexts are 88 bytes and XChaCha20-Poly1305 ciphertexts are 104 bytes.
Action, cover, and normalized public failure share the same wire length.

The nonce and key are domain-separated by public epoch, service alias, public slot, and the
independent random tape. The mechanism uses standard AEAD and does not claim cryptographic
novelty.

## Semantics-only placement

Action placement is sampled inside the public release window using only action semantics,
service domain, epoch, obligation index, and random tape. Private permit time, evidence magnitude,
identity, and context are unavailable to the shaper.

Each obligation is delivered exactly once, within its deadline, to its bound service. Cover is
never decoded as action. K2 primary configurations admit only jointly feasible obligations and
therefore target zero deadline misses.

## Pairwise service isolation

Aliases use `H("NOTICER_AETP_SERVICE_V1" || service || epoch)`. Schedule randomness uses a
separate service alias, bucket, and obligation domain. Aliases are simulator observables, not
authentication credentials. Shared service randomness is retained only as a deliberately leaky
ablation.

## Failure normalization

Evidence insufficiency, baseline unavailability, private context failure, late permit, and score
computation failure do not cross the boundary. Public protocol or endpoint failures may be shown
only when determined by public state, while cadence continues.

## Utility and trace invariants

- one action per obligation and no duplicates
- action slot inside release window and deadline
- wrong service cannot execute the action
- every frame has identical ciphertext length
- every service has constant cadence
- no evidence-dependent silence, reconnect, retry, or failure timing
- no private field in shaper state, frame, hash, or sanitized audit
