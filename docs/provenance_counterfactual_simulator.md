# AEPA Counterfactual Provenance Simulator

## Purpose

`noticer-provenance-sim` is a deterministic K5-10 evaluation harness. It asks
whether two distinct private acquisition histories produce pointwise-identical
public provenance and release traces when their allowed action semantics and
public provenance claims are equal.

The six counterfactual families are P0 early/slow evidence, P1 high/near
threshold evidence, P2 raw morphology, P3 exact sample count, P4 exact
acquisition timing, and P5 private context path. Their values remain in memory
inside non-serializable, redacted types.

## Coupling and comparison order

Each left/right execution receives the same verifier challenge, reference
attester key, verifier-only public claim digest, lease signing key, lease nonce,
ATv2 root, public action plan, schedule tape, transport key, and loss tape. Each
side has independent one-shot challenge and replay stores, so replay rejection
is not bypassed to obtain equality.

For every family, the default run evaluates three services at public epochs 1,
4, 16, and 64. It compares:

1. Exact NEPP-v1 bytes and the appraised public provenance digest.
2. Exact 256-byte NPL1 lease bytes.
3. Every fixed-size ATv2 frame in the complete AETP network trace.
4. Every scheduled K4 fragment, delivery bit, tick, and observable wire byte.

The production token path is used. Each action therefore requires a genuine K1
permit consumed by `EvidenceBridge`, a separately verified NPL1 capability, and
the K5-09 production lease guard.

## Artifacts

Run:

```text
cargo run -p noticer-provenance-sim --release -- --output artifacts/k5/provenance_counterfactual
```

The command writes `summary.json` and `witnesses.csv`. Each row contains only a
family ID, public epoch, service count, equality booleans, and aggregate SHA-256
witnesses. Raw PPG/ACC, morphology, exact sample count, acquisition timestamps,
private context values, baselines, keys, challenges, and lease nonces are never
written.

## Non-claims

This simulator establishes deterministic congruence for the modeled software
pipeline and coupled public randomness. It is not evidence of live Polar
collection, Android hardware attestation, physical sample origin, statistical
privacy against every attacker, or a general proof of AEPA. Those claims remain
outside K5-10.
