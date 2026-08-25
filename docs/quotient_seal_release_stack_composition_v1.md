# QuotientSeal release stack composition v1

## Status

This document freezes the public composition contract for K8-13g1. It does not
claim physical-device, sensor, BLE, pump, or TEE validation. Those claims remain
`NOT_VERIFIED`.

## Canonical stack

The only accepted order is:

1. `AETS`
2. `ATV2_FRAME_PLANNER`
3. `APLOT`
4. `AEPA`
5. `MENFUGU_EXECUTION_PLANNER`

Each adjacent pair forms one directed handoff. A missing, duplicated, reordered,
or substituted stage is rejected. The composition reuses
`NoticerQsmManifest`; it does not define a second module registry.

## Bound public material

The fixed-length `NQSMCMP1` envelope binds the canonical manifest bytes, stage
order, handoff graph, private-field registry digest, and hardware status. The
manifest already binds each module's deployment profile, service alias, epoch,
policy hash, source, certificate, generated runtime, QSM capsule, observer
registry, and any permitted P1 resource evidence.

Changing any bound field changes the composition digest. Decoding rejects
unknown versions, nonzero reserved bits, altered topology, altered privacy
registry binding, unsupported hardware status, and trailing bytes.

## Privacy boundary

The public envelope never serializes raw PPG, a private baseline, K1 raw
features, private token material, or replay state. It carries only a digest of
the frozen forbidden-field registry. Exact-length decoding prevents an attacker
or integration layer from appending a private payload to an otherwise valid
composition.

This boundary is a software contract, not evidence that private material cannot
leak through an unmodeled operating system, radio, device, or TEE channel.

## Deferred work

K8-13g2 adds executable handoff receipts. K8-13g3 decides P0/P1 admission.
K8-13g4 through K8-13g6 add adversarial sequences, the aggregate differential
oracle, and fully reproducible bundles. This contract alone is not an
end-to-end security result.
