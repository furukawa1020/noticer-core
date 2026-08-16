# QuotientForge finite-state IR

## Scope

`quotient-forge-ir` is the canonical finite model shared by the later checker, synthesizer,
certificate, code generator, and Noticer adapter. It is not a general Rust or HyperLTL IR.

Every library source forbids unsafe code. The crate uses owned, bounded collections and validates
all state, symbol, transition, output, and dimension references before hashing or execution.

## Components

The compiled model contains:

- `PrivatePlant`: finite private and public input transition system
- `QuotientMonitor`: finite action-semantics projection over canonical plant states
- `ObserverModel`: explicit observable fields and declared collusion edges
- `UtilityAutomaton`: deterministic accepting/rejecting utility monitor
- `FaultAutomaton`: deterministic public adversarial fault monitor
- `ReleaseTransducer`: deterministic public release machine
- `CostVector`: non-scalar bandwidth, latency, state, retry, reconnect, and radio cost

The private plant records only abstract labels and event identifiers. Real PPG/ACC, baseline,
private score, identity, and private ready time do not belong in generated public artifacts.

## Release input boundary

The synthesis target has exactly three input axes:

```rust
pub struct ReleaseInput {
    pub quotient: QuotientStateId,
    pub public_input: u16,
    pub fault: FaultStateId,
}
```

There is no `PrivatePlantState`, raw private event, score, ready slot, identity, or private context
field. The later code generator must preserve this type boundary rather than adding a generic
payload or callback.

## Total transition functions

Plant, quotient, utility, fault, and release transitions are deterministic. Validation rejects a
duplicate input key, an out-of-range reference, and any missing key. For a release transducer the
required table size is:

```text
release states
x quotient states
x public inputs
x fault states
```

The product is checked for overflow and against `max_transitions` before use. Output actions must
refer to a declared quotient class and a public slot before the horizon.

## Action quotient consistency

Every canonical plant state has exactly one `PlantQuotientProjection`. The projection stores the
expected `QuotientLabel`, and validation requires exact equality with the target quotient state's
label. Therefore two plant states can share a quotient state only when their complete authorized
action semantics agree.

`NoAction`, a different service, action, bucket, release-window start, or deadline is a different
label. A mismatch yields `IrError::QuotientMismatch`; it is not repaired silently.

## Canonicalization

Stateful components use deterministic breadth-first renaming from the initial state:

1. sort outgoing transitions by public canonical input/output keys;
2. assign the initial state ID 0;
3. assign a new ID on first reachable use;
4. drop states unreachable from the initial state;
5. sort the resulting states and transitions by canonical IDs.

Observer declarations and set-valued fields use lexical or enum ordering. The canonical encoding
uses fixed little-endian integers, explicit collection/string lengths, fixed field order, and no
platform paths or map iteration order.

A `CompiledModel` requires a canonical plant before quotient projection is assembled. This avoids
renumbering a plant after the projection and accidentally changing its meaning.

## Hash domains

The crate implements the domains fixed by K6-00:

```text
QUOTIENT_FORGE_IR_V1
QUOTIENT_FORGE_PLANT_V1
QUOTIENT_FORGE_QUOTIENT_V1
QUOTIENT_FORGE_OBSERVER_V1
QUOTIENT_FORGE_UTILITY_V1
QUOTIENT_FORGE_FAULT_V1
QUOTIENT_FORGE_TRANSDUCER_V1
```

Each digest hashes `domain || 0x00 || canonical_encoding`. Equal behavior under state renaming and
transition declaration order has the same component digest after canonicalization. Different
domains cannot substitute for one another.

## Limits

Default IR limits match `configs/quotient_forge/contract.toml`: 256 states, 100,000 transitions,
512 public logical slots, and 16 observers. Individual labels are additionally bounded to 256
bytes. Limit, malformed-reference, non-total, quotient-mismatch, and noncanonical failures remain
distinct errors.

## Cost ordering

`CostVector` is retained as a vector. Its default lexicographic comparison considers dummy frames,
worst latency, state count, reconnects, retries, total frames, scaled mean latency, and radio-on
slots. Security, utility, unauthorized action, and deadline correctness are absent from this soft
comparison because they remain hard checker constraints.

## Guarantee boundary

IR validation establishes finite shape, canonical identity, and static dependence boundaries. It
does not establish AETP, utility reachability, fault recovery, certificate validity, or synthesis
optimality. Those claims require the independent product checker and later certificate contract.
