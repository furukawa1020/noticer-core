# Action-Quotient Release Synthesis

Status: candidate new synthesis problem and K6 bounded contract  
Contract version: 1

## Purpose

Action-Quotient Release Synthesis (AQRS) is the finite synthesis problem used by
QuotientForge. It asks for a public release transducer over authorized action semantics,
public inputs, and public faults. The transducer must preserve declared utility while making
complete observer traces equal for private histories in the same action-equivalence class.

AQRS does not replace general HyperLTL synthesis, information-flow control, program repair,
or traffic shaping. K6 implements a domain-specific, bounded fragment for release systems.

## Existing Noticer boundary

K6 reuses the existing Noticer declassification boundary instead of defining a parallel one.
An `ActionObligation` contains only:

- service binding
- registered action code
- public bucket
- admission cutoff
- release-window start
- release deadline
- maximum use count
- policy hash

An `ActionSemantics` value is the canonical ordered set of these obligations. Exact permit
readiness, score, margin, confidence, baseline, identity, physiological feature, raw PPG/ACC,
private failure reason, and private context are not action semantics.

`PublicContext` supplies the public channel schedule, epoch, service set, and public start slot.
K4 loss and delivery choices are public fault inputs. K6 must adapt these existing types; it must
not make a second action-token or transport authority.

## Finite model

For a declared horizon `T`, a compiled model is the tuple:

```text
M = (P, Q, C, F, O, U, K, T)
```

where:

- `P` is a finite private plant;
- `Q` is a finite quotient monitor;
- `C` is a finite public-input alphabet and schedule;
- `F` is a finite public fault automaton;
- `O` is a finite set of observer projections;
- `U` is a finite utility automaton;
- `K` is a vector-valued cost model;
- `T` is the public logical-slot horizon.

Private wall-clock executions are normalized to public logical slots before comparison. Network
delay, drop, duplicate, reorder, disconnect, and reconnect behavior belongs to `F`. K6 does not
solve general asynchronous hyperproperty verification.

Every finite collection is bounded before allocation. The default ceilings are fixed in
`configs/quotient_forge/contract.toml`. A specification may select smaller limits but cannot
raise them without an explicit compiler configuration and artifact record.

## Action quotient

Let `H_T` be a private plant history through horizon `T`, and let `C_T` be a public-input trace.
The quotient projection is:

```text
q_T : H_T x C_T -> ActionSemantics_T
```

The implementation is a `QuotientMonitor`, not an unrestricted callback into private state.
For fixed public context, define:

```text
h0 equivalent_q h1
iff
q_T(h0, C_T) = q_T(h1, C_T)
and the declared obligations are jointly feasible on C_T.
```

The relation deliberately excludes the following pairs:

- action versus no action
- different action codes
- different services
- different public buckets
- different public deadlines or release windows
- different policy-authorized use counts

Private threshold margin, private evidence trajectory, private identity, and private ready time
before the same admission cutoff remain erased. A quotient reduction that merges different
action semantics is invalid.

## Release transducer

The synthesis target is a deterministic finite transducer:

```text
R : ReleaseState x QuotientState x PublicInput x FaultState
    -> ReleaseState x PublicOutput
```

Its input type must not contain a private plant state, raw private event, score, ready slot,
identity, or private context. Public outputs may include cover/action frames, public release slots,
normalized public failures, connection commands, and public retry commands declared by the model.

The transition function must be total over the declared finite input alphabet. Missing entries,
unknown output symbols, mutable runtime transition tables, and hidden default branches are invalid.

## Observer model

Each observer `o` has an explicit projection:

```text
pi_o : FullPublicTrace -> ObservableTrace_o
```

The bounded fragment supports passive network, authorized service, declared service collusion,
longitudinal public observation, public audit, public failure, and cost-side-channel views. A view
not listed in the specification is not silently covered by the certificate.

An observation can include bytes, size, timing, count, silence, connection state, public failure,
action placement, service aliases, retry, reconnect, and declared cost events. Ciphertext alone is
not treated as the complete trace.

## AQRS security property

For every two reachable private histories, shared public trace, shared public fault trace, and
declared observer, bounded action-quotient noninterference (AQNI) requires:

```text
q_T(h0, C_T) = q_T(h1, C_T)
and C_T is shared
and F_T is shared

implies

pi_o(R(q_T(h0, C_T), C_T, F_T))
=
pi_o(R(q_T(h1, C_T), C_T, F_T)).
```

The checker compares complete projected traces point by point. Statistical attack evaluation is
supplementary evidence; chance-level attack performance cannot replace a failed equality check.

## Utility property

Security cannot be satisfied by suppressing all actions. For every reachable single execution
and every declared recoverable public fault trace, `U` requires:

- each authorized obligation is delivered exactly once;
- delivery occurs inside its public release window and no later than its deadline;
- no unauthorized action is emitted;
- no duplicate action is emitted;
- recoverable declared faults preserve the obligation;
- unrecoverable public failure follows the declared normalized behavior.

Security, action utility, deadline, zero unauthorized actions, and bounded-fault utility are hard
constraints. They are never MaxSMT soft clauses.

## Cost and optimization

Feasibility is checked before optimization. The default cost vector records dummy frames, total
frames, worst latency, scaled mean latency, state count, reconnects, retries, and radio-on slots.
Default comparison is lexicographic:

```text
1. security violations = 0
2. utility violations = 0
3. unauthorized actions = 0
4. deadline misses = 0
5. dummy frames
6. worst latency
7. state count
8. reconnects
```

Only items 5 through 8 are optimization choices after the hard constraints pass. A weighted mode
must be explicit and cannot trade security or utility for cost.

## Bounded synthesis contract

State bounds are explored from one through the declared maximum. A candidate returned by a solver
is untrusted until the independent product checker accepts it. Counterexample-guided synthesis
adds a constraint only after reconstructing a concrete security or utility witness.

State numbering uses initial-state zero, first-use ordering, unreachable-state removal, canonical
transition ordering, and canonical output symbols. Equal-cost solutions use a deterministic
canonical tie-breaker.

## Result taxonomy

The following states are distinct:

| Result | Meaning |
|---|---|
| `CERTIFICATE_VALID` | Independent checker accepted the model and transducer |
| `UNSAT_AT_BOUND` | A completed backend found no candidate at one explicit state bound |
| `UNREALIZABLE_WITHIN_BOUNDS` | Every declared bound completed negatively without timeout |
| `TIMEOUT` | Search or checking exceeded its recorded time budget |
| `RESOURCE_LIMIT` | A declared source, state, transition, memory, or iteration limit was reached |
| `SOLVER_UNAVAILABLE` | Requested external backend was not installed or executable |
| `INVALID_SPEC` | Parse, type, consistency, or resource validation failed |
| `INVALID_CANDIDATE` | Product checking found a counterexample or malformed transducer |
| `INVALID_CERTIFICATE` | Independent certificate validation failed |
| `MALFORMED_SOLVER_OUTPUT` | Backend output could not be parsed canonically |

`SAT` from a solver is not a success result. `UNSAT_AT_BOUND` is not a statement about a larger
bound, a longer horizon, another observer model, or an unbounded implementation. Timeout and
resource exhaustion are inconclusive and must never be relabeled as unrealizability.

## Canonical objects

AST, typed AST, IR, plant, quotient, observer, utility, fault, transducer, certificate, and checker
contract each have a distinct versioned hash domain. The exact ASCII domains are fixed in the
machine-readable contract. Encodings must sort maps and sets, reject trailing data, include a
version, and avoid platform-dependent integer or path representations.

Given the same specification, compiler version, backend/version, seed, and optimization config,
QuotientForge must emit the same canonical transducer and certificate. Reproducibility does not
imply that different solver versions discover a candidate in the same amount of time.

## Certificate soundness target

The K6 theorem target is deliberately bounded:

> If the independent checker accepts certificate `C` for compiled finite model `M`, then the
> certified transducer satisfies bounded AQNI and the declared utility contract for every product
> state reachable within `M`'s recorded horizon and limits.

This target depends on correct parsing, finite abstraction, observer projection, quotient monitor,
and checker implementation. It is not a proof of an unmodeled deployment or physical channel.

## Completeness non-claim

QuotientForge does not guarantee complete general hyperproperty synthesis, unbounded-system
completeness, arbitrary Rust repair, a globally minimal solution after timeout, probabilistic or
differential privacy, physical side-channel safety, raw PPG authenticity, or feasibility outside
the recorded bounds. Longitudinal composition requires identical public handoff state and no
private state carried across certified components; otherwise a new model and certificate are
required.
