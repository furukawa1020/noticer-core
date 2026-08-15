# QuotientForge threat model

Status: K6 bounded software threat model  
Contract version: 1

## Security objective

QuotientForge constructs and checks finite release transducers. For histories with the same
authorized action semantics, shared public inputs, and shared public faults, every declared
observer must receive the same complete observable trace through the recorded horizon. At the
same time, authorized actions, deadlines, exactly-once delivery, and bounded-fault utility must
hold.

The protected fact is excess information inside an action-equivalence class. Action presence,
action code, service, public bucket, public deadline, and other declared quotient fields are
intentional declassification and are not hidden from an observer allowed to see them.

## Components and trust boundary

| Component | Role | Trusted for accepted certificate |
|---|---|---|
| DSL parser and semantic checker | Convert bounded source into typed input | Yes |
| Quotient compiler | Build action-equivalence monitor | Yes |
| IR canonicalizer | Produce deterministic finite model and hashes | Yes |
| Product checker | Recompute security and utility by reachability | Yes |
| Certificate parser/checker | Reject mutation, mismatch, and unsupported versions | Yes |
| Generated release runtime | Execute the certified transition table | Yes |
| Noticer production adapter | Supply only quotient/public/fault inputs | Yes |
| CEGIS/SMT/MaxSMT/exhaustive search | Propose candidate transducers | No |
| z3 or cvc5 process | Propose SAT/UNSAT results for an encoding | No for acceptance |
| CLI, Studio, graphs, benchmark UI | Present results | No |
| Statistical attack models | Supplement structural evidence | No |

The independent checker is intentionally smaller than the synthesizer. A candidate does not gain
authority from solver success, a Studio badge, or an attack score. Production integration accepts
only a checker-validated, version-compatible machine.

## Protected assets

- raw private histories, signals, features, baseline values, scores, margins, ready times, and
  identities
- the integrity of the action quotient and its declassification boundary
- complete observer-trace equality inside each quotient class
- authorized-action utility, deadlines, and exactly-once behavior
- absence of unauthorized and duplicate action
- certificate/model/transducer binding and canonical hashes
- deterministic, bounded generated runtime behavior
- honest distinction among valid, invalid, bounded-negative, and inconclusive outcomes

## Adversaries

### Passive network observer

Observes packet bytes, sizes, slots, count, silence, connection state, public delivery/drop,
retry, reconnect, and public failure according to its projection.

### Authorized service

Observes its service frames, action placement, normalized failure, and declared execution view.
Endpoint compromise beyond the declared projection is outside this model.

### Multi-service collusion

Combines the explicitly declared service views. Pairwise aliases alone do not protect a relation
that the collusion projection exposes.

### Longitudinal observer

Correlates traces over multiple buckets or certified components. Composition is covered only when
public handoff state is identical and private state is not carried into the next component.

### Failure and cost observer

Observes public fault response and declared cost events such as frame count, retries, reconnects,
radio slots, or latency. A cost field omitted from the observer model is an explicit modeling gap.

### Malicious specification author

Attempts private-to-public flow, action suppression, impossible utility, private-dependent fault
rules, huge integer/resource requests, import cycles, ambiguous observer declarations, or an
action quotient that merges different authorized semantics.

### Malformed artifact adversary

Mutates, truncates, reorders, extends, or version-confuses a specification, IR, candidate,
certificate, generated manifest, or solver response.

### Compromised or incorrect solver

Returns a malformed candidate, false SAT, false UNSAT, noncanonical equal-cost solution, or stalls.
Solver output cannot bypass product checking. A false UNSAT can affect completeness and must be
reported with backend/version; it cannot create a valid certificate.

### Resource-exhaustion adversary

Uses large source, state spaces, transitions, observers, horizons, integers, CEGIS iterations,
or solver output to consume CPU, memory, or disk.

## Trust assumptions

- The finite plant abstraction includes every behavior claimed by the certificate.
- The quotient monitor faithfully represents authorized `ActionSemantics`.
- Public inputs and public fault traces are coupled between compared worlds.
- Each observer projection includes every release feature covered by the claim.
- The generated runtime implements the certified table without mutable replacement.
- Existing Noticer cryptographic, verifier, transport, and Menfugu boundaries satisfy their own
  documented contracts.
- Build tools and the deployed binary correspond to the recorded source and certificate.

These assumptions are auditable obligations, not facts established by synthesis.

## Attacker knowledge

The attacker may know the specification, compiler, generated code, certificate, public context,
observer projection, action semantics, cost model, solver backend, and all public artifacts. The
attacker may choose two private histories within one declared quotient class and may choose any
public fault trace accepted by the fault automaton.

No security argument depends on source secrecy, hidden state numbering, undisclosed padding
policy, or an unknown compiler seed.

## Public release surface

| Surface | Potential observation | Required control |
|---|---|---|
| Release frame | bytes, kind, size, service, slot | Declared projection and trace equality |
| Silence/cadence | missing or additional frame | Total public schedule or certified alternative |
| Connection | connect/disconnect/reconnect timing | Public-only transition input |
| Retry | count and slot | Public fault policy only |
| Failure | code, timing, persistence | Normalized public semantics |
| Service view | frame/action placement | Observer-specific equality |
| Collusion view | cross-service relation | Explicit combined projection |
| Longitudinal state | handoff and repeated buckets | Public handoff, no private carryover |
| Cost artifact | bandwidth, latency, state count | Bounded allowlist; no private measurements |
| Certificate | hashes, machine, witness, cost | Canonical encoding and strict parser |
| Generated code | tables and manifest | No private input API; immutable certified table |

## Security goals

- Reject implicit flow from `Private` to `Quotient`, `Public`, or `ObserverOnly`.
- Permit declassification only through the explicit quotient monitor.
- Keep release state and output dependent only on quotient, public, and fault state.
- Prove pointwise projected trace equality for every reachable product state in bounds.
- Preserve authorized exactly-once actions and deadlines under declared recoverable faults.
- Reject unauthorized, duplicate, late, and undeclared output.
- Produce a minimal counterexample when checking finds a violation.
- Bind certificate, model, transducer, utility, observer, fault, cost, and checker contract.
- Reject malformed, trailing, reordered, mismatched, or unsupported certificate input.
- Fail closed under invalid specification, candidate, certificate, and generated manifest.
- Apply deterministic resource limits before unbounded allocation or process output collection.
- Report timeout, missing solver, and resource exhaustion as inconclusive.

## Non-goals

- General HyperLTL or arbitrary temporal-logic synthesis
- Infinite-state or unbounded-time completeness
- Arbitrary Rust program repair
- Differential privacy or probabilistic transducer synthesis
- Protection against observers absent from the declared model
- Endpoint compromise, operating-system compromise, or compiler toolchain compromise
- Cryptographic primitive novelty or key-management proof
- Raw biosignal authenticity, human presence, liveness, or physical spoof resistance
- K1 baseline poisoning or private evidence correctness
- Android attestation, TEE, BLE hardware, sensor firmware, or Menfugu hardware validation
- Hiding the visible physical effect of an authorized action

K5 hardware Tier B, C, D, and S3 remain separate and cannot be upgraded by K6 software CI.

## Attack-to-evidence matrix

| Attack | Expected evidence |
|---|---|
| Private ready slot drives send slot | Type error or network counterexample |
| Private margin drives packet size | Type error or byte/size divergence |
| Private confidence drives retry | Type error or retry divergence |
| Private failure drives public error | Type error or failure divergence |
| Identity drives service alias | Type error or service/collusion divergence |
| Action suppressed to obtain equality | Utility counterexample |
| Duplicate or unauthorized action | Utility counterexample |
| Recoverable loss drops obligation | Fault/utility counterexample |
| Different action semantics merged | Quotient consistency rejection |
| Candidate transition mutated | Certificate or recomputation rejection |
| Cost vector understated | Recomputed cost mismatch |
| State table reordered ambiguously | Noncanonical encoding rejection |
| Unknown certificate version | `INCOMPATIBLE` result |
| Solver returns invalid SAT model | Independent checker rejection |
| Solver times out | `TIMEOUT`, never UNSAT |
| Huge source or horizon | `RESOURCE_LIMIT` before synthesis |
| Observer omits real deployment view | Claim reduction; not a passing result |
| Finite adapter omits runtime behavior | Claim reduction or model repair |

## Resource and parser controls

Default ceilings are machine-readable in `configs/quotient_forge/contract.toml`. Source size is
checked before parsing. Counts and products use checked arithmetic. Import depth/cycles, integer
ranges, state/transition totals, horizon, observer count, CEGIS iterations, solver time, memory,
and solver-output size must be bounded by later implementation Issues.

Exceeding a limit yields `RESOURCE_LIMIT`. Partial search results do not become certificates.
Timeout yields `TIMEOUT`; an unavailable requested backend yields `SOLVER_UNAVAILABLE`.

## Data and artifact boundary

Specifications and benchmark artifacts may contain abstract private labels such as
`ready_early`/`ready_late`. They must not contain real PPG/ACC, exact acquisition timestamps,
baseline values, evidence trajectories, participant/device identifiers, attestation chains,
keys, permit signatures, lease bytes, or action-token secrets.

Counterexample graphs use abstract symbols and the first public divergence. Public artifacts may
include canonical hashes, aggregate cost, model sizes, solver metadata, abstract transition
tables, and certificates. Generated experiment outputs remain ignored by Git.

## Fail-closed behavior

Invalid source does not produce IR. Invalid IR does not reach synthesis. Solver candidates are
untrusted. Invalid candidates do not produce certificates. Invalid or incompatible certificates
do not produce a production-capable `CertifiedReleaseMachine`. Missing entries and arithmetic
overflow are errors rather than cover or action defaults.

`CERTIFICATE_VALID` is the only success class. A UI or CLI must not display a green security
result for `SAT`, `UNSAT_AT_BOUND`, `TIMEOUT`, `RESOURCE_LIMIT`, or attack performance alone.

## Falsification conditions

The bounded AQRS claim is false or must be reduced if any of the following occurs:

- a generated machine can directly read private plant or acquisition state;
- two action-equivalent reachable histories yield different declared observer traces;
- equality is obtained by violating an action, deadline, or bounded-fault obligation;
- different action codes, services, windows, or deadlines are merged by quotient reduction;
- an accepted certificate fails independent recomputation;
- certificate mutation, trailing data, or unknown version is accepted;
- generated runtime behavior differs from the certified transition table;
- timeout or resource exhaustion is reported as unrealizability;
- a solver is the only component checking security;
- a deployment claim includes an observer or runtime behavior absent from the finite model;
- K6 software results are used to claim K5 hardware verification.

## Residual risk and required claim language

Even a valid certificate is bounded evidence about one compiled finite model. Parser, abstraction,
quotient, observer, checker, code generator, adapter, and toolchain bugs remain possible. Separate
mutation tests, differential implementation checks, fuzzing, benchmarks, and deployment review
reduce but do not eliminate this risk.

QuotientForge is described as a domain-specific certifying compiler and AQRS as a candidate new
synthesis problem. Priority, patentability, and exhaustive prior-art conclusions require separate
review and are not established by this threat model.
