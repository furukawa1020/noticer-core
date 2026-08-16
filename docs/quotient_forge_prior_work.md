# QuotientForge prior-work boundary

Status: K6-14 claim boundary  
Review cutoff: 2026-08-17  
Scope: primary-source-oriented literature review, not an exhaustive patent or prior-art search

## 1. Claim anchor

QuotientForge is a domain-specific certifying toolchain for the bounded finite
Action-Quotient Release Synthesis (AQRS) model. It checks, repairs, and, within an
explicit search bound, synthesizes release transducers whose declared observer traces are
equal inside an action-equivalence class while preserving declared action, deadline, and
bounded-fault utility.

The defensible research object is the following exact combination:

```text
private finite plant
  -> authorized-action quotient over private histories
  -> complete declared observer trace equality
  -> action/deadline/bounded-fault utility
  -> bounded search or typed repair
  -> solver-independent finite checking
  -> certificate-linked no_std runtime
  -> existing Noticer AETP/ATv2/APLOT/AEPA boundary
```

AQRS is described as a `candidate new synthesis problem`. Its trace requirement is a
`proposed security notion` specialized to the existing AETP boundary. Priority is not inferred
from the implementation alone.

To the best of our literature review, we found no prior work combining these exact semantics.
This sentence means only that the sources reviewed below did not expose the complete combination.
It is not an exhaustive academic, patent-family, or product search.

## 2. Comparison map

| Prior area | Established capability | Direct overlap | QuotientForge-specific restriction | Claim consequence |
|---|---|---|---|---|
| HyperLTL synthesis | Reactive synthesis for hyperproperties; bounded semi-decision procedures | Multi-trace noninterference and bounded implementation search | Fixed AQRS IR, explicit action quotient, utility/fault automata, declared release observers | Do not claim general hyperproperty synthesis |
| Privacy-aware synthesis | Observer-relative privacy, bounded transducer synthesis, and privacy certificates | Hidden information, observer knowledge, finite-state bounds, certification | Equality modulo authorized actions over the complete release trace, plus hard utility and Noticer bindings | Treat this as the closest synthesis prior work; claim only the domain-specific combination |
| Hyperproperty repair | Finite-state substructure repair and SyGuS repair with transparency objectives | Counterexample-driven repair and distance from the source | Closed release-IR operator set and checker-validated Pareto points | Do not claim general or source-language program repair |
| Runtime enforcement | Sound and transparent HyperLTL enforcement, including output correction | Correcting observable output to satisfy a hyperproperty | Offline finite synthesis/repair followed by immutable generated runtime | Do not claim the general runtime-enforcement problem |
| Hypercontracts | Composition, refinement, quotient, and strong merge over component sets/hyperproperties | The word `quotient`, hyperproperties, and component contracts | Equivalence classes induced by authorized action semantics, not a contract-algebra quotient | Do not claim a new general quotient or compositional contract theory |
| Pacer / NetShaper | Secret-independent and differentially private packet timing/size shaping | Cover traffic, cadence, size, latency, and bandwidth tradeoffs | Mechanism selection under action quotient, observer, utility, deadline, and fault constraints | Traffic shaping is a backend mechanism, not the contribution by itself |
| IFC / Jif | Static information-flow control, authority, and safe declassification | Explicitly authorized release of protected information | Reactive action semantics and complete finite release traces | Action quotient is a domain policy, not the invention of declassification |
| Certifying compilation / PCC | Producer emits independently checkable evidence bound to generated code | Untrusted producer, small checker, artifact binding, tamper rejection | CAQT finite reachability record for AQRS plus generated public-only runtime | Do not claim certificates or independent checking as new in isolation |
| CEGIS / bounded search | Counterexample-guided candidate refinement and bounded implementation search | Candidate enumeration, blockers, symmetry reduction, optimization | AQRS-specific candidate alphabet and checker feedback | CEGIS and MaxSMT are implementation techniques, not novelty claims |
| AETP and Noticer | Action-equivalent trace privacy and the private-to-public declassification boundary | Core property and domain types | Automatic finite construction, repair, checking, and code generation | K6 extends existing project prior work; it does not redefine AETP |

## 3. HyperLTL synthesis

Finkbeiner et al. synthesize reactive systems from HyperLTL and show that full HyperLTL
synthesis is undecidable while identified fragments remain decidable. Their universal fragment
uses a bounded semi-decision procedure that constructs implementations and counterexamples.
Therefore, multi-trace synthesis, noninterference synthesis, bounded implementation search, and
counterexample generation are prior work.

QuotientForge does not parse general HyperLTL and does not establish a new decidability result.
Its narrower object is a deterministic release transducer over finite quotient/public/fault
alphabets. Any theorem is scoped to the compiled finite model and recorded horizon.

## 4. Synthesis with privacy against an observer

Almagor and Kupferman study synthesis where an observer must not determine a secret. Their work
includes bounded synthesis, knowledgeable observers, and certified privacy. This is a direct
collision with any broad statement that QuotientForge introduces privacy-aware synthesis,
observer-aware synthesis, bounded private transducers, or privacy certificates.

The remaining distinction is semantic and domain-specific:

- the permitted disclosure is an ordered `ActionSemantics` quotient rather than a chosen set of
  hidden signals;
- the checked object is the full declared release trace, including silence, size, timing, failure,
  retry, reconnect, service, and cost observations;
- exactly-once action, deadline, no-unauthorized-action, and bounded-fault utility are hard
  constraints;
- the generated API accepts quotient, public, and fault inputs but no private biosignal input;
- the output binds to the existing Noticer security contracts.

These distinctions motivate an AQRS-specific artifact. They do not establish priority without a
broader literature and patent review and direct experimental comparison.

## 5. Program repair

Bonakdarpour and Finkbeiner establish repair for HyperLTL over finite-state Kripke structures.
Beutner et al. later repair infinite-state software against temporal hyperproperties using
symbolic execution, constraint generation, SyGuS, and transparent-repair objectives.

QuotientForge repair is intentionally less general. It rewrites only a typed finite release IR
with a closed operator set such as fixed-size normalization, cover insertion, public retry, and
release-window changes. A result means only that the bounded checker accepted a reachable repair
within the configured operator depth and resource limits. `NoRepair` does not imply that no source
program repair exists.

## 6. Runtime enforcement

Coenen et al. define sound and transparent runtime enforcement for hyperproperties and provide a
parity-game construction for a parallel model. Sequential enforcement is generally undecidable,
with restricted algorithms for partial guarantees or safety properties.

QuotientForge is not a replacement for that theory. It performs offline bounded checking,
synthesis, or repair, then emits an immutable finite runtime. It does not observe an unbounded set
of traces online, does not repair arbitrary live program output, and does not prove transparent
enforcement outside its finite release model.

## 7. Hypercontracts

Hypercontracts provide assume-guarantee theories over component sets and include algebraic
composition, quotient, refinement, and strong merge. This means neither `hyperproperty contract`
nor `quotient` is available as an unqualified novelty term.

The AQRS quotient is an equivalence relation over private histories induced by authorized action
semantics. It is not the Hypercontracts quotient operator. K6 currently has no complete
compositional theory: longitudinal composition is allowed only under an explicit public handoff
and absence of private carryover. A general contract-composition claim is deferred.

## 8. Traffic shaping

Pacer makes cloud traffic shape independent of secrets while respecting flow control, congestion,
and loss recovery. NetShaper provides tunable differential privacy for packet timing and size with
bandwidth/latency tradeoffs. Fixed cadence, padding, cover frames, packet-size normalization, and
traffic-cost tradeoffs are therefore established mechanisms.

AQRS may select such mechanisms, but does not claim their invention. Its exact pointwise equality
inside a declared action quotient is not automatically stronger than Pacer or NetShaper: the
adjacency relation, observer, environment, utility, composition rule, and deployment assumptions
differ. A comparative security statement requires a shared threat model and measurements.

## 9. IFC and declassification

The decentralized label model and Jif support authority-mediated declassification and static
information-flow checks. More broadly, noninterference modulo explicit release is established
information-flow practice.

QuotientForge's `ActionSemantics` is a domain-specific answer to what may be released. The novel
candidate is not declassification itself, but whether the exact combination of action-induced
equivalence, complete release traces, bounded-fault utility, automated construction, and Noticer
code generation is a useful synthesis problem.

## 10. Certificates and generated code

Proof-Carrying Code established producer-generated, independently checkable safety evidence.
Witnessing secure compilation also studies compiler-generated witnesses for preservation of
security hyperproperties. Consequently, a small checker, a certificate, stable hashes, generated
code, and mutation rejection are not standalone contributions.

CAQT should be described precisely as a versioned finite artifact that binds a compiled AQRS
model, transducer, observer/utility/fault contract, and recomputed checker result. It is not a proof
assistant derivation and not a solver proof. Its trust base still includes parsing, lowering,
finite abstraction, quotient construction, observer projection, checker logic, code generation,
adapter correctness, and the toolchain.

## 11. Completeness and soundness boundary

The implementation has three distinct limits:

- Synthesis non-completeness: timeout, resource exhaustion, unavailable solver, and an exhausted
  smaller state bound say nothing about larger bounds or an unbounded implementation.
- Checker non-completeness: BFS is exhaustive only for the supplied finite `CheckerModel`, initial
  pairs, observer projections, input alphabet, resource budget, and horizon. Missing deployment
  behavior is outside the result, and resource exhaustion returns `Inconclusive`.
- Assurance non-completeness: the checker is tested but not machine-verified. Acceptance depends
  on the correctness of the TCB and cannot prove physical BLE timing, OS scheduling, hardware,
  private acquisition, or an omitted observer.

`CERTIFICATE_VALID` therefore means bounded acceptance for one compiled model. It does not mean
unbounded realizability, deployment equivalence, global optimality, or absence of implementation
bugs.

## 12. Claim ladder

### Implemented facts

- A finite product checker distinguishes verified, counterexample, and inconclusive outcomes.
- A solver-independent exhaustive backend and an optional SMT-LIB candidate backend exist.
- Typed repair points are rechecked before acceptance.
- CAQT mutations and contract mismatches are rejected by the implemented checker tests.
- Generated `no_std` Rust exposes only quotient/public/fault inputs.
- Noticer adapters bind existing AETP, ATv2, APLOT, AEPA, and Menfugu contracts.
- The Studio is a browser small-model demonstration, not the central research contribution.

### Research wording allowed at the current evidence level

- `candidate new synthesis problem`
- `proposed security notion`
- `domain-specific certifying compiler`
- `bounded AQRS checker, repair, and synthesis toolchain`
- `to the best of our literature review, we found no prior work combining these exact semantics`

### Wording deferred until stronger evidence

- Claims of general HyperLTL synthesis, general privacy synthesis, or general program repair
- Claims that exact AQRS equality dominates differential privacy or secret-independent shaping
- Claims of unbounded, deployment-wide, or hardware-level security
- Claims of solver scalability, global optimality, or automatic discovery beyond measured bounds
- Priority claims not qualified by search scope

## 13. Primary sources

1. Finkbeiner et al., [Synthesizing Reactive Systems from Hyperproperties](https://finkbeiner.groups.cispa.de/publications/2018-synthesizing-reactive-systems-from-hyperproperties/), CAV 2018.
2. Almagor and Kupferman, [Synthesis with Privacy Against an Observer](https://arxiv.org/abs/2411.08635), FoSSaCS 2024 / LMCS 2025.
3. Bonakdarpour and Finkbeiner, [Program Repair for Hyperproperties](https://arxiv.org/abs/2101.08257), 2021.
4. Beutner et al., [Syntax-Guided Automated Program Repair for Hyperproperties](https://finkbeiner.groups.cispa.de/publications/2024-syntax-guided-automated-program-repair-for-hyperproperties/), CAV 2024.
5. Coenen et al., [Runtime Enforcement of Hyperproperties](https://arxiv.org/abs/2203.04146), ATVA 2021.
6. Incer et al., [Hypercontracts](https://link.springer.com/article/10.1007/s10703-025-00473-6), Formal Methods in System Design, 2025.
7. Mehta et al., [Pacer: Comprehensive Network Side-Channel Mitigation in the Cloud](https://www.usenix.org/conference/usenixsecurity22/presentation/mehta), USENIX Security 2022.
8. Sabzi et al., [NetShaper: A Differentially Private Network Side-Channel Mitigation System](https://www.usenix.org/conference/usenixsecurity24/presentation/sabzi), USENIX Security 2024.
9. Myers and Liskov, [Complete, Safe Information Flow with Decentralized Labels](https://www.cs.cornell.edu/andru/papers/sp98/paper.html), IEEE S&P 1998.
10. Necula, [Proof-Carrying Code](https://people.eecs.berkeley.edu/~necula/papers.html), POPL 1997.
11. Namjoshi and Tabajara, [Witnessing Secure Compilation](https://arxiv.org/abs/1911.05866), 2019.
12. Kifer and Machanavajjhala, [Pufferfish: A Framework for Mathematical Privacy Definitions](https://doi.org/10.1145/2514689), ACM TODS 2014.
13. He, Machanavajjhala, and Ding, [Blowfish Privacy](https://doi.org/10.1145/2588555.2588581), SIGMOD 2014.

