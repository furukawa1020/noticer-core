# AETP Prior-Work Boundary and Rejection Arguments

## Boundary

### Pufferfish

AETP secret pairs can be expressed in a Pufferfish-style framework. AETP is not claimed to be
more general. The candidate difference is the conjunction of action equivalence, exact action
utility, complete release-trace semantics, typed admission, executable pointwise witnesses, and a
biosignal-to-actuation declassification mechanism.

### Robust declassification and information-flow control

AETP shares the goal of preventing release beyond an intended action. It specializes that goal to
probabilistic longitudinal traces, deadlines, physical action preservation, and colluding service
views. It does not replace general robust-declassification or information-flow theory.

### Traffic shaping, padding, and ORAM

Fixed-rate channels and padding are established techniques. AETS uses them as components. The
research question is whether private evidence timing can be erased at admission and replaced by a
semantics-only, utility-preserving schedule over the complete observer trace. Padding alone is not
the contribution.

### CAPE-PPG-CED

CAPE-PPG-CED asks how much a released packet leaks beyond an allowed claim. AETP compares complete
packet, timing, silence, failure, multi-service, and longitudinal distributions between private
histories with identical allowed action semantics. Pointwise equality and counterfactual paired
histories make the mechanism more than a sequence-only packet evaluation.

## Rejection arguments

| # | Argument | Verdict | Response |
|---|---|---|---|
| 1 | Pufferfish instantiation only | Pivot | Admit the semantics relationship; retain value only if the action-preserving mechanism and evidence are substantive. |
| 2 | Noninterference modulo declassification only | Pivot | Do not claim the general theory; evaluate the specialized complete-trace construction. |
| 3 | Robust declassification only | Pivot | Position probabilistic longitudinal and multi-service traces as specialization, not replacement. |
| 4 | Fixed-rate traffic shaping only | Fatal if true | Admission erasure, utility constraints, counterfactual game, and service domains must carry the contribution. |
| 5 | Padding only | Fatal if true | Fixed length without timing protection must fail the negative control. |
| 6 | Simple ORAM application | Survive | AETS does not hide memory access; it enforces action semantics and deadlines across release views. |
| 7 | CAPE sequence extension | Fatal if no mechanism | Pointwise equality, paired histories, physical semantics, and collusion must remain distinct. |
| 8 | Conditional mutual information measurement | Survive | AETP is a mechanism/security game; MMD and attack metrics are only falsification tools. |
| 9 | Weak relation to capability tokens | Pivot | Keep K2 about release privacy and connect authority only through admitted action semantics. |
| 10 | Action semantics leak heavily | Survive | Report allowed leakage separately; AETP protects only excess trace leakage. |
| 11 | Equivalence condition too strong | Pivot | Measure class prevalence on real data and coarsen semantics only with explicit utility review. |
| 12 | Fixed rate impractical | Pivot | Measure overhead and consider approximate AETP; do not hide the cost. |
| 13 | Bystander sees action | Survive | Explicit non-goal; visible action is authorized declassification. |
| 14 | Collusion remains possible | Pivot | Pairwise domains remove private-time synchronization; empirical collusion bounds remain required. |
| 15 | Auxiliary information breaks privacy | Pivot | State bounded attacker knowledge; avoid unconditional privacy claims. |
| 16 | Synthetic experiment only | Pivot | K2 validates mechanism and harness; real multi-day PPG is a later requirement. |
| 17 | Equality is trivial API separation | Fatal if sole evidence | Formal game, complete trace, utility, composition, collusion, pairs, and attacks are all required. |
| 18 | Random scheduling harms UX | Pivot | Preserve deadlines and measure latency; redesign windows if utility fails. |
| 19 | Short deadlines defeat privacy | Pivot | Reject non-jointly-feasible pairs or move to approximate AETP. |
| 20 | Action/no-action is visible | Survive | They are different equivalence classes by definition. |

The aggregate, not type separation alone, is the candidate research contribution: formal game,
complete trace model, action-preserving mechanism, longitudinal composition, multi-service
evaluation, counterfactual generator, and attack evidence.
