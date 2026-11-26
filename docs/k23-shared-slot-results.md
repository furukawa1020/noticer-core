# K23: Shared-slot evaluation

**Scope: finite synthetic evidence only.** No real protocol, real biosignal,
anonymity claim, or publication-priority claim is evaluated here.

## Evaluation criteria

Use receiver-qualified unit actions and inclusive logical deadlines. Report
both complete tape feasibility with foresight and causal feasibility with only
the observed public prefix. Compare with deadline-first and with a causal
least-worst-slack rule: given the same admitted tapes as the synthesis engine,
serve the action with the fewest remaining usable slots in any compatible tape.
Ties are broken by deadline, then action ID. Never infer impossibility from a
failed heuristic or a search cutoff.

The grid covers all unordered pairs with repetition of 16 availability tapes
for two unit actions over three logical slots. Both actions are available in
slot 0 and due in slot 2; later per-action availability takes all subsets.
Repeat under steady capacity `(1, 1, 1)` and outage/burst capacity `(1, 0, 2)`.
Count a success only when every deadline is met on **both** tapes. The table is
an exhaustive comparison on this grid, not an estimate of population incidence.

| Capacity | Pairs | Both feasible with foresight | Deadline-first | Least-worst-slack | Independently checked causal policy | Independently checked no policy | Inconclusive |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Steady | 136 | 120 | 78 | 111 | 111 | 25 | 0 |
| Outage then burst | 136 | 78 | 36 | 62 | 62 | 74 | 0 |
| Total | 272 | 198 | 114 | 173 | 173 | 99 | 0 |

## Readout

- The stronger heuristic ties causal synthesis on this grid (173/272). There
  is **no scheduling-success advantage over the stronger baseline** here.
- In 25 pairs (9 steady, 16 outage/burst) both fixed tapes can succeed with
  foresight, but no single deterministic causal policy can guarantee it.
  The negative certificate checks every legal choice at the relevant
  indistinguishable prefixes; a failed heuristic alone cannot prove that.
- In the smallest crossed example an obliviously selected future gives a
  randomized worst-case optimum of 1/2. Do not transfer this bound to the
  full three-slot grid. One three-slot example has a common slot-zero
  decision and a genuine slot-one conflict.
- Offline matching agreed with an independent enumeration on 1,536 small
  graphs. The causal solver agreed with a separate full-allocation oracle
  on all 272 tape pairs. The forced search-budget and invalid controls are
  retained as `inconclusive` and `invalid`, respectively.
- The receiver-view and frame-count examples illustrate different
  projections. They do not measure re-identification or real wire cost.

Reproduce from an editable install, or set `PYTHONPATH` to `src`:

```text
python tools/run_shared_slot_grid.py
python tools/run_shared_slot_evidence.py --output artifacts/shared-slot/evidence.json
python tools/run_shared_slot_game.py --output artifacts/shared-slot/game.json
python tools/benchmark_shared_slots.py
```

The most useful next test is a predeclared evaluation under identical causal
information against a publicly documented strong baseline, plus a defensive
receipt audit on a real deployment boundary. These synthetic results do not
justify asserting a new mathematical theorem, empirical privacy, or novelty
over prior work.
