# Mixed public-slot policies: exhaustive synthetic comparison

**Not a real-protocol, biosignal, or privacy measurement.** The environment
selects an admitted future before the policy's private draw, then fixes it.
The reward is binary: all authorized unit actions reach their deadlines.

## Grid and comparison

For three and four actions, slot 0 can send all but one action, and slot 1
can send one. Each future allows a nonempty subset of actions in slot 1.
Enumerate every unordered set of respectively three or four distinct futures
from their (2^n-1) nonempty subsets. The two strata contain 35 and 1,365 cases.
The stronger iterative comparator plays 64 rounds of deterministic fictitious
play on the same success frontier and the same tape class. Uniform means
uniform over distinct nondominated success masks. No tuning seeds are used.

| Actions/futures | Cases | Exact value verified | Deterministic guarantee zero | Exact tied uniform | Exact tied iterative64 | Exact exceeds iterative64 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 3 | 35 | 35 | 23 | 35 | 33 | 2 |
| 4 | 1,365 | 1,365 | 1,091 | 1,153 | 1,141 | 224 |
| Total | 1,400 | 1,400 | 1,114 | 1,188 | 1,174 | 226 |

No grid result was inconclusive. The largest gap against iterative64 was
(5/96), with no gap above (1/16). A finite-round comparator is not an
alternative exact optimizer: the observed gap does not establish an advantage
over stronger schedules or solvers. The key comparison is a checkable bound,
not a headline about a large scheduling win.

The asymmetric four-future fixture attains (2/5) instead of the uniform
mixture's (1/4); iterative64 already attains (25/64). The independent tape
distribution limits every causal policy to (2/5). The triangle attains
(2/3), the crossed fixture (1/2), and the fixture with an individually
unreachable tape (0). The two-slot grid includes only individually reachable
futures, so the unreachable case is reported separately, not silently omitted.

## Recreate the numbers

Use an editable installation or set `PYTHONPATH` to `src`.

```text
python tools/run_slot_mix_evidence.py --grid --output artifacts/slot-mix/comparison.json
python tools/write_slot_mix_certificate.py artifacts/slot-mix/asymmetric.json
python tools/check_slot_mix_certificate.py artifacts/slot-mix/asymmetric.json
python tools/benchmark_slot_mix.py
```
