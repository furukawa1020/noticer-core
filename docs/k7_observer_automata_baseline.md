# K7 hidden-signal observer baseline

This finite-corpus approximation is motivated by
[Synthesis with Privacy Against an Observer](https://lmcs.episciences.org/16127):
choose hidden signals within a cost budget so an observer cannot determine
a secret. It is not the paper's LTL synthesis, general transducer construction,
or certified privacy result.

For each candidate hiding set, the tool projects every bounded scenario onto
visible signals. A candidate is accepted only if every observed trace class
contains scenarios with both secret values. Exhaustive candidate search picks
the minimum-cost set, with lexicographic tie-breaking. This is a property of
the declared finite corpus only; held-out traces can invalidate it.

The shared case, corpus, observer, cost, action/deadline, and public-fault
digests are checked against the K7-13 manifest. State count is the number of
distinct prefixes in the finite corpus trie, not the state size of the
authors' synthesized transducer. No deployment privacy or AQNI equivalence
is claimed.
