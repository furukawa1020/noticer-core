# K7 matched-action corpus and split

The corpus contract accepts only rows derived from the Rust runtime capture.
Each pair contains exactly one left and one right trace, two distinct sanitized
session identifiers, and one shared action-semantics digest. Raw private history
is not a schema field.

The split is assigned by counterfactual family, never by frame, window, row, or
random shuffle. Validation then independently proves that pair IDs, family IDs,
and session IDs are disjoint across train, development, and test. This redundant
check prevents a later configuration edit from silently introducing leakage.

The frozen test families contain schedule and fault variants absent from
calibration. Either variant appearing in train or development blocks the corpus.
All three splits must be non-empty and every declared held-out variant must occur
in test.

The contract establishes evaluation hygiene, not privacy. Chance-level attack
accuracy cannot replace pointwise trace equality or a security proof.
