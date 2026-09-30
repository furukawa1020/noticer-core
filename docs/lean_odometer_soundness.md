# Lean 4 adaptive composition soundness model

`QuotientLimit.OdometerSoundness` kernel-checks six safety obligations used by the AQPO implementation:

- a zero profile has a zero sound upper bound;
- pointwise adaptive costs compose below pointwise bounds;
- an allowed pre-release decision implies the reported bound is within budget;
- linearized reservations preserve capacity and cannot double-spend;
- public handoff compatibility preserves every protected profile dimension;
- service splitting remains bounded by one coalition budget.

The model deliberately proves algebraic state-machine obligations rather than claiming that arbitrary Rust code satisfies them. Refinement from runtime receipts and profiles into these Lean structures remains an explicit trusted boundary.

The dedicated CI rejects `sorry` and `axiom`, then runs `lake build` with the pinned toolchain.
