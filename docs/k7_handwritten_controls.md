# K7 handwritten AETS and sensitivity controls

The handwritten AETS approximation transmits one fixed-size action frame at
the public deadline, retrying on subsequent public-available slots when a
fault blocks that slot. Private readiness does not alter its observer trace
within a matched-action pair.

The immediate control transmits as soon as private readiness occurs. The
leaky control adds one private-bit-dependent size increment to the same
deadline-shaped frame. Both are intentionally unsafe controls, isolated from
the AETS result. If either control is not distinguishable on the chosen pair,
the comparison is INVALID_EVALUATION, not evidence of privacy.

The shared manifest binds configuration, action semantics, and public fault
trace. Delivery slot, deadline result, and bandwidth are reported separately.
This local finite approximation is neither a production AETS implementation
nor a security proof.
