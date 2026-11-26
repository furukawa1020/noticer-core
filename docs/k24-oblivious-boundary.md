# Fix the future before the draw

The certificate refers to the following game: first fix one admitted tape,
then independently draw a deterministic causal policy, then reveal only the
current public observations as time advances. Evaluate complete delivery on
that fixed tape. A worst-case guarantee quantifies over the admitted tapes,
not over adaptive schedulers that can observe and change the future.

In the crossed two-tape example, an adversary that can select the future
after seeing the first action can select the opposite continuation. The fair
coin guarantee of 1/2 therefore does not hold in that stronger model.
This is a change in information order, not an empirical security result.
