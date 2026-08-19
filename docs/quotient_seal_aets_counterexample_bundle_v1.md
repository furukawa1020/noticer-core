# AETS counterexample bundle v1

Issue #165 freezes deterministic reduction and reproduction of an AETS matrix
counterexample. The input is an already observed counterexample case, not a
claim that the current engines disagree.

The original case is rerun first and must reproduce a byte-identical case
artifact. Reduction then removes non-`Stop` commands from the highest index
while retaining at least one non-`Stop` command. It next zeros payload tag,
fault, service alias, and public slot in ascending command-index order. Every
candidate is reevaluated. Evaluation errors, non-counterexamples, and changed
typed-difference signatures are logged but rejected.

The preserved signature includes whether the difference came from source
refinement or the differential oracle. Oracle kind and participants are bound,
as are the observable axes on both sides. Trace values and indices may shrink;
the complete original and minimized `ComparisonPoint` values are retained so
that this relaxation is explicit rather than hidden.

The canonical JSON bundle binds the source matrix digest, original and
minimized public inputs, complete differential results, result digests, and the
ordered attempt log. Verification reruns the full reduction and requires the
entire bundle to be byte-identical. Candidate evaluation remains public-only;
private biosignal, evidence, baseline, and key material are forbidden.

Injected disagreements used by tests are harness tests, not scientific attack
results. Hardware status remains `NOT_VERIFIED`, and no priority or world-first
claim is made.
