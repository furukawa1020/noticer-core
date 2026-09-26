# QuotientGuard adaptive runtime attack benchmark

K10-QG-06 fixes a deterministic benchmark for six runtime attack families:
config substitution, epoch rollback, timing probes, fault amplification,
colluding observers, and replay splicing.

Each attack fixture has a paired negative control. A benchmark run is valid only
when every attack reaches its registered detection reason and every negative
control remains accepted. The seed, fixture ID, attack family, class, verdict,
reason, and pass bit are emitted as CSV. Private configuration digests,
service-linkage tags, and sensor values are intentionally excluded.

Run:

~~~bash
cargo run --quiet --manifest-path crates/quotient-guard-attack-bench/Cargo.toml \
  > artifacts/quotient_guard_attack_benchmark.csv
~~~

The output is a reproducible engineering artifact, not evidence that all
adaptive attacks are covered and not a proof of privacy. Generated CSV files
remain outside Git. Changing the fixed seed creates a separate run; it must not
be mixed with the preregistered default run.

Negative controls preserve the approved digest and epoch, matched public timing,
the declared fault budget, service-specific unlinkability, and contiguous slots.
They prevent a detector that rejects every trace from appearing successful.
