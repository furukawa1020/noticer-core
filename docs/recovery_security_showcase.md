# Recovery Security Showcase

The software-only showcase condenses recovery safety into three deterministic acts:

1. **Seal and release** proves normal at-most-once convergence.
2. **Cut power, keep truth** injects a crash at every ceremony phase and resumes without premature release.
3. **Substitute and rewind** demonstrates fail-closed binding substitution and rollback rejection.

Run it with:

```bash
cargo run --manifest-path crates/quotient-commit-core/Cargo.toml --bin quotient-recovery-showcase -- --seed 24301
```

Human-readable status is written to stderr and canonical JSON to stdout. `--output PATH` writes a generated artifact outside version control. Studio Pages displays the same three-act recovery narrative.
