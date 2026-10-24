# QuotientCommit Recovery Acceptance Demo

Run all five deterministic recovery scenarios with one command:

```bash
cargo run --manifest-path crates/quotient-commit-core/Cargo.toml --bin quotient-recovery-demo
```

The command emits canonical JSON on stdout and a human-readable invariant summary on stderr. Use `--output PATH` to write the machine-readable artifact; generated artifacts are not committed. The Studio mirrors the scenario outcomes for presentation, while native Rust execution remains authoritative.
