#![forbid(unsafe_code)]

use quotient_guard_attack_bench::{run_benchmark, DEFAULT_SEED};

fn main() {
    let report = run_benchmark(DEFAULT_SEED);
    print!("{}", report.to_csv());
    if !report.all_passed() {
        std::process::exit(1);
    }
}
