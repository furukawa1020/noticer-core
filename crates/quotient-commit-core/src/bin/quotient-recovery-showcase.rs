use quotient_commit_core::recovery_showcase::{canonical_json, run_showcase, summary};
use std::path::PathBuf;
fn main() {
    let mut args = std::env::args().skip(1);
    let mut seed = 0x5eed;
    let mut output: Option<PathBuf> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--seed" => {
                seed = args.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| {
                    eprintln!("invalid --seed");
                    std::process::exit(2)
                })
            }
            "--output" => output = args.next().map(PathBuf::from),
            _ => {
                eprintln!("usage: quotient-recovery-showcase [--seed N] [--output PATH]");
                std::process::exit(2)
            }
        }
    }
    if seed == 0 {
        eprintln!("seed must be nonzero");
        std::process::exit(2)
    }
    let report = run_showcase(seed);
    eprint!("{}", summary(&report));
    let json = canonical_json(&report);
    if let Some(path) = output {
        if let Err(error) = std::fs::write(&path, json) {
            eprintln!("failed to write {}: {error}", path.display());
            std::process::exit(1)
        }
    } else {
        println!("{json}")
    }
    if !report.all_passed {
        std::process::exit(1)
    }
}
