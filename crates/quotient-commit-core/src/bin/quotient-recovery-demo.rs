use quotient_commit_core::recovery_acceptance::{canonical_json, human_summary, run_acceptance};
use std::path::PathBuf;

fn main() {
    let mut args = std::env::args().skip(1);
    let mut output: Option<PathBuf> = None;
    while let Some(argument) = args.next() {
        if argument != "--output" {
            eprintln!("usage: quotient-recovery-demo [--output PATH]");
            std::process::exit(2);
        }
        output = args.next().map(PathBuf::from);
        if output.is_none() {
            eprintln!("--output requires a path");
            std::process::exit(2);
        }
    }
    let report = run_acceptance();
    eprint!("{}", human_summary(&report));
    let artifact = canonical_json(&report);
    if let Some(path) = output {
        if let Err(error) = std::fs::write(&path, artifact) {
            eprintln!("failed to write {}: {error}", path.display());
            std::process::exit(1);
        }
    } else {
        println!("{artifact}");
    }
    if !report.all_passed {
        std::process::exit(1);
    }
}
