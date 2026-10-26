use quotient_commit_core::recovery_drill::{canonical_json, run};
use std::path::PathBuf;

fn main() {
    let mut args = std::env::args().skip(1);
    let mut seed = 0x5eed;
    let mut output: Option<PathBuf> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--seed" => {
                seed = args
                    .next()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or_else(|| usage())
            }
            "--output" => output = args.next().map(PathBuf::from),
            _ => usage(),
        }
    }
    let report = run(seed).unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(2)
    });
    let json = canonical_json(&report);
    if let Some(path) = output {
        std::fs::write(&path, json).unwrap_or_else(|error| {
            eprintln!("failed to write {}: {error}", path.display());
            std::process::exit(2)
        });
    } else {
        println!("{json}");
    }
    if !report.all_passed {
        std::process::exit(1);
    }
}
fn usage() -> ! {
    eprintln!("usage: quotient-recovery-drill [--seed N] [--output PATH]");
    std::process::exit(2)
}
