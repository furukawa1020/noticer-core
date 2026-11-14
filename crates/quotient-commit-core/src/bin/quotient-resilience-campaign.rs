use quotient_commit_core::recovery_resilience_campaign::{canonical_json, run, CampaignConfig};
use std::path::PathBuf;
fn main() {
    let mut args = std::env::args().skip(1);
    let mut seed = 42;
    let mut faults = 8;
    let mut output: Option<PathBuf> = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--seed" => {
                seed = args
                    .next()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or_else(|| usage())
            }
            "--faults" => {
                faults = args
                    .next()
                    .and_then(|v| v.parse::<u8>().ok())
                    .unwrap_or_else(|| usage())
            }
            "--output" => output = args.next().map(PathBuf::from),
            _ => usage(),
        }
    }
    let r = run(CampaignConfig {
        seed,
        steps: 100,
        faults,
    })
    .unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(2)
    });
    let json = canonical_json(&r);
    if let Some(p) = output {
        std::fs::write(&p, json).unwrap_or_else(|e| {
            eprintln!("{}: {e}", p.display());
            std::process::exit(2)
        })
    } else {
        println!("{json}")
    }
    if !r.all_passed {
        std::process::exit(1)
    }
}
fn usage() -> ! {
    eprintln!("usage: quotient-resilience-campaign [--seed N] [--faults N] [--output PATH]");
    std::process::exit(2)
}
