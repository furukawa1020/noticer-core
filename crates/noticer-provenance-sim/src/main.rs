#![forbid(unsafe_code)]

use std::path::PathBuf;

use clap::Parser;
use noticer_provenance_sim::{run, SimulationConfig};

#[derive(Parser)]
struct Args {
    #[arg(long, default_value_t = 20_260_814)]
    seed: u64,
    #[arg(long, default_value = "artifacts/k5/provenance_counterfactual")]
    output: PathBuf,
}

fn main() {
    if let Err(error) = execute() {
        eprintln!("K5-10 counterfactual simulation failed: {error}");
        std::process::exit(1);
    }
}

fn execute() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let report = run(&SimulationConfig::full(args.seed))?;
    report.write_artifacts(&args.output)?;
    if !report.all_congruent || !report.all_private_inputs_distinct {
        return Err("counterfactual congruence invariant failed".into());
    }
    println!(
        "K5-10 complete: {} cases, provenance/lease/ATv2/K4 congruence 100%, artifacts at {}",
        report.case_count,
        args.output.display()
    );
    Ok(())
}
