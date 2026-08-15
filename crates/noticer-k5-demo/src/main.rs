use std::fs;
use std::path::PathBuf;

use clap::Parser;
use noticer_k5_demo::{
    build_public_artifact, write_public_artifacts, Decision, K4Summary, ProvenanceSummary,
    SoftwareGateSummary,
};

#[derive(Debug, Parser)]
#[command(about = "Inspect one reproducible public K5 Tier A run")]
struct Args {
    #[arg(long)]
    provenance_summary: PathBuf,
    #[arg(long)]
    k4_summary: PathBuf,
    #[arg(long)]
    software_gates: PathBuf,
    #[arg(long, default_value = "artifacts/k5/tier_a/latest")]
    output: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let provenance: ProvenanceSummary = read_json(&args.provenance_summary)?;
    let k4: K4Summary = read_json(&args.k4_summary)?;
    let gates: SoftwareGateSummary = read_json(&args.software_gates)?;
    let artifact = build_public_artifact(&provenance, &k4, &gates);
    write_public_artifacts(&artifact, &args.output)?;
    println!(
        "K5 Tier A: decision={:?}, scenarios={}, private_field_count={}, output={}",
        artifact.decision,
        artifact.scenarios.len(),
        artifact.private_field_count,
        args.output.display()
    );
    if artifact.decision != Decision::GoTierA {
        return Err("K5 Tier A did not satisfy the GO_TIER_A gate".into());
    }
    Ok(())
}

fn read_json<T: serde::de::DeserializeOwned>(
    path: &PathBuf,
) -> Result<T, Box<dyn std::error::Error>> {
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}
