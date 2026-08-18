use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use quotient_seal_mutation::{
    run_campaign, CampaignRequest, InconclusiveEvaluator, SplitContract,
};

#[derive(Debug, Parser)]
#[command(name = "quotient-seal-mutation")]
#[command(about = "Generate deterministic QuotientSeal WASM mutation artifacts")]
struct Cli {
    #[arg(
        long,
        default_value = "configs/quotient_seal/mutation_split_v1.yaml"
    )]
    split_contract: PathBuf,
    #[arg(long)]
    seed: PathBuf,
    #[arg(long)]
    module_family: String,
    #[arg(long)]
    compiler_configuration: String,
    #[arg(long, default_value = "artifacts/quotient_seal_mutation")]
    output_dir: PathBuf,
}

fn main() -> ExitCode {
    match execute(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("quotient-seal-mutation: {error}");
            ExitCode::from(2)
        }
    }
}

fn execute(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let contract = SplitContract::from_path(&cli.split_contract)?;
    let manifest = run_campaign(
        &contract,
        &CampaignRequest {
            seed_path: cli.seed,
            module_family: cli.module_family,
            compiler_configuration: cli.compiler_configuration,
            output_root: cli.output_dir,
        },
        &InconclusiveEvaluator,
    )?;
    println!("{}", serde_json::to_string_pretty(&manifest)?);
    Ok(())
}

