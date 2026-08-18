use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use quotient_seal_matrix::ProcessExecutor;
use quotient_seal_mutation::{
    run_campaign, CampaignManifest, CampaignRequest, CommandTemplate,
    InconclusiveEvaluator, IndependentPipelineEvaluator, SplitContract,
};

#[derive(Debug, Parser)]
#[command(name = "quotient-seal-mutation")]
#[command(about = "Generate deterministic QuotientSeal WASM mutation artifacts")]
struct Cli {
    #[arg(long, default_value = "configs/quotient_seal/mutation_split_v1.yaml")]
    split_contract: PathBuf,
    #[arg(long)]
    seed: PathBuf,
    #[arg(long)]
    module_family: String,
    #[arg(long)]
    compiler_configuration: String,
    #[arg(long, default_value = "artifacts/quotient_seal_mutation")]
    output_dir: PathBuf,
    #[arg(long)]
    parser_a_program: Option<String>,
    #[arg(long)]
    parser_a_arg: Vec<String>,
    #[arg(long)]
    parser_b_program: Option<String>,
    #[arg(long)]
    parser_b_arg: Vec<String>,
    #[arg(long)]
    checker_program: Option<String>,
    #[arg(long)]
    checker_arg: Vec<String>,
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
    let request = CampaignRequest {
        seed_path: cli.seed,
        module_family: cli.module_family,
        compiler_configuration: cli.compiler_configuration,
        output_root: cli.output_dir,
    };
    let manifest = match (
        cli.parser_a_program,
        cli.parser_b_program,
        cli.checker_program,
    ) {
        (None, None, None) => run_campaign(&contract, &request, &InconclusiveEvaluator)?,
        (Some(parser_a), Some(parser_b), Some(checker)) => {
            let current_dir = PathBuf::from(".");
            let evaluator = IndependentPipelineEvaluator::new(
                ProcessExecutor,
                CommandTemplate::new(
                    "parser_a",
                    parser_a,
                    cli.parser_a_arg,
                    current_dir.clone(),
                )?,
                CommandTemplate::new(
                    "parser_b",
                    parser_b,
                    cli.parser_b_arg,
                    current_dir.clone(),
                )?,
                CommandTemplate::new("checker", checker, cli.checker_arg, current_dir)?,
            )?;
            run_campaign(&contract, &request, &evaluator)?
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "parser-a, parser-b, and checker programs must be configured together",
            )
            .into());
        }
    };
    print_manifest(&manifest)?;
    Ok(())
}

fn print_manifest(manifest: &CampaignManifest) -> Result<(), serde_json::Error> {
    println!("{}", serde_json::to_string_pretty(&manifest)?);
    Ok(())
}
