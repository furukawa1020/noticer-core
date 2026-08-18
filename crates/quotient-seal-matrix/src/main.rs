use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use quotient_seal_matrix::{
    plan_configuration, run_plan, CompilationMatrix, MatrixVerdict, PlanInput, ProcessExecutor,
};

#[derive(Debug, Parser)]
#[command(name = "quotient-seal-matrix")]
#[command(about = "Plan and execute reproducible QuotientSeal compiler evaluations")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Plan(Arguments),
    Run(Arguments),
}

#[derive(Debug, clap::Args)]
struct Arguments {
    #[arg(
        long,
        default_value = "configs/quotient_seal/compilation_matrix_v1.yaml"
    )]
    matrix: PathBuf,
    #[arg(long)]
    configuration: String,
    #[arg(long)]
    source: PathBuf,
    #[arg(long, default_value = "artifacts/quotient_seal_matrix")]
    output_dir: PathBuf,
    #[arg(long)]
    checker_program: String,
    #[arg(long, required = true)]
    checker_arg: Vec<String>,
}

fn main() -> ExitCode {
    match execute(Cli::parse()) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("quotient-seal-matrix: {error}");
            ExitCode::from(64)
        }
    }
}

fn execute(cli: Cli) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let arguments = match &cli.command {
        Commands::Plan(arguments) | Commands::Run(arguments) => arguments,
    };
    let matrix = CompilationMatrix::from_path(&arguments.matrix)?;
    let plan = plan_configuration(
        &matrix,
        &arguments.configuration,
        &PlanInput {
            source: arguments.source.clone(),
            output_dir: arguments.output_dir.clone(),
            checker_program: arguments.checker_program.clone(),
            checker_args: arguments.checker_arg.clone(),
        },
    )?;

    match cli.command {
        Commands::Plan(_) => {
            println!("{}", serde_json::to_string_pretty(&plan)?);
            Ok(ExitCode::SUCCESS)
        }
        Commands::Run(_) => {
            let manifest = run_plan(&plan, &ProcessExecutor);
            let manifest_path = arguments
                .output_dir
                .join(&arguments.configuration)
                .join("manifest.json");
            manifest.write_json(&manifest_path)?;
            println!("{}", serde_json::to_string_pretty(&manifest)?);
            Ok(match manifest.verdict {
                MatrixVerdict::Accept => ExitCode::SUCCESS,
                MatrixVerdict::Reject => ExitCode::from(2),
                MatrixVerdict::Inconclusive => ExitCode::from(3),
            })
        }
    }
}

