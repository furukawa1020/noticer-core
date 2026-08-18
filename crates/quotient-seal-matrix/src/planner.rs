use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::config::{CodegenUnits, CompilationMatrix, ToolchainRole};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandSpec {
    pub program: String,
    pub args: Vec<String>,
    pub current_dir: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanInput {
    pub source: PathBuf,
    pub output_dir: PathBuf,
    pub checker_program: String,
    pub checker_args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilationPlan {
    pub schema_version: String,
    pub configuration_id: String,
    pub toolchain_channel: String,
    pub role: ToolchainRole,
    pub held_out: bool,
    pub target: String,
    pub source: PathBuf,
    pub raw_outputs: [PathBuf; 2],
    pub final_outputs: [PathBuf; 2],
    pub rustc_path_command: CommandSpec,
    pub rustc_version_command: CommandSpec,
    pub compile_commands: [CommandSpec; 2],
    pub wasm_opt_version_command: Option<CommandSpec>,
    pub wasm_opt_commands: Option<[CommandSpec; 2]>,
    pub checker_command: CommandSpec,
    pub wasm_opt_expected_version: Option<String>,
    pub fingerprint_sha256: String,
}

pub fn plan_configuration(
    matrix: &CompilationMatrix,
    configuration_id: &str,
    input: &PlanInput,
) -> Result<CompilationPlan, PlanError> {
    matrix.validate().map_err(PlanError::InvalidMatrix)?;
    let config = matrix
        .configuration(configuration_id)
        .ok_or_else(|| PlanError::UnknownConfiguration(configuration_id.to_owned()))?;
    let toolchain = matrix
        .toolchain(&config.toolchain)
        .ok_or_else(|| PlanError::UnknownToolchain(config.toolchain.clone()))?;

    if !input
        .checker_args
        .iter()
        .any(|argument| argument.contains("{artifact}"))
    {
        return Err(PlanError::MissingArtifactPlaceholder);
    }

    let config_dir = input.output_dir.join(&config.id);
    let raw_outputs = [
        config_dir.join("pass-1.raw.wasm"),
        config_dir.join("pass-2.raw.wasm"),
    ];
    let optimized = config.wasm_opt.flag().is_some();
    let final_outputs = if optimized {
        [
            config_dir.join("pass-1.final.wasm"),
            config_dir.join("pass-2.final.wasm"),
        ]
    } else {
        raw_outputs.clone()
    };

    let compile_commands = [
        compile_command(matrix, config, toolchain, input, &raw_outputs[0]),
        compile_command(matrix, config, toolchain, input, &raw_outputs[1]),
    ];
    let rustc_path_command = CommandSpec {
        program: matrix.rustup_binary.clone(),
        args: vec![
            "which".to_owned(),
            "--toolchain".to_owned(),
            toolchain.channel.clone(),
            "rustc".to_owned(),
        ],
        current_dir: config_dir.clone(),
    };
    let rustc_version_command = CommandSpec {
        program: matrix.rustup_binary.clone(),
        args: vec![
            "run".to_owned(),
            toolchain.channel.clone(),
            "rustc".to_owned(),
            "--version".to_owned(),
            "--verbose".to_owned(),
        ],
        current_dir: config_dir.clone(),
    };

    let wasm_opt_commands = config.wasm_opt.flag().map(|flag| {
        [
            wasm_opt_command(
                matrix,
                flag,
                &config_dir,
                &raw_outputs[0],
                &final_outputs[0],
            ),
            wasm_opt_command(
                matrix,
                flag,
                &config_dir,
                &raw_outputs[1],
                &final_outputs[1],
            ),
        ]
    });
    let wasm_opt_version_command = optimized.then(|| CommandSpec {
        program: matrix.wasm_opt_binary.clone(),
        args: vec!["--version".to_owned()],
        current_dir: config_dir.clone(),
    });
    let checker_command = CommandSpec {
        program: input.checker_program.clone(),
        args: input
            .checker_args
            .iter()
            .map(|argument| {
                argument.replace("{artifact}", &final_outputs[0].to_string_lossy())
            })
            .collect(),
        current_dir: config_dir,
    };

    let mut plan = CompilationPlan {
        schema_version: matrix.schema_version.clone(),
        configuration_id: config.id.clone(),
        toolchain_channel: toolchain.channel.clone(),
        role: toolchain.role,
        held_out: toolchain.role == ToolchainRole::HeldOut,
        target: matrix.target.clone(),
        source: input.source.clone(),
        raw_outputs,
        final_outputs,
        rustc_path_command,
        rustc_version_command,
        compile_commands,
        wasm_opt_version_command,
        wasm_opt_commands,
        checker_command,
        wasm_opt_expected_version: optimized
            .then(|| matrix.wasm_opt_expected_version.clone()),
        fingerprint_sha256: String::new(),
    };
    plan.fingerprint_sha256 = plan_fingerprint(&plan)?;
    Ok(plan)
}

fn compile_command(
    matrix: &CompilationMatrix,
    config: &crate::config::CompilationConfig,
    toolchain: &crate::config::ToolchainSpec,
    input: &PlanInput,
    output: &std::path::Path,
) -> CommandSpec {
    let mut args = vec![
        "run".to_owned(),
        toolchain.channel.clone(),
        "rustc".to_owned(),
        "--edition=2021".to_owned(),
        "--crate-type=cdylib".to_owned(),
        format!("--target={}", matrix.target),
        "-Cpanic=abort".to_owned(),
        format!("-Copt-level={}", config.opt_level.rustc_value()),
        format!("-Clto={}", config.lto.rustc_value()),
    ];
    if config.codegen_units == CodegenUnits::One {
        args.push("-Ccodegen-units=1".to_owned());
    }
    args.extend([
        "-o".to_owned(),
        output.to_string_lossy().into_owned(),
        input.source.to_string_lossy().into_owned(),
    ]);
    CommandSpec {
        program: matrix.rustup_binary.clone(),
        args,
        current_dir: output
            .parent()
            .map_or_else(|| input.output_dir.clone(), std::path::Path::to_path_buf),
    }
}

fn wasm_opt_command(
    matrix: &CompilationMatrix,
    flag: &str,
    current_dir: &std::path::Path,
    input: &std::path::Path,
    output: &std::path::Path,
) -> CommandSpec {
    CommandSpec {
        program: matrix.wasm_opt_binary.clone(),
        args: vec![
            flag.to_owned(),
            input.to_string_lossy().into_owned(),
            "-o".to_owned(),
            output.to_string_lossy().into_owned(),
        ],
        current_dir: current_dir.to_path_buf(),
    }
}

fn plan_fingerprint(plan: &CompilationPlan) -> Result<String, PlanError> {
    let encoded = serde_json::to_vec(plan).map_err(PlanError::Serialize)?;
    Ok(format!("{:x}", Sha256::digest(encoded)))
}

#[derive(Debug, Error)]
pub enum PlanError {
    #[error("invalid compilation matrix: {0}")]
    InvalidMatrix(crate::config::MatrixError),
    #[error("unknown compilation configuration: {0}")]
    UnknownConfiguration(String),
    #[error("unknown toolchain: {0}")]
    UnknownToolchain(String),
    #[error("checker arguments must contain {{artifact}}")]
    MissingArtifactPlaceholder,
    #[error("failed to serialize deterministic plan: {0}")]
    Serialize(serde_json::Error),
}

