use std::env;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

use crate::manifest::{
    ArtifactDigest, CheckerRecord, MatrixVerdict, ReproducibilityRecord, ReproducibilityStatus,
    RunManifest, ToolEvidence, RUN_MANIFEST_SCHEMA_VERSION,
};
use crate::planner::{CommandSpec, CompilationPlan};

const MAX_CAPTURE_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl CommandOutput {
    #[must_use]
    pub const fn success(&self) -> bool {
        matches!(self.exit_code, Some(0))
    }
}

pub trait CommandExecutor {
    fn run(&self, command: &CommandSpec) -> io::Result<CommandOutput>;
    fn resolve(&self, program: &str) -> io::Result<PathBuf>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ProcessExecutor;

impl CommandExecutor for ProcessExecutor {
    fn run(&self, command: &CommandSpec) -> io::Result<CommandOutput> {
        fs::create_dir_all(&command.current_dir)?;
        let output = Command::new(&command.program)
            .args(&command.args)
            .current_dir(&command.current_dir)
            .output()?;
        Ok(CommandOutput {
            exit_code: output.status.code(),
            stdout: bounded(String::from_utf8_lossy(&output.stdout).into_owned()),
            stderr: bounded(String::from_utf8_lossy(&output.stderr).into_owned()),
        })
    }

    fn resolve(&self, program: &str) -> io::Result<PathBuf> {
        resolve_executable(program)
    }
}

pub fn run_plan<E: CommandExecutor>(plan: &CompilationPlan, executor: &E) -> RunManifest {
    let source = digest_artifact(&plan.source).ok();
    let rustc = inspect_rustc(plan, executor);
    let wasm_opt = plan
        .wasm_opt_version_command
        .as_ref()
        .map(|version_command| {
            inspect_resolved_tool(
                &version_command.program,
                version_command,
                plan.wasm_opt_expected_version.as_deref(),
                executor,
            )
        });
    let mut manifest = RunManifest {
        schema_version: RUN_MANIFEST_SCHEMA_VERSION.to_owned(),
        plan_fingerprint_sha256: plan.fingerprint_sha256.clone(),
        configuration_id: plan.configuration_id.clone(),
        role: plan.role,
        held_out: plan.held_out,
        target: plan.target.clone(),
        source,
        rustc,
        wasm_opt,
        compile_commands: plan.compile_commands.clone(),
        wasm_opt_commands: plan.wasm_opt_commands.clone(),
        outputs: Vec::new(),
        reproducibility: ReproducibilityRecord {
            status: ReproducibilityStatus::NotMeasured,
            reason: "compilation has not completed twice".to_owned(),
        },
        checker: None,
        verdict: MatrixVerdict::Inconclusive,
        reason: "evaluation did not complete".to_owned(),
    };

    if manifest.source.is_none() {
        manifest.reason = "source artifact could not be hashed".to_owned();
        return manifest;
    }
    if let Some(error) = manifest.rustc.inspection_error.as_ref() {
        manifest.reason = format!("rustc inspection failed: {error}");
        return manifest;
    }
    if let Some(error) = manifest
        .wasm_opt
        .as_ref()
        .and_then(|tool| tool.inspection_error.as_ref())
    {
        manifest.reason = format!("wasm-opt inspection failed: {error}");
        return manifest;
    }

    for command in &plan.compile_commands {
        if let Err(reason) = execute_required(command, executor, "rustc") {
            manifest.reason = reason;
            return manifest;
        }
    }
    if let Some(commands) = &plan.wasm_opt_commands {
        for command in commands {
            if let Err(reason) = execute_required(command, executor, "wasm-opt") {
                manifest.reason = reason;
                return manifest;
            }
        }
    }

    let first = match digest_artifact(&plan.final_outputs[0]) {
        Ok(digest) => digest,
        Err(error) => {
            manifest.reason = format!("first output is unavailable: {error}");
            return manifest;
        }
    };
    let second = match digest_artifact(&plan.final_outputs[1]) {
        Ok(digest) => digest,
        Err(error) => {
            manifest.reason = format!("second output is unavailable: {error}");
            return manifest;
        }
    };
    let identical = first.sha256 == second.sha256;
    manifest.outputs = vec![first, second];
    if !identical {
        manifest.reproducibility = ReproducibilityRecord {
            status: ReproducibilityStatus::Diverged,
            reason: "same source and configuration produced different bytes".to_owned(),
        };
        manifest.reason = "byte reproducibility failed; checker verdict withheld".to_owned();
        return manifest;
    }
    manifest.reproducibility = ReproducibilityRecord {
        status: ReproducibilityStatus::ByteIdentical,
        reason: "two isolated invocations produced the same SHA-256".to_owned(),
    };

    let checker_output = match executor.run(&plan.checker_command) {
        Ok(output) => output,
        Err(error) => {
            manifest.reason = format!("independent checker could not execute: {error}");
            return manifest;
        }
    };
    let checker = CheckerRecord {
        command: plan.checker_command.clone(),
        exit_code: checker_output.exit_code,
        stdout: bounded(checker_output.stdout),
        stderr: bounded(checker_output.stderr),
    };
    match checker.exit_code {
        Some(0) => {
            manifest.verdict = MatrixVerdict::Accept;
            manifest.reason = "independent checker accepted the reproducible artifact".to_owned();
        }
        Some(1) => {
            manifest.verdict = MatrixVerdict::Reject;
            manifest.reason = "independent checker rejected the artifact".to_owned();
        }
        code => {
            manifest.reason =
                format!("independent checker returned non-verdict exit code {code:?}");
        }
    }
    manifest.checker = Some(checker);
    manifest
}

fn execute_required<E: CommandExecutor>(
    command: &CommandSpec,
    executor: &E,
    phase: &str,
) -> Result<(), String> {
    let output = executor
        .run(command)
        .map_err(|error| format!("{phase} could not execute: {error}"))?;
    if output.success() {
        Ok(())
    } else {
        Err(format!(
            "{phase} failed with exit code {:?}: {}",
            output.exit_code,
            bounded(output.stderr)
        ))
    }
}

fn inspect_rustc<E: CommandExecutor>(plan: &CompilationPlan, executor: &E) -> ToolEvidence {
    let requested = format!("rustc@{}", plan.toolchain_channel);
    let path_output = match executor.run(&plan.rustc_path_command) {
        Ok(output) if output.success() => output,
        Ok(output) => {
            return failed_tool(
                requested,
                plan.rustc_version_command.clone(),
                format!("rustup which exited with {:?}", output.exit_code),
            );
        }
        Err(error) => {
            return failed_tool(
                requested,
                plan.rustc_version_command.clone(),
                format!("rustup which failed: {error}"),
            );
        }
    };
    let path = PathBuf::from(path_output.stdout.trim());
    inspect_tool_at_path(requested, path, &plan.rustc_version_command, None, executor)
}

fn inspect_resolved_tool<E: CommandExecutor>(
    requested: &str,
    version_command: &CommandSpec,
    expected_version: Option<&str>,
    executor: &E,
) -> ToolEvidence {
    match executor.resolve(requested) {
        Ok(path) => inspect_tool_at_path(
            requested.to_owned(),
            path,
            version_command,
            expected_version,
            executor,
        ),
        Err(error) => failed_tool(
            requested.to_owned(),
            version_command.clone(),
            format!("binary resolution failed: {error}"),
        ),
    }
}

fn inspect_tool_at_path<E: CommandExecutor>(
    requested: String,
    path: PathBuf,
    version_command: &CommandSpec,
    expected_version: Option<&str>,
    executor: &E,
) -> ToolEvidence {
    let sha256 = match hash_file(&path) {
        Ok(hash) => hash,
        Err(error) => {
            return ToolEvidence {
                requested_binary: requested,
                resolved_path: Some(path),
                sha256: None,
                version: None,
                version_command: version_command.clone(),
                inspection_error: Some(format!("binary hashing failed: {error}")),
            };
        }
    };
    let version_output = match executor.run(version_command) {
        Ok(output) if output.success() => output,
        Ok(output) => {
            return ToolEvidence {
                requested_binary: requested,
                resolved_path: Some(path),
                sha256: Some(sha256),
                version: None,
                version_command: version_command.clone(),
                inspection_error: Some(format!(
                    "version command exited with {:?}",
                    output.exit_code
                )),
            };
        }
        Err(error) => {
            return ToolEvidence {
                requested_binary: requested,
                resolved_path: Some(path),
                sha256: Some(sha256),
                version: None,
                version_command: version_command.clone(),
                inspection_error: Some(format!("version command failed: {error}")),
            };
        }
    };
    let version = version_output.stdout.trim().to_owned();
    let mismatch = expected_version
        .filter(|expected| !version.contains(*expected))
        .map(|expected| format!("version does not contain pinned marker {expected:?}"));
    ToolEvidence {
        requested_binary: requested,
        resolved_path: Some(path),
        sha256: Some(sha256),
        version: Some(version),
        version_command: version_command.clone(),
        inspection_error: mismatch,
    }
}

fn failed_tool(requested: String, version_command: CommandSpec, error: String) -> ToolEvidence {
    ToolEvidence {
        requested_binary: requested,
        resolved_path: None,
        sha256: None,
        version: None,
        version_command,
        inspection_error: Some(error),
    }
}

fn digest_artifact(path: &Path) -> io::Result<ArtifactDigest> {
    Ok(ArtifactDigest {
        path: path.to_path_buf(),
        sha256: hash_file(path)?,
    })
}

fn hash_file(path: &Path) -> io::Result<String> {
    Ok(format!("{:x}", Sha256::digest(fs::read(path)?)))
}

fn bounded(mut value: String) -> String {
    if value.len() > MAX_CAPTURE_BYTES {
        value.truncate(MAX_CAPTURE_BYTES);
        value.push_str("\n[truncated]");
    }
    value
}

fn resolve_executable(program: &str) -> io::Result<PathBuf> {
    let candidate = Path::new(program);
    if candidate.components().count() > 1 && candidate.is_file() {
        return fs::canonicalize(candidate);
    }
    let path = env::var_os("PATH")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "PATH is not set"))?;
    let extensions = executable_extensions();
    for directory in env::split_paths(&path) {
        for extension in &extensions {
            let mut name = OsString::from(program);
            if !extension.is_empty() && Path::new(program).extension().is_none() {
                name.push(extension);
            }
            let executable = directory.join(name);
            if executable.is_file() {
                return fs::canonicalize(executable);
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("executable not found on PATH: {program}"),
    ))
}

fn executable_extensions() -> Vec<OsString> {
    if cfg!(windows) {
        env::var_os("PATHEXT").map_or_else(
            || vec![OsString::from(".EXE"), OsString::from(".CMD")],
            |extensions| {
                extensions
                    .to_string_lossy()
                    .split(';')
                    .filter(|extension| !extension.is_empty())
                    .map(OsString::from)
                    .collect()
            },
        )
    } else {
        vec![OsString::new()]
    }
}
