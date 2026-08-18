use std::cell::Cell;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use quotient_seal_matrix::{
    plan_configuration, run_plan, CommandExecutor, CommandOutput, CommandSpec,
    CompilationMatrix, MatrixVerdict, PlanInput, ReproducibilityStatus, ToolchainRole,
};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "quotient-seal-matrix-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("test directory should be created");
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct FakeExecutor {
    root: PathBuf,
    checker_exit: i32,
    diverge: bool,
    compile_count: Cell<u8>,
}

impl FakeExecutor {
    fn new(root: &Path, checker_exit: i32, diverge: bool) -> Self {
        fs::write(root.join("rustc"), b"fake-rustc").expect("fake rustc");
        fs::write(root.join("wasm-opt"), b"fake-wasm-opt").expect("fake wasm-opt");
        Self {
            root: root.to_path_buf(),
            checker_exit,
            diverge,
            compile_count: Cell::new(0),
        }
    }

    fn write_output(&self, command: &CommandSpec, bytes: &[u8]) {
        let output_index = command
            .args
            .iter()
            .position(|argument| argument == "-o")
            .expect("command must have output")
            + 1;
        let output = PathBuf::from(&command.args[output_index]);
        fs::create_dir_all(output.parent().expect("output parent")).expect("output directory");
        fs::write(output, bytes).expect("fake output");
    }
}

impl CommandExecutor for FakeExecutor {
    fn run(&self, command: &CommandSpec) -> io::Result<CommandOutput> {
        if command.args.first().is_some_and(|argument| argument == "which") {
            return Ok(success(format!("{}\n", self.root.join("rustc").display())));
        }
        if command.args.iter().any(|argument| argument == "--version") {
            let version = if command.program == "wasm-opt" {
                "wasm-opt version 123\n"
            } else {
                "rustc 1.93.0 (fake)\n"
            };
            return Ok(success(version.to_owned()));
        }
        if command.program == "rustup" {
            let count = self.compile_count.get();
            self.compile_count.set(count + 1);
            let bytes: &[u8] = if self.diverge && count == 1 {
                b"different-wasm"
            } else {
                b"same-wasm"
            };
            self.write_output(command, bytes);
            return Ok(success(String::new()));
        }
        if command.program == "wasm-opt" {
            let input = PathBuf::from(&command.args[1]);
            let bytes = fs::read(input)?;
            self.write_output(command, &bytes);
            return Ok(success(String::new()));
        }
        Ok(CommandOutput {
            exit_code: Some(self.checker_exit),
            stdout: String::new(),
            stderr: String::new(),
        })
    }

    fn resolve(&self, program: &str) -> io::Result<PathBuf> {
        Ok(self.root.join(program))
    }
}

fn success(stdout: String) -> CommandOutput {
    CommandOutput {
        exit_code: Some(0),
        stdout,
        stderr: String::new(),
    }
}

fn load_matrix() -> CompilationMatrix {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../configs/quotient_seal/compilation_matrix_v1.yaml");
    let matrix = CompilationMatrix::from_path(&path).expect("matrix should parse");
    matrix.validate().expect("matrix should validate");
    matrix
}

fn make_plan(root: &Path, configuration: &str) -> quotient_seal_matrix::CompilationPlan {
    let source = root.join("lib.rs");
    fs::write(&source, "#![no_std]").expect("source");
    plan_configuration(
        &load_matrix(),
        configuration,
        &PlanInput {
            source,
            output_dir: root.join("outputs"),
            checker_program: "independent-checker".to_owned(),
            checker_args: vec!["--artifact={artifact}".to_owned()],
        },
    )
    .expect("plan should build")
}

#[test]
fn frozen_matrix_has_all_axes_and_held_out_cases() {
    let matrix = load_matrix();
    assert_eq!(matrix.configurations.len(), 14);
    let held_out = matrix
        .configurations
        .iter()
        .filter(|configuration| {
            matrix
                .toolchain(&configuration.toolchain)
                .is_some_and(|toolchain| toolchain.role == ToolchainRole::HeldOut)
        })
        .count();
    assert_eq!(held_out, 6);
}

#[test]
fn planner_is_deterministic_and_records_exact_target_commands() {
    let temp = TestDirectory::new();
    let first = make_plan(&temp.0, "nightly-o2-fat-1-o1");
    let second = make_plan(&temp.0, "nightly-o2-fat-1-o1");
    assert_eq!(first, second);
    assert!(first.held_out);
    assert!(first.compile_commands[0]
        .args
        .iter()
        .any(|argument| argument == "--target=wasm32-unknown-unknown"));
    assert!(first.compile_commands[0]
        .args
        .iter()
        .any(|argument| argument == "-Clto=fat"));
    assert!(first.wasm_opt_commands.is_some());
}

#[test]
fn reproducible_checker_acceptance_is_accept() {
    let temp = TestDirectory::new();
    let plan = make_plan(&temp.0, "stable-o0-off-default-none");
    let manifest = run_plan(&plan, &FakeExecutor::new(&temp.0, 0, false));
    assert_eq!(manifest.verdict, MatrixVerdict::Accept);
    assert_eq!(
        manifest.reproducibility.status,
        ReproducibilityStatus::ByteIdentical
    );
    assert!(manifest.rustc.sha256.is_some());
}

#[test]
fn checker_rejection_is_not_collapsed_into_tool_failure() {
    let temp = TestDirectory::new();
    let plan = make_plan(&temp.0, "stable-o0-off-default-none");
    let manifest = run_plan(&plan, &FakeExecutor::new(&temp.0, 1, false));
    assert_eq!(manifest.verdict, MatrixVerdict::Reject);
}

#[test]
fn divergent_bytes_are_inconclusive_with_reason() {
    let temp = TestDirectory::new();
    let plan = make_plan(&temp.0, "stable-o0-off-default-none");
    let manifest = run_plan(&plan, &FakeExecutor::new(&temp.0, 0, true));
    assert_eq!(manifest.verdict, MatrixVerdict::Inconclusive);
    assert_eq!(
        manifest.reproducibility.status,
        ReproducibilityStatus::Diverged
    );
    assert!(manifest.reason.contains("reproducibility"));
}

#[test]
fn manifest_round_trip_preserves_held_out_role_and_commands() {
    let temp = TestDirectory::new();
    let plan = make_plan(&temp.0, "nightly-o1-thin-default-none");
    let manifest = run_plan(&plan, &FakeExecutor::new(&temp.0, 0, false));
    let path = temp.0.join("manifest.json");
    manifest.write_json(&path).expect("manifest should write");
    let decoded: quotient_seal_matrix::RunManifest =
        serde_json::from_slice(&fs::read(path).expect("manifest bytes"))
            .expect("manifest should parse");
    assert!(decoded.held_out);
    assert_eq!(decoded.compile_commands, plan.compile_commands);
}

