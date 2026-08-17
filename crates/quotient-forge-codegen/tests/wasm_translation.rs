mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use quotient_forge_caqt::CertificateLimits;
use quotient_forge_codegen::generate_package;

use common::{certificate, config, TemporaryDirectory};

fn generate(label: &str) -> TemporaryDirectory {
    let temporary = TemporaryDirectory::new(label);
    let (bytes, expected) = certificate();
    generate_package(
        &bytes,
        expected,
        CertificateLimits::default(),
        &config(),
        temporary.path(),
    )
    .unwrap();
    temporary
}

fn build_wasm(root: &Path) -> PathBuf {
    let wasm = root.join("generated_runtime.wasm");
    let output = Command::new("rustc")
        .args([
            "--edition=2021",
            "--crate-type=cdylib",
            "--target",
            "wasm32-unknown-unknown",
            "-Cpanic=abort",
            "-o",
        ])
        .arg(&wasm)
        .arg(root.join("src/lib.rs"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "generated WASM build failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    wasm
}

fn run_validator(root: &Path, wasm: &Path) -> Output {
    Command::new("node")
        .arg(root.join("wasm-validation.mjs"))
        .arg(wasm)
        .output()
        .unwrap()
}

#[test]
fn actual_wasm_engine_matches_every_certificate_transition() {
    let temporary = generate("wasm-valid");
    let wasm = build_wasm(temporary.path());
    let output = run_validator(temporary.path(), &wasm);
    assert!(
        output.status.success(),
        "WASM validation failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("\"verdict\":\"VALID\""));
}

#[test]
fn actual_wasm_engine_detects_a_mutated_generated_table() {
    let temporary = generate("wasm-mutated");
    let source_path = temporary.path().join("src/lib.rs");
    let source = fs::read_to_string(&source_path).unwrap();
    let changed = source.replacen(
        "Transition { next: 1, output: 0 },",
        "Transition { next: 0, output: 0 },",
        1,
    );
    assert_ne!(source, changed, "mutation target must exist");
    fs::write(source_path, changed).unwrap();
    let wasm = build_wasm(temporary.path());
    let output = run_validator(temporary.path(), &wasm);
    assert!(
        !output.status.success(),
        "mutated WASM unexpectedly validated"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("next-state mismatch"));
}
