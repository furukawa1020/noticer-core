use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use quotient_forge_cli::{execute, CheckCase, CommandName, Options, SolverMode};

struct TemporaryDirectory(PathBuf);

impl TemporaryDirectory {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must follow the Unix epoch")
            .as_nanos();
        Self(std::env::temp_dir().join(format!(
            "quotient-forge-cli-{label}-{}-{nonce}",
            std::process::id()
        )))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn options(command: CommandName, output: PathBuf) -> Options {
    Options {
        command,
        output,
        seed: 7,
        solver: SolverMode::Off,
        certificate: None,
        check_case: CheckCase::ImmediateRelease,
        symmetry_breaking: true,
    }
}

#[test]
fn six_commands_emit_public_only_canonical_manifests() {
    let temporary = TemporaryDirectory::new("commands");
    for command in CommandName::ALL {
        let output = temporary.path().join(command.as_str());
        let summary = execute(&options(command, output.clone())).unwrap();
        assert_eq!(summary.command, command);
        if command == CommandName::CompareBackends {
            let comparison = fs::read_to_string(output.join("comparison.json")).unwrap();
            assert!(comparison.contains("\"exhaustive_qbf_decision\": true"));
            assert!(comparison.contains("\"independently_checked\": true"));
            assert!(comparison.contains("\"status\": \"NOT_RUN\""));
        }
        let manifest = fs::read_to_string(output.join("manifest.json")).unwrap();
        assert!(manifest.contains("\"privacy_contract\":\"public-only-v1\""));
        assert!(manifest.contains("\"seed\":7"));
        assert!(manifest.contains("\"mode\":\"off\""));
        assert!(manifest.contains("\"compiler\":\"rustc "));
        let lower = manifest.to_ascii_lowercase();
        for forbidden in [
            "raw_ppg",
            "baseline",
            "stable_identifier",
            "subject_id",
            "device_id",
            "private_history",
        ] {
            assert!(!lower.contains(forbidden), "manifest leaked {forbidden}");
        }
    }
}

#[test]
fn same_seed_and_command_are_byte_reproducible() {
    let temporary = TemporaryDirectory::new("reproducible");
    let first = temporary.path().join("first");
    let second = temporary.path().join("second");
    execute(&options(CommandName::Check, first.clone())).unwrap();
    execute(&options(CommandName::Check, second.clone())).unwrap();
    assert_eq!(
        fs::read(first.join("manifest.json")).unwrap(),
        fs::read(second.join("manifest.json")).unwrap()
    );
    assert_eq!(
        fs::read(first.join("counterexample.json")).unwrap(),
        fs::read(second.join("counterexample.json")).unwrap()
    );
}

#[test]
fn existing_output_is_not_overwritten() {
    let temporary = TemporaryDirectory::new("no-overwrite");
    fs::create_dir_all(temporary.path()).unwrap();
    let error = execute(&options(CommandName::Check, temporary.path().to_path_buf())).unwrap_err();
    assert!(error.to_string().contains("既に存在"));
}
