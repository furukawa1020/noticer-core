use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use quotient_forge_caqt::{
    Certificate, CertificateLimits, CostVector, DomainHashes, ExpectedContract, ObserverRecord,
    OutputRecord, RelationPair, TransitionRecord, FORMAT_VERSION,
};
use quotient_forge_codegen::{generate_package, CodegenConfig, CodegenError};

fn certificate() -> (Vec<u8>, ExpectedContract) {
    let mut certificate = Certificate {
        version: FORMAT_VERSION,
        hashes: DomainHashes::zero(),
        state_count: 2,
        input_count: 1,
        observer_count: 1,
        state_bound: 2,
        claimed_cost: CostVector::default(),
        observers: vec![ObserverRecord {
            id: 0,
            sees_presence: true,
            sees_payload: true,
            sees_actions: true,
        }],
        outputs: vec![
            OutputRecord {
                id: 0,
                emitted: true,
                payload: vec![0x10, 0x20],
                actions: vec![7],
            },
            OutputRecord {
                id: 1,
                emitted: true,
                payload: vec![0x10, 0x20],
                actions: vec![7],
            },
        ],
        transitions: vec![
            TransitionRecord {
                from: 0,
                input: 0,
                to: 1,
                output: 0,
                authorized_actions: vec![7],
                required_action: Some(7),
                recoverable_fault_action: None,
            },
            TransitionRecord {
                from: 1,
                input: 0,
                to: 1,
                output: 1,
                authorized_actions: vec![7],
                required_action: Some(7),
                recoverable_fault_action: None,
            },
        ],
        relation: vec![RelationPair { left: 0, right: 1 }],
    };
    certificate.seal();
    let expected = ExpectedContract {
        version: FORMAT_VERSION,
        hashes: certificate.hashes,
        state_bound: certificate.state_bound,
        max_cost: certificate.claimed_cost,
    };
    (certificate.encode(), expected)
}

fn config() -> CodegenConfig {
    CodegenConfig {
        package_name: "generated-runtime".to_owned(),
        quotient_inputs: 1,
        public_inputs: 1,
        fault_inputs: 1,
        max_payload_bytes: 32,
        max_actions: 8,
    }
}

struct TemporaryDirectory(PathBuf);

impl TemporaryDirectory {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        Self(std::env::temp_dir().join(format!(
            "quotient-forge-{label}-{}-{nonce}",
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

#[test]
fn generated_no_std_crate_compiles_and_matches_every_vector() {
    let (bytes, expected) = certificate();
    let temporary = TemporaryDirectory::new("compile");
    let package = generate_package(
        &bytes,
        expected,
        CertificateLimits::default(),
        &config(),
        temporary.path(),
    )
    .unwrap();
    assert_eq!(package.files.len(), 6);
    assert_eq!(package.transition_vectors, 2);

    let target = temporary.path().join("target");
    let output = Command::new(env!("CARGO"))
        .args([
            "test",
            "--offline",
            "--manifest-path",
            temporary.path().join("Cargo.toml").to_str().unwrap(),
        ])
        .env("CARGO_TARGET_DIR", target)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "generated crate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn invalid_certificate_and_axis_mismatch_generate_nothing() {
    let (mut bytes, expected) = certificate();
    let invalid_target = TemporaryDirectory::new("invalid");
    bytes.push(0);
    assert!(matches!(
        generate_package(
            &bytes,
            expected,
            CertificateLimits::default(),
            &config(),
            invalid_target.path()
        ),
        Err(CodegenError::CertificateRejected(_))
    ));
    assert!(!invalid_target.path().exists());

    let (bytes, expected) = certificate();
    let mismatch_target = TemporaryDirectory::new("mismatch");
    let mut mismatch = config();
    mismatch.public_inputs = 2;
    assert!(matches!(
        generate_package(
            &bytes,
            expected,
            CertificateLimits::default(),
            &mismatch,
            mismatch_target.path()
        ),
        Err(CodegenError::InputCountMismatch { .. })
    ));
    assert!(!mismatch_target.path().exists());
}

#[test]
fn existing_target_is_never_overwritten() {
    let (bytes, expected) = certificate();
    let temporary = TemporaryDirectory::new("exists");
    fs::create_dir_all(temporary.path()).unwrap();
    fs::write(temporary.path().join("sentinel"), "keep").unwrap();
    assert!(matches!(
        generate_package(
            &bytes,
            expected,
            CertificateLimits::default(),
            &config(),
            temporary.path()
        ),
        Err(CodegenError::TargetExists(_))
    ));
    assert_eq!(
        fs::read_to_string(temporary.path().join("sentinel")).unwrap(),
        "keep"
    );
}

#[test]
fn generation_is_byte_reproducible() {
    let (bytes, expected) = certificate();
    let first = TemporaryDirectory::new("stable-a");
    let second = TemporaryDirectory::new("stable-b");
    generate_package(
        &bytes,
        expected,
        CertificateLimits::default(),
        &config(),
        first.path(),
    )
    .unwrap();
    generate_package(
        &bytes,
        expected,
        CertificateLimits::default(),
        &config(),
        second.path(),
    )
    .unwrap();
    for relative in [
        "Cargo.toml",
        "src/lib.rs",
        "src/vectors.rs",
        "certificate.caqt",
        "codegen-manifest.toml",
        "test-vectors.tsv",
    ] {
        assert_eq!(
            fs::read(first.path().join(relative)).unwrap(),
            fs::read(second.path().join(relative)).unwrap(),
            "generated file differs: {relative}"
        );
    }
}
