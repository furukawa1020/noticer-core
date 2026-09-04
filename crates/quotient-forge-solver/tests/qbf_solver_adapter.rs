use std::fs;
use std::path::PathBuf;

use quotient_forge_solver::{
    classify_qbf_output, BoundedProcessOutput, OutputStream, ProcessLimits, QbfCandidateStatus,
    QbfInstallReceipt, QbfPlatform, QbfSolverAdapter, QbfSolverError, QbfSolverManifest,
    QbfSolverMetadata, QbfSolverResultArtifact, QbfSolverStatus, QdimacsBounds,
    QBF_INSTALL_SCHEMA_V1,
};
use sha2::{Digest, Sha256};

const MANIFEST: &[u8] =
    include_bytes!("../../../configs/quotient_forge/qbf_solver_manifest_v1.json");

#[test]
fn official_source_pin_and_platform_matrix_are_strict() {
    let manifest = QbfSolverManifest::from_slice(MANIFEST).expect("official manifest");
    assert_eq!(manifest.version, "4.0.2");
    assert!(manifest.asset(QbfPlatform::LinuxX86_64).is_some());
    assert!(manifest.asset(QbfPlatform::WindowsX86_64).is_some());
    assert_eq!(manifest.digest_sha256().expect("digest").len(), 64);

    let mut weakened = manifest;
    weakened.security_interpretation = "SOLVER_IS_SECURITY_ORACLE".to_owned();
    assert!(matches!(
        weakened.validate(),
        Err(QbfSolverError::InvalidManifest(_))
    ));
}

#[test]
fn five_results_remain_distinct_and_conflicts_are_malformed() {
    let completed = |stdout: &str| BoundedProcessOutput::Completed {
        stdout: stdout.to_owned(),
        stderr: String::new(),
        success: false,
    };
    assert_eq!(
        classify_qbf_output(&completed("s cnf 1 1 0\n")),
        QbfSolverStatus::Sat
    );
    assert_eq!(
        classify_qbf_output(&completed("s cnf 0\n")),
        QbfSolverStatus::UnsatAtBound
    );
    assert_eq!(
        classify_qbf_output(&completed("UNKNOWN\n")),
        QbfSolverStatus::Unknown
    );
    assert_eq!(
        classify_qbf_output(&BoundedProcessOutput::TimedOut),
        QbfSolverStatus::Timeout
    );
    assert_eq!(
        classify_qbf_output(&BoundedProcessOutput::OutputLimitExceeded {
            stream: OutputStream::Stdout,
        }),
        QbfSolverStatus::Malformed
    );
    assert_eq!(
        classify_qbf_output(&completed("SAT\nUNSAT\n")),
        QbfSolverStatus::Malformed
    );
}

#[test]
fn sat_is_never_accepted_before_the_independent_checker() {
    let run = QbfSolverResultArtifact::from_output(
        metadata(),
        tiny_query(),
        BoundedProcessOutput::Completed {
            stdout: "s cnf 1 1 0\n".to_owned(),
            stderr: String::new(),
            success: false,
        },
    )
    .expect("bounded SAT artifact");
    assert_eq!(run.artifact.result, QbfSolverStatus::Sat);
    assert_eq!(
        run.artifact.candidate_status,
        QbfCandidateStatus::PendingIndependentCheck
    );
    assert!(!run.artifact.candidate_accepted);
    assert!(run.artifact.bounded_only);
}

#[test]
fn binary_is_rehashed_against_the_install_receipt() {
    let manifest = QbfSolverManifest::from_slice(MANIFEST).expect("manifest");
    let root = unique_directory();
    let program = root.join("bin/caqe");
    fs::create_dir_all(program.parent().expect("parent")).expect("create root");
    fs::write(&program, b"pinned-qbf-binary").expect("write binary");
    let receipt_path = root.join("install.json");
    let receipt = QbfInstallReceipt {
        schema_version: QBF_INSTALL_SCHEMA_V1.to_owned(),
        solver: manifest.solver.clone(),
        version: manifest.version.clone(),
        platform: QbfPlatform::LinuxX86_64,
        source_revision: manifest.source_revision.clone(),
        source_sha256: manifest.source_sha256.clone(),
        manifest_sha256: manifest.digest_sha256().expect("manifest digest"),
        binary_sha256: sha256(b"pinned-qbf-binary"),
        executable_path: "bin/caqe".to_owned(),
    };
    fs::write(
        &receipt_path,
        serde_json::to_vec(&receipt).expect("receipt JSON"),
    )
    .expect("write receipt");
    QbfSolverAdapter::from_installation(
        manifest.clone(),
        &root,
        &receipt_path,
        QbfPlatform::LinuxX86_64,
        ProcessLimits::default(),
    )
    .expect("matching binary");

    fs::write(&program, b"tampered").expect("tamper binary");
    assert!(matches!(
        QbfSolverAdapter::from_installation(
            manifest,
            &root,
            &receipt_path,
            QbfPlatform::LinuxX86_64,
            ProcessLimits::default(),
        ),
        Err(QbfSolverError::BinaryHashMismatch)
    ));
    fs::remove_dir_all(root).expect("remove fixture");
}

fn metadata() -> QbfSolverMetadata {
    QbfSolverMetadata {
        solver: "caqe".to_owned(),
        version: "4.0.2".to_owned(),
        platform: "linux-x86_64".to_owned(),
        source_revision: "62ee7692dada5236307f8652234ed7a743651eb7".to_owned(),
        source_sha256: "d09ad720a29eedb27b64182eadd51820b5ac8f30784051f033cdf3972b4e5d37"
            .to_owned(),
        binary_sha256: sha256(b"binary"),
        manifest_sha256: sha256(b"manifest"),
        program: "bin/caqe".to_owned(),
        argv: vec!["--qdo".to_owned(), "query.qdimacs".to_owned()],
        timeout_ms: 1000,
        seed: 7,
        bounds: QdimacsBounds {
            plant_states: 1,
            machine_states: 1,
            horizon: 1,
            action_count: 1,
        },
    }
}

fn tiny_query() -> &'static str {
    "p cnf 2 2\ne 1 0\na 2 0\n1 2 0\n1 -2 0\n"
}

fn unique_directory() -> PathBuf {
    std::env::temp_dir().join(format!("noticer-qbf-adapter-test-{}", std::process::id()))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
