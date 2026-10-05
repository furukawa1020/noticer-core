use quotient_forge_caqt::artifact_digest;
use quotient_forge_codegen::{
    validate_generated_artifacts, ArtifactValidationError, ArtifactValidationLimits,
    GeneratedArtifact,
};

const DOMAIN: &[u8] = b"quotient-forge-codegen-manifest-v2";

fn manifest() -> Vec<u8> {
    let mut lines = vec![
        "format = \"quotient-forge-codegen-v2\"",
        "package = \"fixture\"",
        "certificate_version = 1",
        "certificate_digest = \"00\"",
        "spec_hash = \"00\"",
        "plant_hash = \"00\"",
        "quotient_hash = \"00\"",
        "observer_hash = \"00\"",
        "utility_hash = \"00\"",
        "fault_hash = \"00\"",
        "transducer_hash = \"00\"",
        "checker_contract_hash = \"00\"",
        "states = 1",
        "inputs = 1",
        "outputs = 1",
        "quotient_inputs = 1",
        "public_inputs = 1",
        "fault_inputs = 1",
        "output_encoding = \"qf-fixed-le-v1\"",
        "translation_semantics = \"all-state-input-step-reset-handoff-v1\"",
        "targets = [\"native-no-std\", \"wasm32-unknown-unknown\"]",
    ];
    lines.push("");
    lines.join("\n").into_bytes()
}

fn validate(manifest: &[u8], paths: &[&str]) -> Result<(), ArtifactValidationError> {
    let blobs: Vec<Vec<u8>> = paths
        .iter()
        .map(|path| {
            if *path == "codegen-manifest.toml" {
                manifest.to_vec()
            } else {
                vec![1]
            }
        })
        .collect();
    let artifacts: Vec<_> = paths
        .iter()
        .zip(&blobs)
        .map(|(path, bytes)| GeneratedArtifact { path, bytes })
        .collect();
    validate_generated_artifacts(
        manifest,
        artifact_digest(DOMAIN, manifest),
        &artifacts,
        ArtifactValidationLimits::default(),
    )
}

#[test]
fn exact_artifact_set_and_manifest_binding_are_accepted() {
    let value = manifest();
    assert_eq!(
        validate(
            &value,
            &[
                "Cargo.toml",
                "src/lib.rs",
                "src/vectors.rs",
                "certificate.caqt",
                "codegen-manifest.toml",
                "vector-table.csv",
                "wasm-validation.mjs"
            ]
        ),
        Ok(())
    );
}

#[test]
fn traversal_duplicate_missing_extra_and_manifest_mutations_fail_closed() {
    let value = manifest();
    for paths in [
        vec!["../Cargo.toml"],
        vec!["Cargo.toml", "Cargo.toml"],
        vec!["Cargo.toml"],
        vec!["Cargo.toml", "extra"],
    ] {
        assert!(validate(&value, &paths).is_err());
    }
    let mut crlf = value.clone();
    crlf.extend_from_slice(b"\r\n");
    assert!(validate(&crlf, &["codegen-manifest.toml"]).is_err());
}

#[test]
fn digest_substitution_and_resource_exhaustion_are_rejected() {
    let value = manifest();
    assert_eq!(
        validate_generated_artifacts(
            &value,
            artifact_digest(b"wrong-domain", &value),
            &[],
            ArtifactValidationLimits::default(),
        ),
        Err(ArtifactValidationError::DigestMismatch)
    );
    let limits = ArtifactValidationLimits {
        max_manifest_bytes: 8,
        ..Default::default()
    };
    assert_eq!(
        validate_generated_artifacts(&value, artifact_digest(DOMAIN, &value), &[], limits),
        Err(ArtifactValidationError::ResourceLimit)
    );
}
