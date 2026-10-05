use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use quotient_forge_caqt::{artifact_digest, Digest};

const MANIFEST_DOMAIN: &[u8] = b"quotient-forge-codegen-manifest-v2";
const MANIFEST_FIELDS: [&str; 19] = [
    "format",
    "package",
    "certificate_version",
    "certificate_digest",
    "spec_hash",
    "plant_hash",
    "quotient_hash",
    "observer_hash",
    "utility_hash",
    "fault_hash",
    "transducer_hash",
    "checker_contract_hash",
    "states",
    "inputs",
    "outputs",
    "quotient_inputs",
    "public_inputs",
    "fault_inputs",
    "output_encoding",
];
const REQUIRED_ARTIFACTS: [&str; 7] = [
    "Cargo.toml",
    "src/lib.rs",
    "src/vectors.rs",
    "certificate.caqt",
    "codegen-manifest.toml",
    "vector-table.csv",
    "wasm-validation.mjs",
];

#[derive(Clone, Copy, Debug)]
pub struct GeneratedArtifact<'a> {
    pub path: &'a str,
    pub bytes: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactValidationLimits {
    pub max_manifest_bytes: usize,
    pub max_artifact_bytes: usize,
    pub max_total_bytes: usize,
}

impl Default for ArtifactValidationLimits {
    fn default() -> Self {
        Self {
            max_manifest_bytes: 65_536,
            max_artifact_bytes: 4 * 1024 * 1024,
            max_total_bytes: 16 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactValidationError {
    ResourceLimit,
    ManifestEncoding,
    ManifestFields,
    ManifestValue,
    UnsafePath,
    DuplicateArtifact,
    ArtifactSet,
    ManifestMismatch,
    DigestMismatch,
}

pub fn validate_generated_artifacts(
    manifest: &[u8],
    expected_manifest_digest: Digest,
    artifacts: &[GeneratedArtifact<'_>],
    limits: ArtifactValidationLimits,
) -> Result<(), ArtifactValidationError> {
    if limits.max_manifest_bytes == 0
        || limits.max_artifact_bytes == 0
        || limits.max_total_bytes == 0
        || manifest.len() > limits.max_manifest_bytes
    {
        return Err(ArtifactValidationError::ResourceLimit);
    }
    validate_manifest(manifest)?;
    if artifact_digest(MANIFEST_DOMAIN, manifest) != expected_manifest_digest {
        return Err(ArtifactValidationError::DigestMismatch);
    }

    let mut seen = BTreeMap::new();
    let mut total = 0_usize;
    for artifact in artifacts {
        if !safe_path(artifact.path) {
            return Err(ArtifactValidationError::UnsafePath);
        }
        if artifact.bytes.len() > limits.max_artifact_bytes {
            return Err(ArtifactValidationError::ResourceLimit);
        }
        total = total
            .checked_add(artifact.bytes.len())
            .ok_or(ArtifactValidationError::ResourceLimit)?;
        if total > limits.max_total_bytes {
            return Err(ArtifactValidationError::ResourceLimit);
        }
        if seen.insert(artifact.path, artifact.bytes).is_some() {
            return Err(ArtifactValidationError::DuplicateArtifact);
        }
    }
    let expected: BTreeSet<_> = REQUIRED_ARTIFACTS.into_iter().collect();
    if seen.keys().copied().collect::<BTreeSet<_>>() != expected {
        return Err(ArtifactValidationError::ArtifactSet);
    }
    if seen.get("codegen-manifest.toml").copied() != Some(manifest) {
        return Err(ArtifactValidationError::ManifestMismatch);
    }
    Ok(())
}

fn validate_manifest(bytes: &[u8]) -> Result<(), ArtifactValidationError> {
    if bytes.is_empty() || bytes.contains(&b'\r') || !bytes.ends_with(b"\n") {
        return Err(ArtifactValidationError::ManifestEncoding);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ArtifactValidationError::ManifestEncoding)?;
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line
            .split_once(" = ")
            .ok_or(ArtifactValidationError::ManifestEncoding)?;
        if fields.insert(key, value).is_some() {
            return Err(ArtifactValidationError::ManifestFields);
        }
    }
    let mut expected: BTreeSet<_> = MANIFEST_FIELDS.into_iter().collect();
    expected.insert("translation_semantics");
    expected.insert("targets");
    if fields.keys().copied().collect::<BTreeSet<_>>() != expected {
        return Err(ArtifactValidationError::ManifestFields);
    }
    if fields["format"] != "\"quotient-forge-codegen-v2\""
        || fields["output_encoding"] != "\"qf-fixed-le-v1\""
        || fields["translation_semantics"] != "\"all-state-input-step-reset-handoff-v1\""
        || fields["targets"] != "[\"native-no-std\", \"wasm32-unknown-unknown\"]"
    {
        return Err(ArtifactValidationError::ManifestValue);
    }
    Ok(())
}

fn safe_path(value: &str) -> bool {
    let path = Path::new(value);
    !value.is_empty()
        && !path.is_absolute()
        && !value.contains('\\')
        && path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}
