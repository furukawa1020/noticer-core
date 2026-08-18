use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    mutate_wasm, validate_wasm_container, DatasetSplit, MutationArtifact, MutationEdit,
    MutationFamily, MutationOperator, SplitContract, SplitError, ALL_MUTATION_OPERATORS,
};

pub const MUTATION_CAMPAIGN_VERSION: &str = "quotient-seal-mutation-campaign/v1";
pub const HARDWARE_STATUS: &str = "NOT_VERIFIED";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MutationVerdict {
    Killed,
    Escaped,
    Inconclusive,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evaluation {
    pub verdict: MutationVerdict,
    pub reason_code: String,
    pub detail: String,
}

impl Evaluation {
    #[must_use]
    pub fn killed(reason_code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            verdict: MutationVerdict::Killed,
            reason_code: reason_code.into(),
            detail: detail.into(),
        }
    }

    #[must_use]
    pub fn escaped(reason_code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            verdict: MutationVerdict::Escaped,
            reason_code: reason_code.into(),
            detail: detail.into(),
        }
    }

    #[must_use]
    pub fn inconclusive(reason_code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            verdict: MutationVerdict::Inconclusive,
            reason_code: reason_code.into(),
            detail: detail.into(),
        }
    }
}

pub trait MutantEvaluator {
    fn evaluator_id(&self) -> &str;

    fn evaluate(&self, artifact_path: &Path, artifact: &MutationArtifact) -> Evaluation;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct InconclusiveEvaluator;

impl MutantEvaluator for InconclusiveEvaluator {
    fn evaluator_id(&self) -> &str {
        "checker-not-configured/v1"
    }

    fn evaluate(&self, _artifact_path: &Path, _artifact: &MutationArtifact) -> Evaluation {
        Evaluation::inconclusive(
            "checker_not_configured",
            "artifact generated but no independent checker was configured",
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CampaignRequest {
    pub seed_path: PathBuf,
    pub module_family: String,
    pub compiler_configuration: String,
    pub output_root: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutantRecord {
    pub operator: MutationOperator,
    pub family: MutationFamily,
    pub artifact_path: Option<String>,
    pub record_path: String,
    pub seed_sha256: String,
    pub mutant_sha256: Option<String>,
    pub edits: Vec<MutationEdit>,
    pub evaluation: Evaluation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignManifest {
    pub schema_version: String,
    pub campaign_id: String,
    pub split: DatasetSplit,
    pub module_family: String,
    pub compiler_configuration: String,
    pub evaluator_id: String,
    pub seed_path: String,
    pub seed_sha256: String,
    pub taxonomy_size: usize,
    pub mutants: Vec<MutantRecord>,
    pub hardware_status: String,
}

pub fn run_campaign<E: MutantEvaluator + ?Sized>(
    split_contract: &SplitContract,
    request: &CampaignRequest,
    evaluator: &E,
) -> Result<CampaignManifest, CampaignError> {
    split_contract.validate().map_err(CampaignError::Split)?;
    let split = split_contract
        .classify(&request.module_family, &request.compiler_configuration)
        .map_err(CampaignError::Split)?;
    let seed = fs::read(&request.seed_path).map_err(|source| CampaignError::ReadSeed {
        path: request.seed_path.clone(),
        source,
    })?;
    validate_wasm_container(&seed).map_err(CampaignError::InvalidSeed)?;
    let seed_sha256 = sha256(&seed);
    let campaign_id = campaign_id(
        split_contract,
        split,
        &request.module_family,
        &request.compiler_configuration,
        evaluator.evaluator_id(),
        &seed_sha256,
    )?;
    let campaign_dir = request.output_root.join(&campaign_id);
    let split_dir = split.as_str();
    let mut mutants = Vec::with_capacity(ALL_MUTATION_OPERATORS.len());

    for operator in ALL_MUTATION_OPERATORS {
        let artifact_relative = format!("{split_dir}/{}.wasm", operator.id());
        let record_relative = format!("{split_dir}/{}.json", operator.id());
        let artifact_path = campaign_dir.join(path_from_portable(&artifact_relative));
        let record = match mutate_wasm(&seed, operator) {
            Ok(artifact) => {
                write_equal(&artifact_path, &artifact.bytes)?;
                let evaluation = evaluator.evaluate(&artifact_path, &artifact);
                MutantRecord {
                    operator,
                    family: operator.family(),
                    artifact_path: Some(artifact_relative),
                    record_path: record_relative.clone(),
                    seed_sha256: artifact.seed_sha256,
                    mutant_sha256: Some(artifact.mutant_sha256),
                    edits: artifact.edits,
                    evaluation,
                }
            }
            Err(error) => MutantRecord {
                operator,
                family: operator.family(),
                artifact_path: None,
                record_path: record_relative.clone(),
                seed_sha256: seed_sha256.clone(),
                mutant_sha256: None,
                edits: Vec::new(),
                evaluation: Evaluation::inconclusive("mutation_not_applicable", error.to_string()),
            },
        };
        let record_bytes = serde_json::to_vec_pretty(&record).map_err(CampaignError::Serialize)?;
        write_equal(
            &campaign_dir.join(path_from_portable(&record_relative)),
            &record_bytes,
        )?;
        mutants.push(record);
    }

    let manifest = CampaignManifest {
        schema_version: MUTATION_CAMPAIGN_VERSION.to_owned(),
        campaign_id,
        split,
        module_family: request.module_family.clone(),
        compiler_configuration: request.compiler_configuration.clone(),
        evaluator_id: evaluator.evaluator_id().to_owned(),
        seed_path: portable_path(&request.seed_path),
        seed_sha256,
        taxonomy_size: ALL_MUTATION_OPERATORS.len(),
        mutants,
        hardware_status: HARDWARE_STATUS.to_owned(),
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).map_err(CampaignError::Serialize)?;
    write_equal(&campaign_dir.join("manifest.json"), &manifest_bytes)?;
    Ok(manifest)
}

fn campaign_id(
    contract: &SplitContract,
    split: DatasetSplit,
    module_family: &str,
    compiler_configuration: &str,
    evaluator_id: &str,
    seed_sha256: &str,
) -> Result<String, CampaignError> {
    let mut hasher = Sha256::new();
    hasher.update(MUTATION_CAMPAIGN_VERSION.as_bytes());
    hasher.update([0]);
    hasher.update(serde_json::to_vec(contract).map_err(CampaignError::Serialize)?);
    for value in [
        split.as_str(),
        module_family,
        compiler_configuration,
        evaluator_id,
        seed_sha256,
    ] {
        hasher.update([0]);
        hasher.update(value.as_bytes());
    }
    let digest = format!("{:x}", hasher.finalize());
    Ok(format!("campaign-{}", &digest[..20]))
}

fn write_equal(path: &Path, bytes: &[u8]) -> Result<(), CampaignError> {
    if path.exists() {
        let existing = fs::read(path).map_err(|source| CampaignError::ReadArtifact {
            path: path.to_path_buf(),
            source,
        })?;
        if existing == bytes {
            return Ok(());
        }
        return Err(CampaignError::ArtifactCollision(path.to_path_buf()));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| CampaignError::WriteArtifact {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    fs::write(path, bytes).map_err(|source| CampaignError::WriteArtifact {
        path: path.to_path_buf(),
        source,
    })
}

fn portable_path(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn path_from_portable(path: &str) -> PathBuf {
    path.split('/').collect()
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[derive(Debug, Error)]
pub enum CampaignError {
    #[error("invalid split contract: {0}")]
    Split(SplitError),
    #[error("failed to read seed at {path}: {source}")]
    ReadSeed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("seed is not a supported WASM container: {0}")]
    InvalidSeed(crate::MutationError),
    #[error("failed to serialize campaign artifact: {0}")]
    Serialize(serde_json::Error),
    #[error("failed to read existing artifact at {path}: {source}")]
    ReadArtifact {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write artifact at {path}: {source}")]
    WriteArtifact {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("existing artifact differs from deterministic output: {0}")]
    ArtifactCollision(PathBuf),
}
