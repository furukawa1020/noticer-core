use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::path::{Path, PathBuf};
use thiserror::Error;

use crate::{
    build_family_split, evaluate_held_out_comparison, frozen_registry, generate_negative_families,
    generate_valid_families, BenchmarkComparisonArtifact, BenchmarkComparisonError,
    BenchmarkGateVerdict, BenchmarkInputError, BenchmarkRegistry, FamilySplitPlan,
    NegativeFamilyError, NegativeFamilyFixture, ValidFamilyError, ValidFamilyFixture,
    HARDWARE_STATUS, NEGATIVE_FAMILY_COUNT, VALID_FAMILY_COUNT,
};

pub const GENERIC_BENCHMARK_REPRODUCTION_SCHEMA: &str =
    "quotient-seal.generic-benchmark-reproduction.v1";
pub const GENERIC_BENCHMARK_REPRODUCTION_COMMAND: &str = "cargo run -p quotient-seal-benchmark --example generic_benchmark_reproduction -- --output artifacts/generic_benchmark";
const DOMAIN: &[u8] = b"QUOTIENT_SEAL_GENERIC_BENCHMARK_REPRODUCTION_V1";
const REGISTRY_SEED_TAG: u64 = 0x5245_4749_5354_5259;
const SPLIT_SEED_TAG: u64 = 0x5350_4c49_545f_5631;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericBenchmarkReproductionInputs {
    pub source_tree_sha256: [u8; 32],
    pub config_sha256: [u8; 32],
    pub master_seed: u64,
    pub registry: BenchmarkRegistry,
    pub valid_families: [ValidFamilyFixture; VALID_FAMILY_COUNT],
    pub negative_families: [NegativeFamilyFixture; NEGATIVE_FAMILY_COUNT],
    pub split_plan: FamilySplitPlan,
    pub comparison: BenchmarkComparisonArtifact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenericBenchmarkComponentDigests {
    pub registry_sha256: [u8; 32],
    pub valid_family_sha256: [[u8; 32]; VALID_FAMILY_COUNT],
    pub negative_family_sha256: [[u8; 32]; NEGATIVE_FAMILY_COUNT],
    pub split_plan_sha256: [u8; 32],
    pub comparison_sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenericBenchmarkMachineSummary {
    pub schema: String,
    pub artifact_sha256: [u8; 32],
    pub master_seed: u64,
    pub family_count: u32,
    pub valid_family_count: u32,
    pub negative_family_count: u32,
    pub case_count: u32,
    pub held_out_case_count: u32,
    pub baseline_negative_escaped: u32,
    pub full_negative_escaped: u32,
    pub full_inconclusive: u32,
    pub gate_verdict: BenchmarkGateVerdict,
    pub evidence_origin: String,
    pub hardware_status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenericBenchmarkReproductionBundle {
    pub schema: String,
    pub reproduction_command: String,
    pub source_tree_sha256: [u8; 32],
    pub config_sha256: [u8; 32],
    pub master_seed: u64,
    pub registry: BenchmarkRegistry,
    pub valid_families: [ValidFamilyFixture; VALID_FAMILY_COUNT],
    pub negative_families: [NegativeFamilyFixture; NEGATIVE_FAMILY_COUNT],
    pub split_plan: FamilySplitPlan,
    pub comparison: BenchmarkComparisonArtifact,
    pub component_digests: GenericBenchmarkComponentDigests,
    pub evidence_origin: String,
    pub hardware_status: String,
    pub artifact_sha256: [u8; 32],
}

impl GenericBenchmarkReproductionBundle {
    pub fn build(
        inputs: GenericBenchmarkReproductionInputs,
    ) -> Result<Self, GenericBenchmarkReproductionError> {
        validate_inputs(&inputs)?;
        let component_digests = component_digests(&inputs)?;
        let mut bundle = Self {
            schema: GENERIC_BENCHMARK_REPRODUCTION_SCHEMA.to_owned(),
            reproduction_command: GENERIC_BENCHMARK_REPRODUCTION_COMMAND.to_owned(),
            source_tree_sha256: inputs.source_tree_sha256,
            config_sha256: inputs.config_sha256,
            master_seed: inputs.master_seed,
            registry: inputs.registry,
            valid_families: inputs.valid_families,
            negative_families: inputs.negative_families,
            split_plan: inputs.split_plan,
            comparison: inputs.comparison,
            component_digests,
            evidence_origin: "INJECTED_TEST_FIXTURE".to_owned(),
            hardware_status: HARDWARE_STATUS.to_owned(),
            artifact_sha256: [0; 32],
        };
        bundle.artifact_sha256 = bundle.recomputed_sha256()?;
        Ok(bundle)
    }

    pub fn inputs(&self) -> GenericBenchmarkReproductionInputs {
        GenericBenchmarkReproductionInputs {
            source_tree_sha256: self.source_tree_sha256,
            config_sha256: self.config_sha256,
            master_seed: self.master_seed,
            registry: self.registry.clone(),
            valid_families: self.valid_families.clone(),
            negative_families: self.negative_families.clone(),
            split_plan: self.split_plan.clone(),
            comparison: self.comparison.clone(),
        }
    }

    pub fn verify_internal_recomputation(&self) -> Result<(), GenericBenchmarkReproductionError> {
        self.verify_complete_recomputation(&self.inputs())
    }

    pub fn verify_complete_recomputation(
        &self,
        expected_inputs: &GenericBenchmarkReproductionInputs,
    ) -> Result<(), GenericBenchmarkReproductionError> {
        let expected = Self::build(expected_inputs.clone())?;
        if self != &expected || self.canonical_json()? != expected.canonical_json()? {
            return Err(GenericBenchmarkReproductionError::ArtifactMismatch);
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, GenericBenchmarkReproductionError> {
        serde_json::to_vec(self).map_err(|_| GenericBenchmarkReproductionError::Json)
    }

    pub fn recomputed_sha256(&self) -> Result<[u8; 32], GenericBenchmarkReproductionError> {
        let mut value = self.clone();
        value.artifact_sha256 = [0; 32];
        let encoded =
            serde_json::to_vec(&value).map_err(|_| GenericBenchmarkReproductionError::Json)?;
        Ok(domain_hash(DOMAIN, &encoded))
    }

    pub fn machine_summary(&self) -> GenericBenchmarkMachineSummary {
        GenericBenchmarkMachineSummary {
            schema: self.schema.clone(),
            artifact_sha256: self.artifact_sha256,
            master_seed: self.master_seed,
            family_count: 16,
            valid_family_count: VALID_FAMILY_COUNT as u32,
            negative_family_count: NEGATIVE_FAMILY_COUNT as u32,
            case_count: self.comparison.summary.case_count,
            held_out_case_count: self.comparison.summary.held_out_case_count,
            baseline_negative_escaped: self.comparison.summary.baseline_negative_escaped,
            full_negative_escaped: self.comparison.summary.full_negative_escaped,
            full_inconclusive: self.comparison.summary.full_inconclusive,
            gate_verdict: self.comparison.summary.gate_verdict,
            evidence_origin: self.evidence_origin.clone(),
            hardware_status: self.hardware_status.clone(),
        }
    }

    pub fn machine_summary_json(&self) -> Result<Vec<u8>, GenericBenchmarkReproductionError> {
        serde_json::to_vec(&self.machine_summary())
            .map_err(|_| GenericBenchmarkReproductionError::Json)
    }

    pub fn write_artifacts(&self, output_directory: &Path) -> std::io::Result<(PathBuf, PathBuf)> {
        std::fs::create_dir_all(output_directory)?;
        let bundle_path = output_directory.join("generic_benchmark_bundle.json");
        let summary_path = output_directory.join("generic_benchmark_summary.json");
        let bundle = self
            .canonical_json()
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let summary = self
            .machine_summary_json()
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        std::fs::write(&bundle_path, bundle)?;
        std::fs::write(&summary_path, summary)?;
        Ok((bundle_path, summary_path))
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GenericBenchmarkReproductionError {
    #[error("source tree or config digest is missing")]
    MissingBinding,
    #[error("master seed does not bind registry or split seed")]
    SeedBinding,
    #[error("registry is invalid: {0}")]
    Registry(BenchmarkInputError),
    #[error("valid fixture is invalid: {0}")]
    Valid(ValidFamilyError),
    #[error("negative fixture is invalid: {0}")]
    Negative(NegativeFamilyError),
    #[error("comparison is invalid: {0}")]
    Comparison(BenchmarkComparisonError),
    #[error("valid fixtures differ from full regeneration")]
    ValidFixtureMismatch,
    #[error("negative fixtures differ from full regeneration")]
    NegativeFixtureMismatch,
    #[error("split plan differs from full regeneration")]
    SplitMismatch,
    #[error("comparison differs from full regeneration")]
    ComparisonMismatch,
    #[error("canonical JSON encoding failed")]
    Json,
    #[error("reproduction bundle differs from full recomputation")]
    ArtifactMismatch,
}

impl From<BenchmarkInputError> for GenericBenchmarkReproductionError {
    fn from(error: BenchmarkInputError) -> Self {
        Self::Registry(error)
    }
}

impl From<ValidFamilyError> for GenericBenchmarkReproductionError {
    fn from(error: ValidFamilyError) -> Self {
        Self::Valid(error)
    }
}

impl From<NegativeFamilyError> for GenericBenchmarkReproductionError {
    fn from(error: NegativeFamilyError) -> Self {
        Self::Negative(error)
    }
}

impl From<BenchmarkComparisonError> for GenericBenchmarkReproductionError {
    fn from(error: BenchmarkComparisonError) -> Self {
        Self::Comparison(error)
    }
}

pub fn injected_benchmark_reproduction_inputs(
) -> Result<GenericBenchmarkReproductionInputs, GenericBenchmarkReproductionError> {
    let master_seed = 0x4745_4e45_5249_4356;
    let registry = frozen_registry(derive_seed(master_seed, REGISTRY_SEED_TAG));
    let valid_families = generate_valid_families(&registry)?;
    let negative_families = generate_negative_families(&registry, &valid_families)?;
    let split_plan = build_family_split(derive_seed(master_seed, SPLIT_SEED_TAG));
    let comparison =
        evaluate_held_out_comparison(&registry, &valid_families, &negative_families, &split_plan)?;
    Ok(GenericBenchmarkReproductionInputs {
        source_tree_sha256: [0x51; 32],
        config_sha256: [0x52; 32],
        master_seed,
        registry,
        valid_families,
        negative_families,
        split_plan,
        comparison,
    })
}

fn validate_inputs(
    inputs: &GenericBenchmarkReproductionInputs,
) -> Result<(), GenericBenchmarkReproductionError> {
    if inputs.source_tree_sha256 == [0; 32] || inputs.config_sha256 == [0; 32] {
        return Err(GenericBenchmarkReproductionError::MissingBinding);
    }
    inputs.registry.validate()?;
    if inputs.registry.seed != derive_seed(inputs.master_seed, REGISTRY_SEED_TAG)
        || inputs.split_plan.seed != derive_seed(inputs.master_seed, SPLIT_SEED_TAG)
    {
        return Err(GenericBenchmarkReproductionError::SeedBinding);
    }
    let expected_valid = generate_valid_families(&inputs.registry)?;
    if inputs.valid_families != expected_valid {
        return Err(GenericBenchmarkReproductionError::ValidFixtureMismatch);
    }
    let expected_negative = generate_negative_families(&inputs.registry, &expected_valid)?;
    if inputs.negative_families != expected_negative {
        return Err(GenericBenchmarkReproductionError::NegativeFixtureMismatch);
    }
    let expected_split = build_family_split(derive_seed(inputs.master_seed, SPLIT_SEED_TAG));
    if inputs.split_plan != expected_split {
        return Err(GenericBenchmarkReproductionError::SplitMismatch);
    }
    let expected_comparison = evaluate_held_out_comparison(
        &inputs.registry,
        &expected_valid,
        &expected_negative,
        &expected_split,
    )?;
    if inputs.comparison != expected_comparison {
        return Err(GenericBenchmarkReproductionError::ComparisonMismatch);
    }
    Ok(())
}

fn component_digests(
    inputs: &GenericBenchmarkReproductionInputs,
) -> Result<GenericBenchmarkComponentDigests, GenericBenchmarkReproductionError> {
    let registry_sha256 = inputs.registry.artifact_sha256()?;
    let valid_family_sha256 = inputs
        .valid_families
        .iter()
        .map(ValidFamilyFixture::artifact_sha256)
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| GenericBenchmarkReproductionError::ValidFixtureMismatch)?;
    let negative_family_sha256 = inputs
        .negative_families
        .iter()
        .map(NegativeFamilyFixture::artifact_sha256)
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| GenericBenchmarkReproductionError::NegativeFixtureMismatch)?;
    Ok(GenericBenchmarkComponentDigests {
        registry_sha256,
        valid_family_sha256,
        negative_family_sha256,
        split_plan_sha256: inputs.split_plan.artifact_sha256,
        comparison_sha256: inputs.comparison.artifact_sha256,
    })
}

fn derive_seed(master: u64, tag: u64) -> u64 {
    master.rotate_left(17) ^ tag.wrapping_mul(0x9e37_79b9_7f4a_7c15)
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}
