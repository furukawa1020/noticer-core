#![forbid(unsafe_code)]

//! Shared fail-closed resource contract for QuotientForge artifact fuzzing.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use thiserror::Error;

pub const CONTRACT_SCHEMA: &str = "noticer.k7.fuzz-resource-contract.v1";
pub const REPORT_SCHEMA: &str = "noticer.k7.fuzz-run-report.v1";
const MAX_CONTRACT_BYTES: u64 = 65_536;
const MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_DEPTH: u32 = 4_096;
const MAX_INTEGER_BITS: u32 = 4_096;
const MAX_COLLECTION_ITEMS: u32 = 1_000_000;
const MAX_STATE_PRODUCT: u64 = 1_000_000_000;
const MAX_EXECUTIONS: u64 = 100_000_000;
const MAX_RUNTIME_MS: u64 = 86_400_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactTarget {
    CanonicalIr,
    Caqt,
    CodegenManifest,
    Dsl,
    Qdimacs,
    Smtlib,
}

impl ArtifactTarget {
    pub const ALL: [Self; 6] = [
        Self::CanonicalIr,
        Self::Caqt,
        Self::CodegenManifest,
        Self::Dsl,
        Self::Qdimacs,
        Self::Smtlib,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetLimits {
    pub max_input_bytes: u64,
    pub max_depth: u32,
    pub max_integer_bits: u32,
    pub max_collection_items: u32,
    pub max_state_product: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FuzzBudget {
    pub max_executions: u64,
    pub max_runtime_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FuzzResourceContract {
    pub schema: String,
    pub target_limits: BTreeMap<ArtifactTarget, TargetLimits>,
    pub budget: FuzzBudget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputShape<'a> {
    pub input_bytes: u64,
    pub depth: u32,
    pub integer_bits: u32,
    pub collection_items: u32,
    pub state_factors: &'a [u64],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RunStatus {
    Completed,
    Counterexample,
    Timeout,
    Failure,
    Disagreement,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FuzzRunReport {
    pub schema: String,
    pub target: ArtifactTarget,
    pub contract_sha256: String,
    pub seed: u64,
    pub runtime_ms: u64,
    pub executions: u64,
    pub coverage_proxy: u64,
    pub status: RunStatus,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FuzzContractError {
    #[error("unsupported fuzz resource contract schema")]
    UnsupportedSchema,
    #[error("fuzz target set is incomplete or noncanonical")]
    TargetSetMismatch,
    #[error("fuzz resource limit is zero or exceeds its hard maximum")]
    InvalidLimit,
    #[error("fuzz contract file exceeds its byte limit")]
    ContractTooLarge,
    #[error("fuzz contract JSON is invalid")]
    InvalidJson,
    #[error("fuzz contract JSON is not canonical")]
    NonCanonicalJson,
    #[error("input byte limit exceeded before parser entry")]
    InputBytesExceeded,
    #[error("input depth limit exceeded before parser entry")]
    DepthExceeded,
    #[error("integer bit limit exceeded before parser entry")]
    IntegerBitsExceeded,
    #[error("collection item limit exceeded before parser entry")]
    CollectionItemsExceeded,
    #[error("state product overflowed or exceeded its limit before parser entry")]
    StateProductExceeded,
    #[error("fuzz run report exceeds the frozen budget")]
    BudgetExceeded,
    #[error("fuzz timeout was incorrectly reported as completed")]
    TimeoutReportedAsSuccess,
    #[error("fuzz run report is internally inconsistent")]
    InvalidReport,
}

impl FuzzResourceContract {
    pub fn validate(&self) -> Result<(), FuzzContractError> {
        if self.schema != CONTRACT_SCHEMA {
            return Err(FuzzContractError::UnsupportedSchema);
        }
        let actual: BTreeSet<_> = self.target_limits.keys().copied().collect();
        let expected: BTreeSet<_> = ArtifactTarget::ALL.into_iter().collect();
        if actual != expected {
            return Err(FuzzContractError::TargetSetMismatch);
        }
        if self.budget.max_executions == 0
            || self.budget.max_executions > MAX_EXECUTIONS
            || self.budget.max_runtime_ms == 0
            || self.budget.max_runtime_ms > MAX_RUNTIME_MS
            || self.target_limits.values().any(|limits| {
                limits.max_input_bytes == 0
                    || limits.max_input_bytes > MAX_INPUT_BYTES
                    || limits.max_depth == 0
                    || limits.max_depth > MAX_DEPTH
                    || limits.max_integer_bits == 0
                    || limits.max_integer_bits > MAX_INTEGER_BITS
                    || limits.max_collection_items == 0
                    || limits.max_collection_items > MAX_COLLECTION_ITEMS
                    || limits.max_state_product == 0
                    || limits.max_state_product > MAX_STATE_PRODUCT
            })
        {
            return Err(FuzzContractError::InvalidLimit);
        }
        Ok(())
    }

    pub fn preflight(
        &self,
        target: ArtifactTarget,
        shape: &InputShape<'_>,
    ) -> Result<(), FuzzContractError> {
        self.validate()?;
        let limits = self
            .target_limits
            .get(&target)
            .ok_or(FuzzContractError::TargetSetMismatch)?;
        if shape.input_bytes > limits.max_input_bytes {
            return Err(FuzzContractError::InputBytesExceeded);
        }
        if shape.depth > limits.max_depth {
            return Err(FuzzContractError::DepthExceeded);
        }
        if shape.integer_bits > limits.max_integer_bits {
            return Err(FuzzContractError::IntegerBitsExceeded);
        }
        if shape.collection_items > limits.max_collection_items {
            return Err(FuzzContractError::CollectionItemsExceeded);
        }
        let product = shape
            .state_factors
            .iter()
            .try_fold(1_u64, |value, factor| value.checked_mul(*factor));
        if product.is_none_or(|value| value > limits.max_state_product) {
            return Err(FuzzContractError::StateProductExceeded);
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, FuzzContractError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| FuzzContractError::InvalidJson)
    }

    pub fn sha256(&self) -> Result<String, FuzzContractError> {
        Ok(hex_digest(&self.canonical_json()?))
    }
}

pub fn load_contract(path: &Path) -> Result<FuzzResourceContract, FuzzContractError> {
    let metadata = std::fs::metadata(path).map_err(|_| FuzzContractError::InvalidJson)?;
    if metadata.len() > MAX_CONTRACT_BYTES {
        return Err(FuzzContractError::ContractTooLarge);
    }
    let bytes = std::fs::read(path).map_err(|_| FuzzContractError::InvalidJson)?;
    let contract: FuzzResourceContract =
        serde_json::from_slice(&bytes).map_err(|_| FuzzContractError::InvalidJson)?;
    let canonical = contract.canonical_json()?;
    if bytes.strip_suffix(b"\n").unwrap_or(&bytes) != canonical {
        return Err(FuzzContractError::NonCanonicalJson);
    }
    Ok(contract)
}

pub fn build_report(
    contract: &FuzzResourceContract,
    target: ArtifactTarget,
    seed: u64,
    runtime_ms: u64,
    executions: u64,
    coverage_proxy: u64,
    status: RunStatus,
) -> Result<FuzzRunReport, FuzzContractError> {
    contract.validate()?;
    if executions > contract.budget.max_executions || coverage_proxy > executions {
        return Err(FuzzContractError::BudgetExceeded);
    }
    if runtime_ms > contract.budget.max_runtime_ms {
        if status == RunStatus::Completed {
            return Err(FuzzContractError::TimeoutReportedAsSuccess);
        }
        if status != RunStatus::Timeout {
            return Err(FuzzContractError::BudgetExceeded);
        }
    }
    Ok(FuzzRunReport {
        schema: REPORT_SCHEMA.to_owned(),
        target,
        contract_sha256: contract.sha256()?,
        seed,
        runtime_ms,
        executions,
        coverage_proxy,
        status,
    })
}

pub fn validate_report(
    contract: &FuzzResourceContract,
    report: &FuzzRunReport,
) -> Result<(), FuzzContractError> {
    let rebuilt = build_report(
        contract,
        report.target,
        report.seed,
        report.runtime_ms,
        report.executions,
        report.coverage_proxy,
        report.status,
    )?;
    if report.schema != REPORT_SCHEMA || *report != rebuilt {
        return Err(FuzzContractError::InvalidReport);
    }
    Ok(())
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
