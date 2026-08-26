use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

pub const GENERIC_BENCHMARK_SCHEMA: &str = "quotient-seal.generic-benchmark.v1";
pub const GENERIC_BENCHMARK_MAGIC: [u8; 8] = *b"QSBENCH1";
pub const HARDWARE_STATUS: &str = "NOT_VERIFIED";
pub const BENCHMARK_FAMILY_COUNT: usize = 16;
const MAX_REGISTRY_BYTES: usize = 64 * 1024;
const DOMAIN: &[u8] = b"QUOTIENT_SEAL_GENERIC_BENCHMARK_V1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BenchmarkFamilyId {
    PrivateDeadlineAdmission,
    MedicalAlertClass,
    SmartHomeAction,
    PrivateScheduler,
    CredentialRelease,
    FraudReview,
    SafetyInterlock,
    ResourceAdmission,
    ExtraCall,
    PrivateTrap,
    ResourceLeak,
    ExportedMemory,
    ResetLeak,
    StateCorruption,
    DuplicateAction,
    HandoffCarryover,
}

impl BenchmarkFamilyId {
    pub const ALL: [Self; BENCHMARK_FAMILY_COUNT] = [
        Self::PrivateDeadlineAdmission,
        Self::MedicalAlertClass,
        Self::SmartHomeAction,
        Self::PrivateScheduler,
        Self::CredentialRelease,
        Self::FraudReview,
        Self::SafetyInterlock,
        Self::ResourceAdmission,
        Self::ExtraCall,
        Self::PrivateTrap,
        Self::ResourceLeak,
        Self::ExportedMemory,
        Self::ResetLeak,
        Self::StateCorruption,
        Self::DuplicateAction,
        Self::HandoffCarryover,
    ];

    pub const fn kind(self) -> BenchmarkFamilyKind {
        match self {
            Self::PrivateDeadlineAdmission
            | Self::MedicalAlertClass
            | Self::SmartHomeAction
            | Self::PrivateScheduler
            | Self::CredentialRelease
            | Self::FraudReview
            | Self::SafetyInterlock
            | Self::ResourceAdmission => BenchmarkFamilyKind::Valid,
            Self::ExtraCall
            | Self::PrivateTrap
            | Self::ResourceLeak
            | Self::ExportedMemory
            | Self::ResetLeak
            | Self::StateCorruption
            | Self::DuplicateAction
            | Self::HandoffCarryover => BenchmarkFamilyKind::Negative,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BenchmarkFamilyKind {
    Valid,
    Negative,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ActionClass {
    Admit,
    Alert,
    Activate,
    Schedule,
    Release,
    Review,
    Interlock,
    Allocate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PrivatePredicateClass {
    Deadline,
    Threshold,
    Occupancy,
    Priority,
    Authorization,
    Risk,
    Safety,
    Capacity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BenchmarkExpectedVerdict {
    Valid,
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkObserverContract {
    pub api: bool,
    pub control: bool,
    pub instruction: bool,
    pub memory: bool,
    pub resource: bool,
}

impl BenchmarkObserverContract {
    pub const ALL_PUBLIC_SURFACES: Self = Self {
        api: true,
        control: true,
        instruction: true,
        memory: true,
        resource: true,
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkResourceBudget {
    pub max_steps: u32,
    pub max_host_calls: u16,
    pub max_memory_pages: u16,
    pub max_trace_events: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkFamilyContract {
    pub family_id: BenchmarkFamilyId,
    pub family_kind: BenchmarkFamilyKind,
    pub action_class: ActionClass,
    pub private_predicate_class: PrivatePredicateClass,
    pub expected_verdict: BenchmarkExpectedVerdict,
    pub variant_count: u16,
    pub family_seed: u64,
    pub observers: BenchmarkObserverContract,
    pub resource_budget: BenchmarkResourceBudget,
    pub evidence_origin: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkRegistry {
    pub schema: String,
    pub seed: u64,
    pub hardware_status: String,
    pub families: Vec<BenchmarkFamilyContract>,
}

impl BenchmarkRegistry {
    pub fn validate(&self) -> Result<(), BenchmarkInputError> {
        if self.schema != GENERIC_BENCHMARK_SCHEMA {
            return Err(BenchmarkInputError::Schema);
        }
        if self.hardware_status != HARDWARE_STATUS {
            return Err(BenchmarkInputError::HardwareStatus);
        }
        if self.families.len() != BENCHMARK_FAMILY_COUNT {
            return Err(BenchmarkInputError::FamilyCount);
        }
        for (index, family) in self.families.iter().enumerate() {
            let expected_id = BenchmarkFamilyId::ALL[index];
            if family.family_id != expected_id {
                return Err(BenchmarkInputError::FamilyOrder { index });
            }
            if family.family_kind != family.family_id.kind()
                || family.expected_verdict != expected_verdict(family.family_kind)
            {
                return Err(BenchmarkInputError::FamilyKind { index });
            }
            if family.variant_count == 0
                || family.resource_budget.max_steps == 0
                || family.resource_budget.max_trace_events == 0
                || family.evidence_origin != "INJECTED_TEST_FIXTURE"
            {
                return Err(BenchmarkInputError::FamilyContract { index });
            }
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, BenchmarkInputError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| BenchmarkInputError::Json)
    }

    pub fn artifact_sha256(&self) -> Result<[u8; 32], BenchmarkInputError> {
        let json = self.canonical_json()?;
        Ok(hash(&json))
    }

    pub fn encode(&self) -> Result<Vec<u8>, BenchmarkInputError> {
        let json = self.canonical_json()?;
        let length = u32::try_from(json.len()).map_err(|_| BenchmarkInputError::Length)?;
        let digest = hash(&json);
        let mut encoded = Vec::with_capacity(8 + 4 + json.len() + 32);
        encoded.extend_from_slice(&GENERIC_BENCHMARK_MAGIC);
        encoded.extend_from_slice(&length.to_be_bytes());
        encoded.extend_from_slice(&json);
        encoded.extend_from_slice(&digest);
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, BenchmarkInputError> {
        if encoded.len() < 44 || encoded[..8] != GENERIC_BENCHMARK_MAGIC {
            return Err(BenchmarkInputError::Envelope);
        }
        let json_length = u32::from_be_bytes(
            encoded[8..12]
                .try_into()
                .map_err(|_| BenchmarkInputError::Envelope)?,
        ) as usize;
        if json_length > MAX_REGISTRY_BYTES || encoded.len() != 12 + json_length + 32 {
            return Err(BenchmarkInputError::Length);
        }
        let json = &encoded[12..12 + json_length];
        let expected_digest = hash(json);
        if encoded[12 + json_length..] != expected_digest {
            return Err(BenchmarkInputError::Digest);
        }
        let registry: Self = serde_json::from_slice(json).map_err(|_| BenchmarkInputError::Json)?;
        registry.validate()?;
        if registry.canonical_json()? != json {
            return Err(BenchmarkInputError::NonCanonical);
        }
        Ok(registry)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvaluatorKind {
    Baseline,
    FullQuotientSeal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkCaseInput {
    pub family_id: BenchmarkFamilyId,
    pub variant_id: u16,
    pub seed: u64,
    pub public_input_sha256: [u8; 32],
    pub source_artifact_sha256: [u8; 32],
}

impl BenchmarkCaseInput {
    pub fn validate(&self, registry: &BenchmarkRegistry) -> Result<(), BenchmarkInputError> {
        registry.validate()?;
        let contract = registry
            .families
            .iter()
            .find(|family| family.family_id == self.family_id)
            .ok_or(BenchmarkInputError::UnknownFamily)?;
        if self.variant_id >= contract.variant_count
            || self.public_input_sha256 == [0; 32]
            || self.source_artifact_sha256 == [0; 32]
        {
            return Err(BenchmarkInputError::CaseInput);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BenchmarkInconclusiveReason {
    Unsupported,
    ResourceBound,
    EngineDisagreement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "verdict",
    content = "reason",
    rename_all = "SCREAMING_SNAKE_CASE"
)]
pub enum BenchmarkOutcome {
    Valid,
    Invalid,
    Inconclusive(BenchmarkInconclusiveReason),
}

impl BenchmarkOutcome {
    pub const fn is_conclusive(self) -> bool {
        matches!(self, Self::Valid | Self::Invalid)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BenchmarkInputError {
    #[error("benchmark registry schema mismatch")]
    Schema,
    #[error("hardware status must remain NOT_VERIFIED")]
    HardwareStatus,
    #[error("benchmark registry must contain exactly 16 families")]
    FamilyCount,
    #[error("family at index {index} violates canonical ordering")]
    FamilyOrder { index: usize },
    #[error("family at index {index} has inconsistent kind or verdict")]
    FamilyKind { index: usize },
    #[error("family at index {index} has an invalid contract")]
    FamilyContract { index: usize },
    #[error("unknown benchmark family")]
    UnknownFamily,
    #[error("benchmark case input is invalid")]
    CaseInput,
    #[error("benchmark envelope is malformed")]
    Envelope,
    #[error("benchmark envelope length is invalid")]
    Length,
    #[error("benchmark registry digest mismatch")]
    Digest,
    #[error("benchmark registry JSON is invalid")]
    Json,
    #[error("benchmark registry JSON is not canonical")]
    NonCanonical,
}

pub fn frozen_registry(seed: u64) -> BenchmarkRegistry {
    let actions = [
        ActionClass::Admit,
        ActionClass::Alert,
        ActionClass::Activate,
        ActionClass::Schedule,
        ActionClass::Release,
        ActionClass::Review,
        ActionClass::Interlock,
        ActionClass::Allocate,
    ];
    let predicates = [
        PrivatePredicateClass::Deadline,
        PrivatePredicateClass::Threshold,
        PrivatePredicateClass::Occupancy,
        PrivatePredicateClass::Priority,
        PrivatePredicateClass::Authorization,
        PrivatePredicateClass::Risk,
        PrivatePredicateClass::Safety,
        PrivatePredicateClass::Capacity,
    ];
    let families = BenchmarkFamilyId::ALL
        .iter()
        .enumerate()
        .map(|(index, family_id)| {
            let semantic_index = index % 8;
            let family_kind = family_id.kind();
            BenchmarkFamilyContract {
                family_id: *family_id,
                family_kind,
                action_class: actions[semantic_index],
                private_predicate_class: predicates[semantic_index],
                expected_verdict: expected_verdict(family_kind),
                variant_count: 4,
                family_seed: derive_seed(seed, index as u64),
                observers: BenchmarkObserverContract::ALL_PUBLIC_SURFACES,
                resource_budget: BenchmarkResourceBudget {
                    max_steps: 1_024,
                    max_host_calls: 32,
                    max_memory_pages: 2,
                    max_trace_events: 2_048,
                },
                evidence_origin: "INJECTED_TEST_FIXTURE".to_owned(),
            }
        })
        .collect();
    BenchmarkRegistry {
        schema: GENERIC_BENCHMARK_SCHEMA.to_owned(),
        seed,
        hardware_status: HARDWARE_STATUS.to_owned(),
        families,
    }
}

const fn expected_verdict(kind: BenchmarkFamilyKind) -> BenchmarkExpectedVerdict {
    match kind {
        BenchmarkFamilyKind::Valid => BenchmarkExpectedVerdict::Valid,
        BenchmarkFamilyKind::Negative => BenchmarkExpectedVerdict::Invalid,
    }
}

fn derive_seed(seed: u64, index: u64) -> u64 {
    seed.rotate_left((index as u32) & 31) ^ index.wrapping_mul(0x9e37_79b9_7f4a_7c15)
}

fn hash(json: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(json);
    hasher.finalize().into()
}
