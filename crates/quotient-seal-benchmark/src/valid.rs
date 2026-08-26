use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    ActionClass, BenchmarkCaseInput, BenchmarkFamilyId, BenchmarkFamilyKind, BenchmarkInputError,
    BenchmarkRegistry, HARDWARE_STATUS,
};

pub const VALID_FAMILY_COUNT: usize = 8;
pub const VALID_VARIANTS_PER_FAMILY: usize = 4;
const VALID_DOMAIN: &[u8] = b"QUOTIENT_SEAL_GENERIC_VALID_FAMILY_V1";
const RECEIPT_DOMAIN: &[u8] = b"QUOTIENT_SEAL_GENERIC_VALID_RECEIPT_V1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValidSourceOp {
    EvaluatePrivatePredicate,
    ProjectActionSemantics,
    EmitConstantRateSlot,
    ResetPublicState,
    HandoffPublicState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidVariant {
    pub input: BenchmarkCaseInput,
    pub expected_action: bool,
    pub reset_epoch: u32,
    pub handoff_service: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidFamilyFixture {
    pub family_id: BenchmarkFamilyId,
    pub action_class: ActionClass,
    pub family_seed: u64,
    pub source_program: Vec<ValidSourceOp>,
    pub source_artifact_sha256: [u8; 32],
    pub variants: Vec<ValidVariant>,
    pub evidence_origin: String,
    pub hardware_status: String,
}

impl ValidFamilyFixture {
    pub fn canonical_json(&self) -> Result<Vec<u8>, ValidFamilyError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| ValidFamilyError::Json)
    }

    pub fn artifact_sha256(&self) -> Result<[u8; 32], ValidFamilyError> {
        Ok(domain_hash(VALID_DOMAIN, &self.canonical_json()?))
    }

    pub fn validate(&self) -> Result<(), ValidFamilyError> {
        if self.family_id.kind() != BenchmarkFamilyKind::Valid {
            return Err(ValidFamilyError::NotValidFamily);
        }
        if self.source_program != canonical_program()
            || self.source_artifact_sha256 == [0; 32]
            || self.variants.len() != VALID_VARIANTS_PER_FAMILY
            || self.evidence_origin != "INJECTED_TEST_FIXTURE"
            || self.hardware_status != HARDWARE_STATUS
        {
            return Err(ValidFamilyError::FixtureContract);
        }
        for (index, variant) in self.variants.iter().enumerate() {
            if variant.input.family_id != self.family_id
                || usize::from(variant.input.variant_id) != index
                || variant.input.source_artifact_sha256 != self.source_artifact_sha256
                || variant.reset_epoch != index as u32
                || variant.handoff_service != 100 + index as u16
            {
                return Err(ValidFamilyError::VariantContract { index });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyntheticPrivateHistory {
    pub synthetic_bucket: u16,
    pub allowed_action: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", content = "value", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValidPublicEvent {
    Tick(u16),
    DecisionSlot,
    Action(ActionClass),
    Cover,
    ResetAck(u32),
    HandoffAck(u16),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidExecutionReceipt {
    pub family_id: BenchmarkFamilyId,
    pub variant_id: u16,
    pub seed: u64,
    pub source_artifact_sha256: [u8; 32],
    pub action_released: bool,
    pub public_trace: Vec<ValidPublicEvent>,
    pub final_public_state_sha256: [u8; 32],
    pub action_count: u32,
    pub reset_count: u32,
    pub handoff_count: u32,
    pub evidence_origin: String,
    pub hardware_status: String,
    pub receipt_sha256: [u8; 32],
}

impl ValidExecutionReceipt {
    pub fn canonical_json(&self) -> Result<Vec<u8>, ValidFamilyError> {
        let mut value = self.clone();
        value.receipt_sha256 = [0; 32];
        serde_json::to_vec(&value).map_err(|_| ValidFamilyError::Json)
    }

    pub fn recomputed_sha256(&self) -> Result<[u8; 32], ValidFamilyError> {
        Ok(domain_hash(RECEIPT_DOMAIN, &self.canonical_json()?))
    }

    pub fn verify(&self, fixture: &ValidFamilyFixture) -> Result<(), ValidFamilyError> {
        let expected = execute_valid_family(
            fixture,
            self.variant_id,
            SyntheticPrivateHistory {
                synthetic_bucket: 0,
                allowed_action: self.action_released,
            },
        )?;
        if self != &expected {
            return Err(ValidFamilyError::ReceiptMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ValidFamilyError {
    #[error("registry contract is invalid: {0}")]
    Registry(BenchmarkInputError),
    #[error("requested family is not a valid family")]
    NotValidFamily,
    #[error("valid family fixture violates the frozen contract")]
    FixtureContract,
    #[error("variant at index {index} violates the frozen contract")]
    VariantContract { index: usize },
    #[error("variant ID is not present")]
    UnknownVariant,
    #[error("synthetic history does not have the variant's allowed action semantics")]
    ActionSemanticsMismatch,
    #[error("valid family JSON encoding failed")]
    Json,
    #[error("valid receipt failed complete recomputation")]
    ReceiptMismatch,
}

impl From<BenchmarkInputError> for ValidFamilyError {
    fn from(error: BenchmarkInputError) -> Self {
        Self::Registry(error)
    }
}

pub fn generate_valid_families(
    registry: &BenchmarkRegistry,
) -> Result<[ValidFamilyFixture; VALID_FAMILY_COUNT], ValidFamilyError> {
    registry.validate()?;
    let fixtures = registry
        .families
        .iter()
        .filter(|family| family.family_kind == BenchmarkFamilyKind::Valid)
        .map(|family| {
            let source_program = canonical_program();
            let source_artifact_sha256 = source_digest(
                family.family_id,
                family.action_class,
                family.family_seed,
                &source_program,
            )?;
            let variants = (0..VALID_VARIANTS_PER_FAMILY)
                .map(|index| ValidVariant {
                    input: BenchmarkCaseInput {
                        family_id: family.family_id,
                        variant_id: index as u16,
                        seed: derive_variant_seed(family.family_seed, index as u64),
                        public_input_sha256: public_input_digest(family.family_id, index as u16),
                        source_artifact_sha256,
                    },
                    expected_action: index % 2 == 0,
                    reset_epoch: index as u32,
                    handoff_service: 100 + index as u16,
                })
                .collect();
            let fixture = ValidFamilyFixture {
                family_id: family.family_id,
                action_class: family.action_class,
                family_seed: family.family_seed,
                source_program,
                source_artifact_sha256,
                variants,
                evidence_origin: "INJECTED_TEST_FIXTURE".to_owned(),
                hardware_status: HARDWARE_STATUS.to_owned(),
            };
            fixture.validate()?;
            Ok(fixture)
        })
        .collect::<Result<Vec<_>, ValidFamilyError>>()?;
    fixtures
        .try_into()
        .map_err(|_| ValidFamilyError::FixtureContract)
}

pub fn execute_valid_family(
    fixture: &ValidFamilyFixture,
    variant_id: u16,
    private_history: SyntheticPrivateHistory,
) -> Result<ValidExecutionReceipt, ValidFamilyError> {
    fixture.validate()?;
    let variant = fixture
        .variants
        .get(usize::from(variant_id))
        .ok_or(ValidFamilyError::UnknownVariant)?;
    if private_history.allowed_action != variant.expected_action {
        return Err(ValidFamilyError::ActionSemanticsMismatch);
    }

    let decision_event = if variant.expected_action {
        ValidPublicEvent::Action(fixture.action_class)
    } else {
        ValidPublicEvent::Cover
    };
    let public_trace = vec![
        ValidPublicEvent::Tick(0),
        ValidPublicEvent::DecisionSlot,
        decision_event,
        ValidPublicEvent::ResetAck(variant.reset_epoch),
        ValidPublicEvent::HandoffAck(variant.handoff_service),
    ];
    let final_public_state_sha256 = public_state_digest(
        fixture.family_id,
        variant_id,
        variant.expected_action,
        variant.reset_epoch,
        variant.handoff_service,
    );
    let mut receipt = ValidExecutionReceipt {
        family_id: fixture.family_id,
        variant_id,
        seed: variant.input.seed,
        source_artifact_sha256: fixture.source_artifact_sha256,
        action_released: variant.expected_action,
        public_trace,
        final_public_state_sha256,
        action_count: u32::from(variant.expected_action),
        reset_count: 1,
        handoff_count: 1,
        evidence_origin: "INJECTED_TEST_FIXTURE".to_owned(),
        hardware_status: HARDWARE_STATUS.to_owned(),
        receipt_sha256: [0; 32],
    };
    receipt.receipt_sha256 = receipt.recomputed_sha256()?;
    Ok(receipt)
}

fn canonical_program() -> Vec<ValidSourceOp> {
    vec![
        ValidSourceOp::EvaluatePrivatePredicate,
        ValidSourceOp::ProjectActionSemantics,
        ValidSourceOp::EmitConstantRateSlot,
        ValidSourceOp::ResetPublicState,
        ValidSourceOp::HandoffPublicState,
    ]
}

fn source_digest(
    family_id: BenchmarkFamilyId,
    action_class: ActionClass,
    family_seed: u64,
    source_program: &[ValidSourceOp],
) -> Result<[u8; 32], ValidFamilyError> {
    let encoded = serde_json::to_vec(&(family_id, action_class, family_seed, source_program))
        .map_err(|_| ValidFamilyError::Json)?;
    Ok(domain_hash(VALID_DOMAIN, &encoded))
}

fn public_input_digest(family_id: BenchmarkFamilyId, variant_id: u16) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(4);
    encoded.push(family_code(family_id));
    encoded.extend_from_slice(&variant_id.to_be_bytes());
    domain_hash(b"QUOTIENT_SEAL_GENERIC_PUBLIC_INPUT_V1", &encoded)
}

fn public_state_digest(
    family_id: BenchmarkFamilyId,
    variant_id: u16,
    action: bool,
    reset_epoch: u32,
    handoff_service: u16,
) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(10);
    encoded.push(family_code(family_id));
    encoded.extend_from_slice(&variant_id.to_be_bytes());
    encoded.push(u8::from(action));
    encoded.extend_from_slice(&reset_epoch.to_be_bytes());
    encoded.extend_from_slice(&handoff_service.to_be_bytes());
    domain_hash(b"QUOTIENT_SEAL_GENERIC_PUBLIC_STATE_V1", &encoded)
}

fn derive_variant_seed(seed: u64, variant: u64) -> u64 {
    seed.rotate_right((variant as u32) & 31) ^ variant.wrapping_mul(0xd6e8_feb8_6659_fd93)
}

fn family_code(family_id: BenchmarkFamilyId) -> u8 {
    BenchmarkFamilyId::ALL
        .iter()
        .position(|candidate| *candidate == family_id)
        .map_or(0, |index| index as u8 + 1)
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}
