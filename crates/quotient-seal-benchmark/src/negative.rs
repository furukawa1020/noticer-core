use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    BenchmarkCaseInput, BenchmarkExpectedVerdict, BenchmarkFamilyId, BenchmarkFamilyKind,
    BenchmarkInputError, BenchmarkOutcome, BenchmarkRegistry, ValidFamilyError, ValidFamilyFixture,
    HARDWARE_STATUS, VALID_FAMILY_COUNT,
};

pub const NEGATIVE_FAMILY_COUNT: usize = 8;
pub const NEGATIVE_VARIANTS_PER_FAMILY: usize = 4;
const NEGATIVE_DOMAIN: &[u8] = b"QUOTIENT_SEAL_GENERIC_NEGATIVE_FAMILY_V1";
const RECEIPT_DOMAIN: &[u8] = b"QUOTIENT_SEAL_GENERIC_NEGATIVE_RECEIPT_V1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NegativeMutationClass {
    ExtraCall,
    PrivateTrap,
    ResourceLeak,
    ExportedMemory,
    ResetLeak,
    StateCorruption,
    DuplicateAction,
    HandoffCarryover,
}

impl NegativeMutationClass {
    const ALL: [Self; NEGATIVE_FAMILY_COUNT] = [
        Self::ExtraCall,
        Self::PrivateTrap,
        Self::ResourceLeak,
        Self::ExportedMemory,
        Self::ResetLeak,
        Self::StateCorruption,
        Self::DuplicateAction,
        Self::HandoffCarryover,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NegativeObserverSurface {
    Api,
    Control,
    Resource,
    Memory,
    State,
    Handoff,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NegativeDifferenceKind {
    ExtraHostCall,
    PrivateDependentTrap,
    ResourceCountDivergence,
    ExportedLinearMemory,
    ResetStateRetention,
    PublicStateCorruption,
    DuplicatePublicAction,
    PrivateHandoffCarryover,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NegativeDifference {
    pub kind: NegativeDifferenceKind,
    pub surface: NegativeObserverSurface,
    pub step_index: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NegativeVariant {
    pub input: BenchmarkCaseInput,
    pub counterpart_variant_id: u16,
    pub expected_verdict: BenchmarkExpectedVerdict,
    pub expected_difference: NegativeDifference,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NegativeFamilyFixture {
    pub family_id: BenchmarkFamilyId,
    pub mutation_class: NegativeMutationClass,
    pub counterpart_family_id: BenchmarkFamilyId,
    pub counterpart_source_sha256: [u8; 32],
    pub mutated_source_sha256: [u8; 32],
    pub variants: Vec<NegativeVariant>,
    pub evidence_origin: String,
    pub hardware_status: String,
}

impl NegativeFamilyFixture {
    pub fn validate(&self) -> Result<(), NegativeFamilyError> {
        if self.family_id.kind() != BenchmarkFamilyKind::Negative
            || self.counterpart_family_id.kind() != BenchmarkFamilyKind::Valid
        {
            return Err(NegativeFamilyError::FamilyKind);
        }
        if self.counterpart_source_sha256 == [0; 32]
            || self.mutated_source_sha256 == [0; 32]
            || self.counterpart_source_sha256 == self.mutated_source_sha256
            || self.variants.len() != NEGATIVE_VARIANTS_PER_FAMILY
            || self.evidence_origin != "INJECTED_TEST_FIXTURE"
            || self.hardware_status != HARDWARE_STATUS
        {
            return Err(NegativeFamilyError::FixtureContract);
        }
        for (index, variant) in self.variants.iter().enumerate() {
            if variant.input.family_id != self.family_id
                || usize::from(variant.input.variant_id) != index
                || variant.input.source_artifact_sha256 != self.mutated_source_sha256
                || usize::from(variant.counterpart_variant_id) != index
                || variant.expected_verdict != BenchmarkExpectedVerdict::Invalid
                || variant.expected_difference != difference_for(self.mutation_class, index as u32)
            {
                return Err(NegativeFamilyError::VariantContract { index });
            }
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, NegativeFamilyError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| NegativeFamilyError::Json)
    }

    pub fn artifact_sha256(&self) -> Result<[u8; 32], NegativeFamilyError> {
        Ok(domain_hash(NEGATIVE_DOMAIN, &self.canonical_json()?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NegativeExecutionReceipt {
    pub family_id: BenchmarkFamilyId,
    pub mutation_class: NegativeMutationClass,
    pub variant_id: u16,
    pub seed: u64,
    pub counterpart_source_sha256: [u8; 32],
    pub mutated_source_sha256: [u8; 32],
    pub verdict: BenchmarkOutcome,
    pub first_difference: NegativeDifference,
    pub action_count: u32,
    pub host_call_count: u32,
    pub resource_event_count: u32,
    pub trap_count: u32,
    pub evidence_origin: String,
    pub hardware_status: String,
    pub receipt_sha256: [u8; 32],
}

impl NegativeExecutionReceipt {
    pub fn canonical_json(&self) -> Result<Vec<u8>, NegativeFamilyError> {
        let mut value = self.clone();
        value.receipt_sha256 = [0; 32];
        serde_json::to_vec(&value).map_err(|_| NegativeFamilyError::Json)
    }

    pub fn recomputed_sha256(&self) -> Result<[u8; 32], NegativeFamilyError> {
        Ok(domain_hash(RECEIPT_DOMAIN, &self.canonical_json()?))
    }

    pub fn verify(&self, fixture: &NegativeFamilyFixture) -> Result<(), NegativeFamilyError> {
        let expected = execute_negative_family(fixture, self.variant_id)?;
        if self != &expected {
            return Err(NegativeFamilyError::ReceiptMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NegativeFamilyError {
    #[error("registry contract is invalid: {0}")]
    Registry(BenchmarkInputError),
    #[error("valid counterpart fixture is invalid: {0}")]
    ValidCounterpart(ValidFamilyError),
    #[error("negative or counterpart family kind is invalid")]
    FamilyKind,
    #[error("negative family fixture violates the frozen contract")]
    FixtureContract,
    #[error("negative variant at index {index} violates the frozen contract")]
    VariantContract { index: usize },
    #[error("negative variant ID is not present")]
    UnknownVariant,
    #[error("negative family JSON encoding failed")]
    Json,
    #[error("negative receipt failed complete recomputation")]
    ReceiptMismatch,
}

impl From<BenchmarkInputError> for NegativeFamilyError {
    fn from(error: BenchmarkInputError) -> Self {
        Self::Registry(error)
    }
}

impl From<ValidFamilyError> for NegativeFamilyError {
    fn from(error: ValidFamilyError) -> Self {
        Self::ValidCounterpart(error)
    }
}

pub fn generate_negative_families(
    registry: &BenchmarkRegistry,
    valid_fixtures: &[ValidFamilyFixture; VALID_FAMILY_COUNT],
) -> Result<[NegativeFamilyFixture; NEGATIVE_FAMILY_COUNT], NegativeFamilyError> {
    registry.validate()?;
    for fixture in valid_fixtures {
        fixture.validate()?;
    }
    let negative_contracts = registry
        .families
        .iter()
        .filter(|family| family.family_kind == BenchmarkFamilyKind::Negative);
    let fixtures = negative_contracts
        .enumerate()
        .map(|(index, contract)| {
            let counterpart = &valid_fixtures[index];
            let mutation_class = NegativeMutationClass::ALL[index];
            let mutated_source_sha256 = mutated_source_digest(
                counterpart.source_artifact_sha256,
                contract.family_id,
                mutation_class,
            );
            let variants = (0..NEGATIVE_VARIANTS_PER_FAMILY)
                .map(|variant_index| NegativeVariant {
                    input: BenchmarkCaseInput {
                        family_id: contract.family_id,
                        variant_id: variant_index as u16,
                        seed: derive_variant_seed(contract.family_seed, variant_index as u64),
                        public_input_sha256: public_input_digest(
                            contract.family_id,
                            variant_index as u16,
                        ),
                        source_artifact_sha256: mutated_source_sha256,
                    },
                    counterpart_variant_id: variant_index as u16,
                    expected_verdict: BenchmarkExpectedVerdict::Invalid,
                    expected_difference: difference_for(mutation_class, variant_index as u32),
                })
                .collect();
            let fixture = NegativeFamilyFixture {
                family_id: contract.family_id,
                mutation_class,
                counterpart_family_id: counterpart.family_id,
                counterpart_source_sha256: counterpart.source_artifact_sha256,
                mutated_source_sha256,
                variants,
                evidence_origin: "INJECTED_TEST_FIXTURE".to_owned(),
                hardware_status: HARDWARE_STATUS.to_owned(),
            };
            fixture.validate()?;
            Ok(fixture)
        })
        .collect::<Result<Vec<_>, NegativeFamilyError>>()?;
    fixtures
        .try_into()
        .map_err(|_| NegativeFamilyError::FixtureContract)
}

pub fn execute_negative_family(
    fixture: &NegativeFamilyFixture,
    variant_id: u16,
) -> Result<NegativeExecutionReceipt, NegativeFamilyError> {
    fixture.validate()?;
    let variant = fixture
        .variants
        .get(usize::from(variant_id))
        .ok_or(NegativeFamilyError::UnknownVariant)?;
    let (action_count, host_call_count, resource_event_count, trap_count) =
        counts_for(fixture.mutation_class);
    let mut receipt = NegativeExecutionReceipt {
        family_id: fixture.family_id,
        mutation_class: fixture.mutation_class,
        variant_id,
        seed: variant.input.seed,
        counterpart_source_sha256: fixture.counterpart_source_sha256,
        mutated_source_sha256: fixture.mutated_source_sha256,
        verdict: BenchmarkOutcome::Invalid,
        first_difference: variant.expected_difference,
        action_count,
        host_call_count,
        resource_event_count,
        trap_count,
        evidence_origin: "INJECTED_TEST_FIXTURE".to_owned(),
        hardware_status: HARDWARE_STATUS.to_owned(),
        receipt_sha256: [0; 32],
    };
    receipt.receipt_sha256 = receipt.recomputed_sha256()?;
    Ok(receipt)
}

fn difference_for(class: NegativeMutationClass, variant: u32) -> NegativeDifference {
    let (kind, surface) = match class {
        NegativeMutationClass::ExtraCall => (
            NegativeDifferenceKind::ExtraHostCall,
            NegativeObserverSurface::Api,
        ),
        NegativeMutationClass::PrivateTrap => (
            NegativeDifferenceKind::PrivateDependentTrap,
            NegativeObserverSurface::Control,
        ),
        NegativeMutationClass::ResourceLeak => (
            NegativeDifferenceKind::ResourceCountDivergence,
            NegativeObserverSurface::Resource,
        ),
        NegativeMutationClass::ExportedMemory => (
            NegativeDifferenceKind::ExportedLinearMemory,
            NegativeObserverSurface::Memory,
        ),
        NegativeMutationClass::ResetLeak => (
            NegativeDifferenceKind::ResetStateRetention,
            NegativeObserverSurface::State,
        ),
        NegativeMutationClass::StateCorruption => (
            NegativeDifferenceKind::PublicStateCorruption,
            NegativeObserverSurface::State,
        ),
        NegativeMutationClass::DuplicateAction => (
            NegativeDifferenceKind::DuplicatePublicAction,
            NegativeObserverSurface::Api,
        ),
        NegativeMutationClass::HandoffCarryover => (
            NegativeDifferenceKind::PrivateHandoffCarryover,
            NegativeObserverSurface::Handoff,
        ),
    };
    NegativeDifference {
        kind,
        surface,
        step_index: 2 + variant,
    }
}

const fn counts_for(class: NegativeMutationClass) -> (u32, u32, u32, u32) {
    match class {
        NegativeMutationClass::ExtraCall => (1, 2, 1, 0),
        NegativeMutationClass::PrivateTrap => (0, 1, 1, 1),
        NegativeMutationClass::ResourceLeak => (1, 1, 2, 0),
        NegativeMutationClass::ExportedMemory => (1, 1, 1, 0),
        NegativeMutationClass::ResetLeak => (1, 1, 1, 0),
        NegativeMutationClass::StateCorruption => (1, 1, 1, 0),
        NegativeMutationClass::DuplicateAction => (2, 1, 1, 0),
        NegativeMutationClass::HandoffCarryover => (1, 1, 1, 0),
    }
}

fn mutated_source_digest(
    counterpart: [u8; 32],
    family_id: BenchmarkFamilyId,
    class: NegativeMutationClass,
) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(35);
    encoded.extend_from_slice(&counterpart);
    encoded.push(family_code(family_id));
    encoded.push(mutation_code(class));
    domain_hash(NEGATIVE_DOMAIN, &encoded)
}

fn public_input_digest(family_id: BenchmarkFamilyId, variant_id: u16) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(3);
    encoded.push(family_code(family_id));
    encoded.extend_from_slice(&variant_id.to_be_bytes());
    domain_hash(b"QUOTIENT_SEAL_GENERIC_NEGATIVE_INPUT_V1", &encoded)
}

fn derive_variant_seed(seed: u64, variant: u64) -> u64 {
    seed.rotate_left((variant as u32) & 31) ^ variant.wrapping_mul(0xa076_1d64_78bd_642f)
}

fn family_code(family_id: BenchmarkFamilyId) -> u8 {
    BenchmarkFamilyId::ALL
        .iter()
        .position(|candidate| *candidate == family_id)
        .map_or(0, |index| index as u8 + 1)
}

const fn mutation_code(class: NegativeMutationClass) -> u8 {
    match class {
        NegativeMutationClass::ExtraCall => 1,
        NegativeMutationClass::PrivateTrap => 2,
        NegativeMutationClass::ResourceLeak => 3,
        NegativeMutationClass::ExportedMemory => 4,
        NegativeMutationClass::ResetLeak => 5,
        NegativeMutationClass::StateCorruption => 6,
        NegativeMutationClass::DuplicateAction => 7,
        NegativeMutationClass::HandoffCarryover => 8,
    }
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}
