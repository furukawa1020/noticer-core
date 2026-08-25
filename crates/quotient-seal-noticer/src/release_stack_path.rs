//! Deterministic public handoff receipts for the canonical five-stage release path.

use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    Digest, NoticerModuleId, ReleaseStackCompositionContract, RELEASE_STACK_HARDWARE_STATUS,
    RELEASE_STACK_STAGE_COUNT,
};

pub const RELEASE_STACK_PATH_VERSION: &str = "noticer-release-stack-path/v1";
pub const RELEASE_STACK_CANONICAL_SEED: u64 = 0x4e4f_5449_4345_5231;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ReleasePathKind {
    Cover = 0,
    Action = 1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseStackPublicInput {
    path_kind: ReleasePathKind,
    public_slot: u64,
    action_code: Option<u8>,
    deterministic_seed: u64,
}

impl ReleaseStackPublicInput {
    pub fn new(
        path_kind: ReleasePathKind,
        public_slot: u64,
        action_code: Option<u8>,
    ) -> Result<Self, ReleaseStackPathError> {
        let input = Self {
            path_kind,
            public_slot,
            action_code,
            deterministic_seed: RELEASE_STACK_CANONICAL_SEED,
        };
        input.validate()?;
        Ok(input)
    }

    pub const fn path_kind(&self) -> ReleasePathKind {
        self.path_kind
    }

    pub const fn public_slot(&self) -> u64 {
        self.public_slot
    }

    pub const fn action_code(&self) -> Option<u8> {
        self.action_code
    }

    pub const fn deterministic_seed(&self) -> u64 {
        self.deterministic_seed
    }

    pub fn canonical_bytes(&self) -> [u8; 32] {
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(b"NQSMINP1");
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10] = self.path_kind as u8;
        bytes[12..20].copy_from_slice(&self.public_slot.to_le_bytes());
        bytes[20..28].copy_from_slice(&self.deterministic_seed.to_le_bytes());
        if let Some(action_code) = self.action_code {
            bytes[28] = 1;
            bytes[29] = action_code;
        }
        bytes
    }

    pub fn digest(&self) -> Digest {
        Digest::new(sha256(&self.canonical_bytes()))
    }

    fn validate(&self) -> Result<(), ReleaseStackPathError> {
        if self.deterministic_seed != RELEASE_STACK_CANONICAL_SEED {
            return Err(ReleaseStackPathError::InvalidInput);
        }
        match (self.path_kind, self.action_code) {
            (ReleasePathKind::Action, Some(_)) | (ReleasePathKind::Cover, None) => Ok(()),
            _ => Err(ReleaseStackPathError::InvalidInput),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseStageReceipt {
    pub stage_index: u8,
    pub module_id: NoticerModuleId,
    pub input_commitment: Digest,
    pub output_commitment: Digest,
    pub predecessor_receipt_digest: Digest,
    pub source_digest: Digest,
    pub qsm_capsule_digest: Digest,
    pub observer_registry_digest: Digest,
    pub receipt_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseStackPathArtifact {
    pub schema_version: String,
    pub composition_digest: Digest,
    pub public_input: ReleaseStackPublicInput,
    pub receipts: Vec<ReleaseStageReceipt>,
    pub authorized_action_count: u8,
    pub cover_count: u8,
    pub final_output_commitment: Digest,
    pub hardware_status: String,
    pub artifact_digest: Digest,
}

pub fn execute_canonical_release_path(
    contract: &ReleaseStackCompositionContract,
    input: ReleaseStackPublicInput,
) -> Result<ReleaseStackPathArtifact, ReleaseStackPathError> {
    input.validate()?;
    let input_bytes = input.canonical_bytes();
    let mut current_commitment = sha256(&input_bytes);
    let mut predecessor_receipt = [0_u8; 32];
    let mut receipt_digests = Vec::with_capacity(RELEASE_STACK_STAGE_COUNT);
    let mut receipts = Vec::with_capacity(RELEASE_STACK_STAGE_COUNT);

    for (index, binding) in contract.manifest().entries().iter().enumerate() {
        let output_commitment = stage_output_commitment(
            contract,
            &input_bytes,
            index as u8,
            binding.module_id,
            &current_commitment,
            &predecessor_receipt,
        );
        let receipt_digest = stage_receipt_digest(
            contract,
            index as u8,
            binding.module_id,
            &current_commitment,
            &output_commitment,
            &predecessor_receipt,
        );
        receipts.push(ReleaseStageReceipt {
            stage_index: index as u8,
            module_id: binding.module_id,
            input_commitment: Digest::new(current_commitment),
            output_commitment: Digest::new(output_commitment),
            predecessor_receipt_digest: Digest::new(predecessor_receipt),
            source_digest: binding.source_digest,
            qsm_capsule_digest: binding.qsm_capsule_digest,
            observer_registry_digest: binding.observer_registry_digest,
            receipt_digest: Digest::new(receipt_digest),
        });
        receipt_digests.push(receipt_digest);
        current_commitment = output_commitment;
        predecessor_receipt = receipt_digest;
    }

    let (authorized_action_count, cover_count) = match input.path_kind() {
        ReleasePathKind::Action => (1, 0),
        ReleasePathKind::Cover => (0, 1),
    };
    let artifact_digest = path_artifact_digest(
        contract,
        &input_bytes,
        &receipt_digests,
        &current_commitment,
        authorized_action_count,
        cover_count,
    );

    Ok(ReleaseStackPathArtifact {
        schema_version: RELEASE_STACK_PATH_VERSION.to_owned(),
        composition_digest: contract.digest(),
        public_input: input,
        receipts,
        authorized_action_count,
        cover_count,
        final_output_commitment: Digest::new(current_commitment),
        hardware_status: RELEASE_STACK_HARDWARE_STATUS.to_owned(),
        artifact_digest: Digest::new(artifact_digest),
    })
}

pub fn verify_canonical_release_path(
    contract: &ReleaseStackCompositionContract,
    artifact: &ReleaseStackPathArtifact,
) -> Result<(), ReleaseStackPathError> {
    artifact.public_input.validate()?;
    if artifact.schema_version != RELEASE_STACK_PATH_VERSION
        || artifact.composition_digest != contract.digest()
    {
        return Err(ReleaseStackPathError::CompositionBinding);
    }
    if artifact.receipts.len() != RELEASE_STACK_STAGE_COUNT {
        return Err(ReleaseStackPathError::ReceiptCount {
            actual: artifact.receipts.len(),
        });
    }

    let expected = execute_canonical_release_path(contract, artifact.public_input.clone())?;
    for (index, ((actual, expected_receipt), binding)) in artifact
        .receipts
        .iter()
        .zip(&expected.receipts)
        .zip(contract.manifest().entries())
        .enumerate()
    {
        if actual.stage_index != index as u8 || actual.module_id != binding.module_id {
            return Err(ReleaseStackPathError::ReceiptOrder { index });
        }
        if actual.source_digest != binding.source_digest
            || actual.qsm_capsule_digest != binding.qsm_capsule_digest
            || actual.observer_registry_digest != binding.observer_registry_digest
        {
            return Err(ReleaseStackPathError::StageBinding { index });
        }
        if actual.input_commitment != expected_receipt.input_commitment
            || actual.predecessor_receipt_digest != expected_receipt.predecessor_receipt_digest
        {
            return Err(ReleaseStackPathError::ReceiptChain { index });
        }
        if actual.output_commitment != expected_receipt.output_commitment
            || actual.receipt_digest != expected_receipt.receipt_digest
        {
            return Err(ReleaseStackPathError::ReceiptDigest { index });
        }
    }

    if artifact.authorized_action_count != expected.authorized_action_count
        || artifact.cover_count != expected.cover_count
        || artifact.final_output_commitment != expected.final_output_commitment
    {
        return Err(ReleaseStackPathError::Outcome);
    }
    if artifact.hardware_status != RELEASE_STACK_HARDWARE_STATUS {
        return Err(ReleaseStackPathError::HardwareStatus);
    }
    if artifact.artifact_digest != expected.artifact_digest {
        return Err(ReleaseStackPathError::ArtifactDigest);
    }
    if artifact != &expected {
        return Err(ReleaseStackPathError::NonCanonical);
    }
    Ok(())
}

fn stage_output_commitment(
    contract: &ReleaseStackCompositionContract,
    input_bytes: &[u8; 32],
    stage_index: u8,
    module_id: NoticerModuleId,
    input_commitment: &[u8; 32],
    predecessor_receipt: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"noticer-release-stage-output/v1\0");
    hasher.update(contract.canonical_bytes());
    hasher.update(input_bytes);
    hasher.update([stage_index, module_id as u8]);
    hasher.update(input_commitment);
    hasher.update(predecessor_receipt);
    hasher.finalize().into()
}

fn stage_receipt_digest(
    contract: &ReleaseStackCompositionContract,
    stage_index: u8,
    module_id: NoticerModuleId,
    input_commitment: &[u8; 32],
    output_commitment: &[u8; 32],
    predecessor_receipt: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"noticer-release-stage-receipt/v1\0");
    hasher.update(contract.canonical_bytes());
    hasher.update([stage_index, module_id as u8]);
    hasher.update(input_commitment);
    hasher.update(output_commitment);
    hasher.update(predecessor_receipt);
    hasher.finalize().into()
}

fn path_artifact_digest(
    contract: &ReleaseStackCompositionContract,
    input_bytes: &[u8; 32],
    receipt_digests: &[[u8; 32]],
    final_output: &[u8; 32],
    action_count: u8,
    cover_count: u8,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"noticer-release-stack-path-artifact/v1\0");
    hasher.update(contract.canonical_bytes());
    hasher.update(input_bytes);
    hasher.update((receipt_digests.len() as u16).to_le_bytes());
    for digest in receipt_digests {
        hasher.update(digest);
    }
    hasher.update(final_output);
    hasher.update([action_count, cover_count]);
    hasher.update(RELEASE_STACK_HARDWARE_STATUS.as_bytes());
    hasher.finalize().into()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ReleaseStackPathError {
    #[error("release stack public input is non-canonical")]
    InvalidInput,
    #[error("release stack artifact is bound to a different composition")]
    CompositionBinding,
    #[error("release stack receipt count is {actual}, expected five")]
    ReceiptCount { actual: usize },
    #[error("release stack receipt {index} is reordered or substituted")]
    ReceiptOrder { index: usize },
    #[error("release stack receipt {index} does not match its manifest binding")]
    StageBinding { index: usize },
    #[error("release stack receipt {index} breaks the predecessor chain")]
    ReceiptChain { index: usize },
    #[error("release stack receipt {index} digest does not recompute")]
    ReceiptDigest { index: usize },
    #[error("release stack path outcome is inconsistent with public semantics")]
    Outcome,
    #[error("release stack path hardware status must remain NOT_VERIFIED")]
    HardwareStatus,
    #[error("release stack path artifact digest does not recompute")]
    ArtifactDigest,
    #[error("release stack path artifact is non-canonical")]
    NonCanonical,
}
