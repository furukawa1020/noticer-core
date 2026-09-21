use crate::{durable_recovery_ledger::RecoveryLedgerHead, monotonic_anchor::AnchorBinding};
use noticer_crypto::{authenticate_state, StateAuthenticationKey};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateSnapshot {
    pub binding: AnchorBinding,
    pub clock_slot: u64,
    pub anchor_slot: u64,
    pub recovery_ledger: RecoveryLedgerHead,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenerationAnchorState {
    pub revision: u64,
    pub commitment: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationAnchorError {
    Unavailable,
    BindingMismatch,
    UpdateFailed,
}
pub trait GenerationAnchor {
    fn current(
        &mut self,
        binding: AnchorBinding,
    ) -> Result<GenerationAnchorState, GenerationAnchorError>;
    fn advance(
        &mut self,
        binding: AnchorBinding,
        expected_revision: u64,
        next: GenerationAnchorState,
    ) -> Result<(), GenerationAnchorError>;
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateGenerationError {
    Anchor(GenerationAnchorError),
    CommitmentMismatch,
    BindingMismatch,
    Regression,
    RevisionOverflow,
}

pub fn state_commitment(snapshot: &StateSnapshot, key: &StateAuthenticationKey) -> [u8; 32] {
    let mut message = [0u8; 72];
    message[..4].copy_from_slice(&snapshot.binding.epoch.to_le_bytes());
    message[4..12].copy_from_slice(&snapshot.binding.generation.to_le_bytes());
    message[12..20].copy_from_slice(&snapshot.clock_slot.to_le_bytes());
    message[20..28].copy_from_slice(&snapshot.anchor_slot.to_le_bytes());
    message[28..36].copy_from_slice(&snapshot.recovery_ledger.sequence.to_le_bytes());
    message[36..68].copy_from_slice(&snapshot.recovery_ledger.tag);
    message[68..].copy_from_slice(b"SGV1");
    authenticate_state(key, &message)
}
pub fn initial_generation_state(
    snapshot: &StateSnapshot,
    key: &StateAuthenticationKey,
) -> GenerationAnchorState {
    GenerationAnchorState {
        revision: 0,
        commitment: state_commitment(snapshot, key),
    }
}
pub fn verify_generation<A: GenerationAnchor>(
    snapshot: &StateSnapshot,
    key: &StateAuthenticationKey,
    anchor: &mut A,
) -> Result<GenerationAnchorState, StateGenerationError> {
    let state = anchor
        .current(snapshot.binding)
        .map_err(StateGenerationError::Anchor)?;
    if state.commitment != state_commitment(snapshot, key) {
        return Err(StateGenerationError::CommitmentMismatch);
    }
    Ok(state)
}
pub fn advance_generation<A: GenerationAnchor>(
    previous: &StateSnapshot,
    next: &StateSnapshot,
    key: &StateAuthenticationKey,
    anchor: &mut A,
) -> Result<GenerationAnchorState, StateGenerationError> {
    if previous.binding != next.binding {
        return Err(StateGenerationError::BindingMismatch);
    }
    if next.clock_slot < previous.clock_slot
        || next.anchor_slot < previous.anchor_slot
        || next.recovery_ledger.sequence < previous.recovery_ledger.sequence
    {
        return Err(StateGenerationError::Regression);
    }
    let current = verify_generation(previous, key, anchor)?;
    let revision = current
        .revision
        .checked_add(1)
        .ok_or(StateGenerationError::RevisionOverflow)?;
    let next_state = GenerationAnchorState {
        revision,
        commitment: state_commitment(next, key),
    };
    anchor
        .advance(next.binding, current.revision, next_state)
        .map_err(StateGenerationError::Anchor)?;
    Ok(next_state)
}
