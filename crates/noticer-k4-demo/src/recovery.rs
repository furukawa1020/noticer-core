use crate::{
    authenticated_public_clock::{
        AuthenticatedClockError, AuthenticatedDurablePublicClock, PublicClockAuthKey,
    },
    monotonic_anchor::{AnchorBinding, MonotonicAnchor, MonotonicAnchorError},
};
use noticer_aetp::ServiceBinding;
use noticer_crypto::{CryptoError, IssuerKeyMaterial, VerifierKeyMaterial};
use std::path::Path;

const DOMAIN: &[u8] = b"NOTICER_CLOCK_RECOVERY_V1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryPermit {
    pub operator_domain: ServiceBinding,
    pub epoch: u32,
    pub generation: u64,
    pub record_slot: u64,
    pub anchor_slot: u64,
    pub target_slot: u64,
    pub expires_at: u64,
    pub nonce: [u8; 16],
    pub signature: [u8; 64],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryLedgerError {
    Storage,
}

pub trait RecoveryLedger {
    fn consume(&mut self, permit_id: [u8; 16]) -> Result<bool, RecoveryLedgerError>;
}

#[derive(Debug)]
pub enum RecoveryError {
    Clock(AuthenticatedClockError),
    Anchor(MonotonicAnchorError),
    Signature(CryptoError),
    Binding,
    Expired,
    TargetRollback,
    Replay,
    Ledger,
}

#[allow(clippy::too_many_arguments)]
pub fn issue_recovery_permit(
    issuer: &IssuerKeyMaterial,
    operator_domain: ServiceBinding,
    generation: u64,
    record_slot: u64,
    anchor_slot: u64,
    target_slot: u64,
    expires_at: u64,
    nonce: [u8; 16],
) -> RecoveryPermit {
    let mut permit = RecoveryPermit {
        operator_domain,
        epoch: issuer.epoch(),
        generation,
        record_slot,
        anchor_slot,
        target_slot,
        expires_at,
        nonce,
        signature: [0; 64],
    };
    permit.signature = issuer.sign(&permit_message(&permit));
    permit
}

#[allow(clippy::too_many_arguments)]
pub fn recover_clock<A: MonotonicAnchor, L: RecoveryLedger>(
    path: impl AsRef<Path>,
    key: PublicClockAuthKey,
    verifier: &VerifierKeyMaterial,
    expected_operator_domain: ServiceBinding,
    binding: AnchorBinding,
    now: u64,
    permit: &RecoveryPermit,
    anchor: &mut A,
    ledger: &mut L,
) -> Result<u64, RecoveryError> {
    let mut clock = AuthenticatedDurablePublicClock::open_observed(
        path,
        binding.epoch,
        binding.generation,
        key,
    )
    .map_err(RecoveryError::Clock)?;
    let anchor_slot = anchor.current(binding).map_err(RecoveryError::Anchor)?;
    if permit.operator_domain != expected_operator_domain
        || permit.epoch != binding.epoch
        || permit.generation != binding.generation
        || permit.record_slot != clock.slot()
        || permit.anchor_slot != anchor_slot
    {
        return Err(RecoveryError::Binding);
    }
    if now > permit.expires_at {
        return Err(RecoveryError::Expired);
    }
    if permit.target_slot < permit.record_slot || permit.target_slot < permit.anchor_slot {
        return Err(RecoveryError::TargetRollback);
    }
    verifier
        .verify(&permit_message(permit), &permit.signature)
        .map_err(RecoveryError::Signature)?;
    let permit_id = permit.signature[..16].try_into().expect("fixed permit id");
    if !ledger
        .consume(permit_id)
        .map_err(|_| RecoveryError::Ledger)?
    {
        return Err(RecoveryError::Replay);
    }
    clock
        .advance(permit.target_slot)
        .map_err(RecoveryError::Clock)?;
    anchor
        .advance(binding, permit.target_slot)
        .map_err(RecoveryError::Anchor)?;
    Ok(permit.target_slot)
}

pub(crate) fn permit_message(permit: &RecoveryPermit) -> Vec<u8> {
    let mut output = Vec::with_capacity(92);
    output.extend_from_slice(DOMAIN);
    output.extend_from_slice(&permit.operator_domain.0);
    output.extend_from_slice(&permit.epoch.to_le_bytes());
    output.extend_from_slice(&permit.generation.to_le_bytes());
    output.extend_from_slice(&permit.record_slot.to_le_bytes());
    output.extend_from_slice(&permit.anchor_slot.to_le_bytes());
    output.extend_from_slice(&permit.target_slot.to_le_bytes());
    output.extend_from_slice(&permit.expires_at.to_le_bytes());
    output.extend_from_slice(&permit.nonce);
    output
}
