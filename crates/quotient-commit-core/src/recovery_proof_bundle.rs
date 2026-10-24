//! Canonical public proof bundle for a completed recovery ceremony.

use crate::receipt::hmac_sha256;
use crate::recovery_ceremony::{CeremonyCheckpoint, CeremonyPhase};
use crate::recovery_witness::RecoveryWitnessBatch;
use crate::startup_admission_gate::StartupAdmissionPermit;
use crate::startup_security_gate::StartupAuthorization;

const DOMAIN: &[u8] = b"noticer.quotient-commit.recovery-proof-bundle.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryProofBundle {
    pub version: u8,
    pub anchor_generation: u64,
    pub policy_epoch: u64,
    pub certificate_authenticator: [u8; 32],
    pub anchor_authenticator: [u8; 32],
    pub admission_authenticator: [u8; 32],
    pub witness_authenticator: [u8; 32],
    pub ceremony_authenticator: [u8; 32],
    pub authenticator: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryProofBundleError {
    InvalidKey,
    IncompleteCeremony,
    ComponentMismatch,
    AuthenticationFailed,
}

pub fn build_proof_bundle(
    security: StartupAuthorization,
    admission: StartupAdmissionPermit,
    witness: RecoveryWitnessBatch,
    ceremony: CeremonyCheckpoint,
    key: [u8; 32],
) -> Result<RecoveryProofBundle, RecoveryProofBundleError> {
    if key == [0; 32] {
        return Err(RecoveryProofBundleError::InvalidKey);
    }
    if ceremony.phase != CeremonyPhase::Complete {
        return Err(RecoveryProofBundleError::IncompleteCeremony);
    }
    if ceremony.certificate_authenticator != security.certificate_authenticator
        || ceremony.anchor_authenticator != security.anchor_authenticator
        || ceremony.admission_authenticator != admission.authenticator
        || ceremony.witness_authenticator != witness.authenticator
        || ceremony.authenticator == [0; 32]
    {
        return Err(RecoveryProofBundleError::ComponentMismatch);
    }
    let mut bundle = RecoveryProofBundle {
        version: 1,
        anchor_generation: security.anchor_generation,
        policy_epoch: admission.policy_epoch,
        certificate_authenticator: security.certificate_authenticator,
        anchor_authenticator: security.anchor_authenticator,
        admission_authenticator: admission.authenticator,
        witness_authenticator: witness.authenticator,
        ceremony_authenticator: ceremony.authenticator,
        authenticator: [0; 32],
    };
    bundle.authenticator = authenticate(bundle, key);
    Ok(bundle)
}

pub fn verify_proof_bundle(
    bundle: RecoveryProofBundle,
    key: [u8; 32],
) -> Result<(), RecoveryProofBundleError> {
    if key == [0; 32] {
        return Err(RecoveryProofBundleError::InvalidKey);
    }
    if bundle.version != 1
        || bundle.anchor_generation == 0
        || bundle.policy_epoch == 0
        || bundle.authenticator != authenticate(bundle, key)
    {
        return Err(RecoveryProofBundleError::AuthenticationFailed);
    }
    Ok(())
}

#[must_use]
pub fn canonical_json(value: RecoveryProofBundle) -> String {
    format!("{{\"schema\":\"noticer.recovery-proof-bundle.v1\",\"anchor_generation\":{},\"policy_epoch\":{},\"certificate_authenticator\":\"{}\",\"anchor_authenticator\":\"{}\",\"admission_authenticator\":\"{}\",\"witness_authenticator\":\"{}\",\"ceremony_authenticator\":\"{}\",\"authenticator\":\"{}\"}}",
        value.anchor_generation,value.policy_epoch,hex(value.certificate_authenticator),hex(value.anchor_authenticator),hex(value.admission_authenticator),hex(value.witness_authenticator),hex(value.ceremony_authenticator),hex(value.authenticator))
}

fn authenticate(mut value: RecoveryProofBundle, key: [u8; 32]) -> [u8; 32] {
    value.authenticator = [0; 32];
    let mut bytes = Vec::with_capacity(DOMAIN.len() + 2 + 8 * 2 + 32 * 5);
    bytes.extend_from_slice(DOMAIN);
    bytes.push(value.version);
    bytes.extend_from_slice(&value.anchor_generation.to_be_bytes());
    bytes.extend_from_slice(&value.policy_epoch.to_be_bytes());
    for field in [
        value.certificate_authenticator,
        value.anchor_authenticator,
        value.admission_authenticator,
        value.witness_authenticator,
        value.ceremony_authenticator,
    ] {
        bytes.extend_from_slice(&field);
    }
    hmac_sha256(key, &bytes)
}
fn hex(value: [u8; 32]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in value {
        out.push(D[(byte >> 4) as usize] as char);
        out.push(D[(byte & 15) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    const KEY: [u8; 32] = [7; 32];
    fn parts() -> (
        StartupAuthorization,
        StartupAdmissionPermit,
        RecoveryWitnessBatch,
        CeremonyCheckpoint,
    ) {
        let security = StartupAuthorization {
            anchor_generation: 2,
            certificate_authenticator: [1; 32],
            anchor_authenticator: [2; 32],
            authenticator: [3; 32],
        };
        let admission = StartupAdmissionPermit {
            policy_epoch: 4,
            weighted_backlog: 0,
            snapshot_authenticator: [4; 32],
            authenticator: [5; 32],
        };
        let witness = RecoveryWitnessBatch {
            entry_count: 1,
            succeeded: 1,
            failed_closed: 0,
            head_authenticator: [6; 32],
            authenticator: [7; 32],
        };
        let ceremony = CeremonyCheckpoint {
            ceremony_id: [8; 32],
            phase: CeremonyPhase::Complete,
            certificate_authenticator: [1; 32],
            anchor_authenticator: [2; 32],
            admission_authenticator: [5; 32],
            witness_authenticator: [7; 32],
            authenticator: [9; 32],
        };
        (security, admission, witness, ceremony)
    }
    #[test]
    fn bundle_is_deterministic_verifiable_and_private_safe() {
        let (s, a, w, c) = parts();
        let first = build_proof_bundle(s, a, w, c, KEY).unwrap();
        let second = build_proof_bundle(s, a, w, c, KEY).unwrap();
        assert_eq!(first, second);
        assert_eq!(verify_proof_bundle(first, KEY), Ok(()));
        let json = canonical_json(first);
        for forbidden in ["transaction", "subject", "biosignal", "identity"] {
            assert!(!json.contains(forbidden));
        }
    }
    #[test]
    fn substitution_and_incomplete_ceremony_are_rejected() {
        let (s, a, w, mut c) = parts();
        c.witness_authenticator = [0; 32];
        assert_eq!(
            build_proof_bundle(s, a, w, c, KEY),
            Err(RecoveryProofBundleError::ComponentMismatch)
        );
        let (s, a, w, mut c) = parts();
        c.phase = CeremonyPhase::RecoveryWitnessed;
        assert_eq!(
            build_proof_bundle(s, a, w, c, KEY),
            Err(RecoveryProofBundleError::IncompleteCeremony)
        );
    }
    #[test]
    fn authenticated_field_tampering_is_rejected() {
        let (s, a, w, c) = parts();
        let mut bundle = build_proof_bundle(s, a, w, c, KEY).unwrap();
        bundle.policy_epoch += 1;
        assert_eq!(
            verify_proof_bundle(bundle, KEY),
            Err(RecoveryProofBundleError::AuthenticationFailed)
        );
    }
}
