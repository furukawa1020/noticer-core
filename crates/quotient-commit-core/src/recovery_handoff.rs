//! One-shot cross-device handoff of public recovery proof state.
use crate::receipt::hmac_sha256;
use crate::recovery_proof_bundle::{verify_proof_bundle, RecoveryProofBundle};
use std::collections::BTreeSet;
const DOMAIN: &[u8] = b"noticer.quotient-commit.recovery-handoff.v1\0";
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandoffCertificate {
    pub source_epoch: u64,
    pub target_epoch: u64,
    pub nonce: [u8; 32],
    pub proof_authenticator: [u8; 32],
    pub recovery_head: [u8; 32],
    pub authenticator: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffError {
    InvalidKey,
    InvalidEpoch,
    EpochDowngrade,
    InvalidNonce,
    InvalidProof,
    AuthenticationFailed,
    ReplayDetected,
    WrongTargetEpoch,
}
pub fn issue_handoff(
    source_epoch: u64,
    target_epoch: u64,
    nonce: [u8; 32],
    proof: RecoveryProofBundle,
    recovery_head: [u8; 32],
    key: [u8; 32],
) -> Result<HandoffCertificate, HandoffError> {
    if key == [0; 32] {
        return Err(HandoffError::InvalidKey);
    }
    if source_epoch == 0 || target_epoch == 0 {
        return Err(HandoffError::InvalidEpoch);
    }
    if target_epoch <= source_epoch {
        return Err(HandoffError::EpochDowngrade);
    }
    if nonce == [0; 32] {
        return Err(HandoffError::InvalidNonce);
    }
    if recovery_head == [0; 32] || verify_proof_bundle(proof, key).is_err() {
        return Err(HandoffError::InvalidProof);
    }
    let mut c = HandoffCertificate {
        source_epoch,
        target_epoch,
        nonce,
        proof_authenticator: proof.authenticator,
        recovery_head,
        authenticator: [0; 32],
    };
    c.authenticator = authenticate(c, key);
    Ok(c)
}
#[derive(Debug)]
pub struct HandoffAcceptor {
    target_epoch: u64,
    key: [u8; 32],
    used_nonces: BTreeSet<[u8; 32]>,
}
impl HandoffAcceptor {
    pub fn new(target_epoch: u64, key: [u8; 32]) -> Result<Self, HandoffError> {
        if key == [0; 32] {
            return Err(HandoffError::InvalidKey);
        }
        if target_epoch == 0 {
            return Err(HandoffError::InvalidEpoch);
        }
        Ok(Self {
            target_epoch,
            key,
            used_nonces: BTreeSet::new(),
        })
    }
    pub fn accept(&mut self, certificate: HandoffCertificate) -> Result<(), HandoffError> {
        if certificate.target_epoch != self.target_epoch {
            return Err(HandoffError::WrongTargetEpoch);
        }
        if certificate.target_epoch <= certificate.source_epoch {
            return Err(HandoffError::EpochDowngrade);
        }
        if certificate.authenticator != authenticate(certificate, self.key) {
            return Err(HandoffError::AuthenticationFailed);
        }
        if !self.used_nonces.insert(certificate.nonce) {
            return Err(HandoffError::ReplayDetected);
        }
        Ok(())
    }
}
fn authenticate(mut c: HandoffCertificate, key: [u8; 32]) -> [u8; 32] {
    c.authenticator = [0; 32];
    let mut b = Vec::with_capacity(DOMAIN.len() + 112);
    b.extend_from_slice(DOMAIN);
    b.extend_from_slice(&c.source_epoch.to_be_bytes());
    b.extend_from_slice(&c.target_epoch.to_be_bytes());
    b.extend_from_slice(&c.nonce);
    b.extend_from_slice(&c.proof_authenticator);
    b.extend_from_slice(&c.recovery_head);
    hmac_sha256(key, &b)
}
#[must_use]
pub fn canonical_json(c: HandoffCertificate) -> String {
    format!("{{\"schema\":\"noticer.recovery-handoff.v1\",\"source_epoch\":{},\"target_epoch\":{},\"nonce\":\"{}\",\"proof_authenticator\":\"{}\",\"recovery_head\":\"{}\",\"authenticator\":\"{}\"}}",c.source_epoch,c.target_epoch,hex(c.nonce),hex(c.proof_authenticator),hex(c.recovery_head),hex(c.authenticator))
}
fn hex(v: [u8; 32]) -> String {
    v.iter().map(|b| format!("{b:02x}")).collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    const KEY: [u8; 32] = [7; 32];
    fn proof() -> RecoveryProofBundle {
        let mut p = RecoveryProofBundle {
            version: 1,
            anchor_generation: 1,
            policy_epoch: 1,
            certificate_authenticator: [1; 32],
            anchor_authenticator: [2; 32],
            admission_authenticator: [3; 32],
            witness_authenticator: [4; 32],
            ceremony_authenticator: [5; 32],
            authenticator: [0; 32],
        };
        let mut b = Vec::new();
        b.extend_from_slice(b"noticer.quotient-commit.recovery-proof-bundle.v1\0");
        b.push(1);
        b.extend_from_slice(&1u64.to_be_bytes());
        b.extend_from_slice(&1u64.to_be_bytes());
        for f in [[1; 32], [2; 32], [3; 32], [4; 32], [5; 32]] {
            b.extend_from_slice(&f)
        }
        p.authenticator = hmac_sha256(KEY, &b);
        p
    }
    #[test]
    fn one_shot_handoff_accepts_once() {
        let c = issue_handoff(1, 2, [9; 32], proof(), [8; 32], KEY).unwrap();
        let mut a = HandoffAcceptor::new(2, KEY).unwrap();
        assert_eq!(a.accept(c), Ok(()));
        assert_eq!(a.accept(c), Err(HandoffError::ReplayDetected));
    }
    #[test]
    fn downgrade_substitution_and_wrong_target_fail() {
        assert_eq!(
            issue_handoff(2, 1, [9; 32], proof(), [8; 32], KEY),
            Err(HandoffError::EpochDowngrade)
        );
        let mut c = issue_handoff(1, 2, [9; 32], proof(), [8; 32], KEY).unwrap();
        c.recovery_head = [7; 32];
        assert_eq!(
            HandoffAcceptor::new(2, KEY).unwrap().accept(c),
            Err(HandoffError::AuthenticationFailed)
        );
    }
    #[test]
    fn artifact_excludes_private_identifiers() {
        let j = canonical_json(issue_handoff(1, 2, [9; 32], proof(), [8; 32], KEY).unwrap());
        for x in ["subject", "biosignal", "identity", "transaction"] {
            assert!(!j.contains(x));
        }
    }
}
