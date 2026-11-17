use crate::{receipt::hmac_sha256, recovery_authority_lattice::RecoveryCapability};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RecoveryDecision {
    Deny = 0,
    Restore = 1,
    Release = 2,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecisionCapsule {
    pub authority: RecoveryCapability,
    pub quorum_digest: [u8; 32],
    pub evidence_root: [u8; 32],
    pub causal_cut: [u8; 32],
    pub epoch: u64,
    pub decision: RecoveryDecision,
    pub authenticator: [u8; 32],
}
pub fn issue(
    authority: RecoveryCapability,
    quorum_digest: [u8; 32],
    evidence_root: [u8; 32],
    causal_cut: [u8; 32],
    epoch: u64,
    decision: RecoveryDecision,
    key: [u8; 32],
) -> DecisionCapsule {
    let mut v = DecisionCapsule {
        authority,
        quorum_digest,
        evidence_root,
        causal_cut,
        epoch,
        decision,
        authenticator: [0; 32],
    };
    v.authenticator = auth(v, key);
    v
}
pub fn verify(v: DecisionCapsule, key: [u8; 32]) -> bool {
    v.quorum_digest != [0; 32]
        && v.evidence_root != [0; 32]
        && v.causal_cut != [0; 32]
        && v.authenticator == auth(v, key)
}
fn auth(mut v: DecisionCapsule, key: [u8; 32]) -> [u8; 32] {
    v.authenticator = [0; 32];
    let mut b = Vec::new();
    b.extend_from_slice(b"noticer.decision-capsule.v1");
    b.push(v.authority as u8);
    b.extend_from_slice(&v.quorum_digest);
    b.extend_from_slice(&v.evidence_root);
    b.extend_from_slice(&v.causal_cut);
    b.extend_from_slice(&v.epoch.to_be_bytes());
    b.push(v.decision as u8);
    hmac_sha256(key, &b)
}
#[cfg(test)]
mod tests {
    use super::*;
    const K: [u8; 32] = [3; 32];
    #[test]
    fn binds_decision_inputs() {
        let v = issue(
            RecoveryCapability::Release,
            [1; 32],
            [2; 32],
            [3; 32],
            7,
            RecoveryDecision::Release,
            K,
        );
        assert!(verify(v, K));
    }
    #[test]
    fn rejects_substitution() {
        let mut v = issue(
            RecoveryCapability::Release,
            [1; 32],
            [2; 32],
            [3; 32],
            7,
            RecoveryDecision::Release,
            K,
        );
        v.decision = RecoveryDecision::Deny;
        assert!(!verify(v, K));
    }
}
