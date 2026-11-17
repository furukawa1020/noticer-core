use crate::{
    receipt::hmac_sha256,
    recovery_decision_capsule::{DecisionCapsule, RecoveryDecision},
};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecisionCommitment {
    pub decision: RecoveryDecision,
    pub epoch: u64,
    pub capsule_commitment: [u8; 32],
}
pub fn commit(c: DecisionCapsule, public_key: [u8; 32]) -> DecisionCommitment {
    let mut b = Vec::new();
    b.extend_from_slice(b"noticer.public-decision.v1");
    b.extend_from_slice(&c.authenticator);
    b.push(c.decision as u8);
    b.extend_from_slice(&c.epoch.to_be_bytes());
    DecisionCommitment {
        decision: c.decision,
        epoch: c.epoch,
        capsule_commitment: hmac_sha256(public_key, &b),
    }
}
pub fn verify(c: DecisionCapsule, v: DecisionCommitment, key: [u8; 32]) -> bool {
    commit(c, key) == v
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{recovery_authority_lattice::RecoveryCapability, recovery_decision_capsule::issue};
    const K: [u8; 32] = [2; 32];
    fn c() -> DecisionCapsule {
        issue(
            RecoveryCapability::Release,
            [1; 32],
            [2; 32],
            [3; 32],
            7,
            RecoveryDecision::Release,
            K,
        )
    }
    #[test]
    fn verifies_commitment() {
        let x = c();
        assert!(verify(x, commit(x, K), K))
    }
    #[test]
    fn rejects_substitution() {
        let x = c();
        let mut v = commit(x, K);
        v.epoch = 8;
        assert!(!verify(x, v, K))
    }
}
