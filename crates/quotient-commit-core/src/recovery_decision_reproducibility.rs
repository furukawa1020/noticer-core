use crate::{
    recovery_authority_lattice::RecoveryCapability,
    recovery_decision_capsule::{issue, verify, DecisionCapsule, RecoveryDecision},
};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecisionInputs {
    pub authority: RecoveryCapability,
    pub quorum_digest: [u8; 32],
    pub evidence_root: [u8; 32],
    pub causal_cut: [u8; 32],
    pub epoch: u64,
    pub decision: RecoveryDecision,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReproductionError {
    InvalidCapsule,
    Divergence,
}
pub fn reproduce(
    inputs: DecisionInputs,
    capsule: DecisionCapsule,
    key: [u8; 32],
) -> Result<(), ReproductionError> {
    if !verify(capsule, key) {
        return Err(ReproductionError::InvalidCapsule);
    }
    let expected = issue(
        inputs.authority,
        inputs.quorum_digest,
        inputs.evidence_root,
        inputs.causal_cut,
        inputs.epoch,
        inputs.decision,
        key,
    );
    if expected != capsule {
        return Err(ReproductionError::Divergence);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    const K: [u8; 32] = [4; 32];
    fn i() -> DecisionInputs {
        DecisionInputs {
            authority: RecoveryCapability::Restore,
            quorum_digest: [1; 32],
            evidence_root: [2; 32],
            causal_cut: [3; 32],
            epoch: 7,
            decision: RecoveryDecision::Restore,
        }
    }
    #[test]
    fn reproduces() {
        let x = i();
        let c = issue(
            x.authority,
            x.quorum_digest,
            x.evidence_root,
            x.causal_cut,
            x.epoch,
            x.decision,
            K,
        );
        assert_eq!(reproduce(x, c, K), Ok(()))
    }
    #[test]
    fn detects_divergence() {
        let x = i();
        let c = issue(
            x.authority,
            x.quorum_digest,
            x.evidence_root,
            x.causal_cut,
            x.epoch,
            x.decision,
            K,
        );
        let mut y = x;
        y.epoch = 8;
        assert_eq!(reproduce(y, c, K), Err(ReproductionError::Divergence))
    }
}
