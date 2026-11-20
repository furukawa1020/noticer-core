//! Final fail-closed gate for applying a certified repair.

use crate::remedy_replay::ReplayVerdict;
use crate::remedy_replay_disagreement::{deployment_blocked, RepairReplayDisagreement};
use crate::remedy_verdict::RepairVerdict;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepairDeploymentEvidence {
    pub verdict: RepairVerdict,
    pub certificate_digest: [u8; 32],
    pub authenticated: bool,
    pub replay: ReplayVerdict,
    pub disagreement: RepairReplayDisagreement,
    pub safety: bool,
    pub action_equivalence: bool,
    pub liveness: bool,
    pub privacy: bool,
    pub minimality: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepairDeploymentPermit {
    pub certificate_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeploymentError {
    NonDeployableVerdict,
    ZeroCertificate,
    Unauthenticated,
    ReplayNotVerified,
    ReplayDisagreement,
    VerificationFailed,
}

pub fn authorize(
    evidence: RepairDeploymentEvidence,
) -> Result<RepairDeploymentPermit, DeploymentError> {
    if !evidence.verdict.deployment_allowed() {
        return Err(DeploymentError::NonDeployableVerdict);
    }
    if evidence.certificate_digest == [0; 32] {
        return Err(DeploymentError::ZeroCertificate);
    }
    if !evidence.authenticated {
        return Err(DeploymentError::Unauthenticated);
    }
    if evidence.replay != ReplayVerdict::Verified {
        return Err(DeploymentError::ReplayNotVerified);
    }
    if deployment_blocked(evidence.disagreement) {
        return Err(DeploymentError::ReplayDisagreement);
    }
    if !(evidence.safety
        && evidence.action_equivalence
        && evidence.liveness
        && evidence.privacy
        && evidence.minimality)
    {
        return Err(DeploymentError::VerificationFailed);
    }
    Ok(RepairDeploymentPermit {
        certificate_digest: evidence.certificate_digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> RepairDeploymentEvidence {
        RepairDeploymentEvidence {
            verdict: RepairVerdict::Repaired,
            certificate_digest: [1; 32],
            authenticated: true,
            replay: ReplayVerdict::Verified,
            disagreement: RepairReplayDisagreement::None,
            safety: true,
            action_equivalence: true,
            liveness: true,
            privacy: true,
            minimality: true,
        }
    }

    #[test]
    fn every_gate_is_mandatory() {
        assert!(authorize(valid()).is_ok());
        let mut changed = valid();
        changed.privacy = false;
        assert_eq!(authorize(changed), Err(DeploymentError::VerificationFailed));
        let mut changed = valid();
        changed.disagreement = RepairReplayDisagreement::PrimaryAcceptedReplayRejected;
        assert_eq!(authorize(changed), Err(DeploymentError::ReplayDisagreement));
    }
}
