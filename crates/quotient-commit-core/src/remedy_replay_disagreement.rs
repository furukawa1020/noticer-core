//! Typed disagreement between primary evaluation and independent replay.

use crate::remedy_replay::ReplayVerdict;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairReplayDisagreement {
    None,
    PrimaryAcceptedReplayRejected,
    PrimaryRejectedReplayAccepted,
    ReplayInputInvalid,
}

#[must_use]
pub const fn classify(primary_accepted: bool, replay: ReplayVerdict) -> RepairReplayDisagreement {
    match (primary_accepted, replay) {
        (_, ReplayVerdict::Invalid) => RepairReplayDisagreement::ReplayInputInvalid,
        (true, ReplayVerdict::Rejected) => RepairReplayDisagreement::PrimaryAcceptedReplayRejected,
        (false, ReplayVerdict::Verified) => RepairReplayDisagreement::PrimaryRejectedReplayAccepted,
        _ => RepairReplayDisagreement::None,
    }
}

#[must_use]
pub const fn deployment_blocked(disagreement: RepairReplayDisagreement) -> bool {
    !matches!(disagreement, RepairReplayDisagreement::None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_disagreement_blocks_deployment() {
        for value in [
            RepairReplayDisagreement::PrimaryAcceptedReplayRejected,
            RepairReplayDisagreement::PrimaryRejectedReplayAccepted,
            RepairReplayDisagreement::ReplayInputInvalid,
        ] {
            assert!(deployment_blocked(value));
        }
        assert!(!deployment_blocked(RepairReplayDisagreement::None));
    }
}
