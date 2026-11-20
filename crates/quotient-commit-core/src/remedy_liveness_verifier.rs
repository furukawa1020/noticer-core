//! Rejects repairs that obtain safety by suppressing every permitted action.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LivenessEvidence {
    pub eligible_actions: u32,
    pub released_actions: u32,
    pub progress_bound_slots: u32,
    pub observed_progress_slots: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LivenessError {
    NoEligibleAction,
    SuppressedAllActions,
    ZeroProgressBound,
    ProgressBoundExceeded,
}

pub fn verify(evidence: LivenessEvidence) -> Result<(), LivenessError> {
    if evidence.eligible_actions == 0 {
        return Err(LivenessError::NoEligibleAction);
    }
    if evidence.released_actions == 0 {
        return Err(LivenessError::SuppressedAllActions);
    }
    if evidence.progress_bound_slots == 0 {
        return Err(LivenessError::ZeroProgressBound);
    }
    if evidence.observed_progress_slots > evidence.progress_bound_slots {
        return Err(LivenessError::ProgressBoundExceeded);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_all_patch_is_not_a_repair() {
        assert_eq!(
            verify(LivenessEvidence {
                eligible_actions: 3,
                released_actions: 0,
                progress_bound_slots: 8,
                observed_progress_slots: 0
            }),
            Err(LivenessError::SuppressedAllActions)
        );
    }

    #[test]
    fn bounded_progress_is_accepted() {
        assert_eq!(
            verify(LivenessEvidence {
                eligible_actions: 3,
                released_actions: 2,
                progress_bound_slots: 8,
                observed_progress_slots: 4
            }),
            Ok(())
        );
    }
}
