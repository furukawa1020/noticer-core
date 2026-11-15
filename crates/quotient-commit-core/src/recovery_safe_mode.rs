#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SafeModeReason {
    IntegrityFault,
    QuorumLoss,
    LivenessFailure,
    OperatorRequest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SafeModeState {
    Normal,
    Safe {
        reason: SafeModeReason,
        entered_epoch: u64,
    },
    Reauthorized {
        policy_epoch: u64,
        approval_digest: [u8; 32],
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SafeModeError {
    AlreadySafe,
    NotSafe,
    StalePolicy,
    EmptyApproval,
}

pub struct SafeModeController {
    state: SafeModeState,
}

impl SafeModeController {
    pub fn new() -> Self {
        Self {
            state: SafeModeState::Normal,
        }
    }
    pub fn state(&self) -> SafeModeState {
        self.state
    }
    pub fn enter(&mut self, reason: SafeModeReason, epoch: u64) -> Result<(), SafeModeError> {
        if !matches!(self.state, SafeModeState::Normal) {
            return Err(SafeModeError::AlreadySafe);
        }
        self.state = SafeModeState::Safe {
            reason,
            entered_epoch: epoch,
        };
        Ok(())
    }
    pub fn reauthorize(
        &mut self,
        policy_epoch: u64,
        approval_digest: [u8; 32],
    ) -> Result<(), SafeModeError> {
        let SafeModeState::Safe { entered_epoch, .. } = self.state else {
            return Err(SafeModeError::NotSafe);
        };
        if policy_epoch <= entered_epoch {
            return Err(SafeModeError::StalePolicy);
        }
        if approval_digest == [0; 32] {
            return Err(SafeModeError::EmptyApproval);
        }
        self.state = SafeModeState::Reauthorized {
            policy_epoch,
            approval_digest,
        };
        Ok(())
    }
}

impl Default for SafeModeController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn requires_newer_policy_and_explicit_approval() {
        let mut controller = SafeModeController::new();
        controller.enter(SafeModeReason::IntegrityFault, 7).unwrap();
        assert_eq!(
            controller.reauthorize(7, [1; 32]),
            Err(SafeModeError::StalePolicy)
        );
        assert_eq!(
            controller.reauthorize(8, [0; 32]),
            Err(SafeModeError::EmptyApproval)
        );
        assert_eq!(controller.reauthorize(8, [1; 32]), Ok(()));
    }
    #[test]
    fn cannot_enter_or_reauthorize_out_of_state() {
        let mut controller = SafeModeController::new();
        assert_eq!(
            controller.reauthorize(2, [1; 32]),
            Err(SafeModeError::NotSafe)
        );
        controller.enter(SafeModeReason::QuorumLoss, 1).unwrap();
        assert_eq!(
            controller.enter(SafeModeReason::LivenessFailure, 1),
            Err(SafeModeError::AlreadySafe)
        );
    }
}
