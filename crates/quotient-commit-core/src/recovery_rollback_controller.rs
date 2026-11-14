//! One-step deployment rollback without reviving retired authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RollbackPermit {
    pub from_epoch: u64,
    pub target_epoch: u64,
    pub fencing_token: u64,
    pub current_key_binding: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollbackError {
    InvalidState,
    NotAdjacent,
    AlreadyRolledBack,
    StaleFence,
    OldKeyNotRetired,
    InvalidBinding,
}
pub struct RollbackController {
    current_epoch: u64,
    fencing_token: u64,
    used: bool,
}
impl RollbackController {
    pub fn new(current_epoch: u64, fencing_token: u64) -> Result<Self, RollbackError> {
        if current_epoch < 2 || fencing_token == 0 {
            return Err(RollbackError::InvalidState);
        }
        Ok(Self {
            current_epoch,
            fencing_token,
            used: false,
        })
    }
    pub fn trigger(
        &mut self,
        target_epoch: u64,
        new_fence: u64,
        current_key_binding: [u8; 32],
        old_key_retired: bool,
    ) -> Result<RollbackPermit, RollbackError> {
        if self.used {
            return Err(RollbackError::AlreadyRolledBack);
        }
        if target_epoch.checked_add(1) != Some(self.current_epoch) {
            return Err(RollbackError::NotAdjacent);
        }
        if new_fence <= self.fencing_token {
            return Err(RollbackError::StaleFence);
        }
        if !old_key_retired {
            return Err(RollbackError::OldKeyNotRetired);
        }
        if current_key_binding == [0; 32] {
            return Err(RollbackError::InvalidBinding);
        }
        self.used = true;
        self.fencing_token = new_fence;
        Ok(RollbackPermit {
            from_epoch: self.current_epoch,
            target_epoch,
            fencing_token: new_fence,
            current_key_binding,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn one_step_rollback_advances_fence() {
        let mut c = RollbackController::new(5, 10).unwrap();
        let p = c.trigger(4, 11, [1; 32], true).unwrap();
        assert_eq!(p.target_epoch, 4);
        assert_eq!(
            c.trigger(4, 12, [1; 32], true),
            Err(RollbackError::AlreadyRolledBack)
        )
    }
    #[test]
    fn skip_stale_fence_and_old_key_fail() {
        let mut c = RollbackController::new(5, 10).unwrap();
        assert_eq!(
            c.trigger(3, 11, [1; 32], true),
            Err(RollbackError::NotAdjacent)
        );
        assert_eq!(
            c.trigger(4, 10, [1; 32], true),
            Err(RollbackError::StaleFence)
        );
        assert_eq!(
            c.trigger(4, 11, [1; 32], false),
            Err(RollbackError::OldKeyNotRetired)
        );
    }
}
