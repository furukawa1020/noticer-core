#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum RecoveryCapability {
    Observe = 0,
    Diagnose = 1,
    Restore = 2,
    Release = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Authority {
    pub capability: RecoveryCapability,
    pub epoch: u64,
    pub expires_at: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityError {
    EpochMismatch,
    Expired,
    InsufficientCapability,
    Escalation,
}

impl Authority {
    pub fn authorize(
        &self,
        required: RecoveryCapability,
        epoch: u64,
        now: u64,
    ) -> Result<(), AuthorityError> {
        if self.epoch != epoch {
            return Err(AuthorityError::EpochMismatch);
        }
        if now > self.expires_at {
            return Err(AuthorityError::Expired);
        }
        if self.capability < required {
            return Err(AuthorityError::InsufficientCapability);
        }
        Ok(())
    }
    pub fn attenuate(
        &self,
        capability: RecoveryCapability,
        expires_at: u64,
    ) -> Result<Self, AuthorityError> {
        if capability > self.capability || expires_at > self.expires_at {
            return Err(AuthorityError::Escalation);
        }
        Ok(Self {
            capability,
            epoch: self.epoch,
            expires_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lattice_authorizes_only_downward_actions() {
        let authority = Authority {
            capability: RecoveryCapability::Restore,
            epoch: 4,
            expires_at: 100,
        };
        assert_eq!(
            authority.authorize(RecoveryCapability::Diagnose, 4, 90),
            Ok(())
        );
        assert_eq!(
            authority.authorize(RecoveryCapability::Release, 4, 90),
            Err(AuthorityError::InsufficientCapability)
        );
    }
    #[test]
    fn attenuation_cannot_expand_capability_or_lifetime() {
        let authority = Authority {
            capability: RecoveryCapability::Restore,
            epoch: 4,
            expires_at: 100,
        };
        assert_eq!(
            authority.attenuate(RecoveryCapability::Release, 90),
            Err(AuthorityError::Escalation)
        );
        assert_eq!(
            authority.attenuate(RecoveryCapability::Observe, 101),
            Err(AuthorityError::Escalation)
        );
    }
}
