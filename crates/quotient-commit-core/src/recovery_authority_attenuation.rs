use crate::recovery_authority_lattice::RecoveryCapability;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScopedAuthority {
    pub subject: [u8; 16],
    pub capability: RecoveryCapability,
    pub scopes: u64,
    pub epoch: u64,
    pub expires_at: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttenuationError {
    SubjectUnchanged,
    CapabilityExpanded,
    ScopeExpanded,
    EpochChanged,
    LifetimeExpanded,
}

pub fn verify(parent: ScopedAuthority, child: ScopedAuthority) -> Result<(), AttenuationError> {
    if parent.subject == child.subject {
        return Err(AttenuationError::SubjectUnchanged);
    }
    if child.capability > parent.capability {
        return Err(AttenuationError::CapabilityExpanded);
    }
    if child.scopes & !parent.scopes != 0 {
        return Err(AttenuationError::ScopeExpanded);
    }
    if child.epoch != parent.epoch {
        return Err(AttenuationError::EpochChanged);
    }
    if child.expires_at > parent.expires_at {
        return Err(AttenuationError::LifetimeExpanded);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn authority(
        subject: u8,
        capability: RecoveryCapability,
        scopes: u64,
        expires_at: u64,
    ) -> ScopedAuthority {
        ScopedAuthority {
            subject: [subject; 16],
            capability,
            scopes,
            epoch: 7,
            expires_at,
        }
    }
    #[test]
    fn accepts_strictly_attenuated_authority() {
        assert_eq!(
            verify(
                authority(1, RecoveryCapability::Release, 0b111, 100),
                authority(2, RecoveryCapability::Restore, 0b011, 90)
            ),
            Ok(())
        );
    }
    #[test]
    fn rejects_capability_and_scope_expansion() {
        assert_eq!(
            verify(
                authority(1, RecoveryCapability::Restore, 0b011, 100),
                authority(2, RecoveryCapability::Release, 0b011, 90)
            ),
            Err(AttenuationError::CapabilityExpanded)
        );
        assert_eq!(
            verify(
                authority(1, RecoveryCapability::Restore, 0b001, 100),
                authority(2, RecoveryCapability::Restore, 0b011, 90)
            ),
            Err(AttenuationError::ScopeExpanded)
        );
    }
}
