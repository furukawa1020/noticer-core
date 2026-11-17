use crate::recovery_authority_lattice::RecoveryCapability;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecayError {
    Expired,
    Exhausted,
    CapabilityExceeded,
    Expansion,
}
pub struct DecayingAuthority {
    capability: RecoveryCapability,
    remaining: u32,
    expires_at: u64,
}
impl DecayingAuthority {
    pub fn new(
        capability: RecoveryCapability,
        operations: u32,
        expires_at: u64,
    ) -> Result<Self, DecayError> {
        if operations == 0 {
            return Err(DecayError::Exhausted);
        }
        Ok(Self {
            capability,
            remaining: operations,
            expires_at,
        })
    }
    pub fn use_once(&mut self, required: RecoveryCapability, now: u64) -> Result<(), DecayError> {
        if now > self.expires_at {
            return Err(DecayError::Expired);
        }
        if self.remaining == 0 {
            return Err(DecayError::Exhausted);
        }
        if required > self.capability {
            return Err(DecayError::CapabilityExceeded);
        }
        self.remaining -= 1;
        if self.remaining == 0 {
            self.capability = RecoveryCapability::Observe
        }
        Ok(())
    }
    pub fn attenuate(&mut self, next: RecoveryCapability) -> Result<(), DecayError> {
        if next > self.capability {
            return Err(DecayError::Expansion);
        }
        self.capability = next;
        Ok(())
    }
    pub fn remaining(&self) -> u32 {
        self.remaining
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn decays_to_observe() {
        let mut a = DecayingAuthority::new(RecoveryCapability::Release, 1, 100).unwrap();
        assert_eq!(a.use_once(RecoveryCapability::Release, 90), Ok(()));
        assert_eq!(
            a.use_once(RecoveryCapability::Release, 90),
            Err(DecayError::Exhausted)
        )
    }
    #[test]
    fn cannot_expand() {
        let mut a = DecayingAuthority::new(RecoveryCapability::Restore, 2, 100).unwrap();
        assert_eq!(
            a.attenuate(RecoveryCapability::Release),
            Err(DecayError::Expansion)
        );
    }
}
