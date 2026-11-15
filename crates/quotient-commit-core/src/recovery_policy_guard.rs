#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyVersion {
    pub epoch: u64,
    pub generation: u64,
    pub digest: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuardError {
    Invalid,
    EpochRollback,
    GenerationRollback,
    Equivocation,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct PolicyRollbackGuard {
    current: Option<PolicyVersion>,
}
impl PolicyRollbackGuard {
    pub fn accept(&mut self, next: PolicyVersion) -> Result<(), GuardError> {
        if next.epoch == 0 || next.generation == 0 || next.digest == [0; 32] {
            return Err(GuardError::Invalid);
        }
        if let Some(c) = self.current {
            if next.epoch < c.epoch {
                return Err(GuardError::EpochRollback);
            }
            if next.epoch == c.epoch && next.generation < c.generation {
                return Err(GuardError::GenerationRollback);
            }
            if next.epoch == c.epoch && next.generation == c.generation && next.digest != c.digest {
                return Err(GuardError::Equivocation);
            }
        }
        self.current = Some(next);
        Ok(())
    }
    #[must_use]
    pub const fn current(&self) -> Option<PolicyVersion> {
        self.current
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn v(e: u64, g: u64, d: u8) -> PolicyVersion {
        PolicyVersion {
            epoch: e,
            generation: g,
            digest: [d; 32],
        }
    }
    #[test]
    fn monotonic_updates_pass() {
        let mut x = PolicyRollbackGuard::default();
        x.accept(v(1, 1, 1)).unwrap();
        x.accept(v(1, 2, 2)).unwrap();
        x.accept(v(2, 1, 3)).unwrap()
    }
    #[test]
    fn rollback_and_equivocation_fail() {
        let mut x = PolicyRollbackGuard::default();
        x.accept(v(2, 3, 1)).unwrap();
        assert_eq!(x.accept(v(1, 4, 2)), Err(GuardError::EpochRollback));
        assert_eq!(x.accept(v(2, 2, 2)), Err(GuardError::GenerationRollback));
        assert_eq!(x.accept(v(2, 3, 2)), Err(GuardError::Equivocation));
    }
}
