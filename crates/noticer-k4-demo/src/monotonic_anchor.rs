use crate::authenticated_public_clock::{
    AuthenticatedClockError, AuthenticatedDurablePublicClock, PublicClockAuthKey,
};
use std::path::Path;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnchorBinding {
    pub epoch: u32,
    pub generation: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MonotonicAnchorError {
    Unavailable,
    BindingMismatch,
    UpdateFailed,
}
pub trait MonotonicAnchor {
    fn current(&mut self, binding: AnchorBinding) -> Result<u64, MonotonicAnchorError>;
    fn advance(&mut self, binding: AnchorBinding, slot: u64) -> Result<(), MonotonicAnchorError>;
}
#[derive(Debug)]
pub enum AnchoredClockError {
    Clock(AuthenticatedClockError),
    Anchor(MonotonicAnchorError),
    Poisoned,
}
pub struct AnchoredAuthenticatedClock<A> {
    clock: AuthenticatedDurablePublicClock,
    anchor: A,
    binding: AnchorBinding,
    poisoned: bool,
}
impl<A: MonotonicAnchor> AnchoredAuthenticatedClock<A> {
    pub fn open(
        path: impl AsRef<Path>,
        binding: AnchorBinding,
        key: PublicClockAuthKey,
        mut anchor: A,
    ) -> Result<Self, AnchoredClockError> {
        let slot = anchor
            .current(binding)
            .map_err(AnchoredClockError::Anchor)?;
        let clock = AuthenticatedDurablePublicClock::open(
            path,
            binding.epoch,
            binding.generation,
            slot,
            key,
        )
        .map_err(AnchoredClockError::Clock)?;
        Ok(Self {
            clock,
            anchor,
            binding,
            poisoned: false,
        })
    }
    pub const fn slot(&self) -> u64 {
        self.clock.slot()
    }
    pub fn advance(&mut self, slot: u64) -> Result<(), AnchoredClockError> {
        if self.poisoned {
            return Err(AnchoredClockError::Poisoned);
        }
        self.clock
            .advance(slot)
            .map_err(AnchoredClockError::Clock)?;
        if let Err(e) = self.anchor.advance(self.binding, slot) {
            self.poisoned = true;
            return Err(AnchoredClockError::Anchor(e));
        }
        Ok(())
    }
}
