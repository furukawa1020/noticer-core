//! Monotonic recovery authentication-key rotation.

use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RotationView {
    pub active_epoch: u64,
    pub staged_epoch: Option<u64>,
    pub previous_epoch: Option<u64>,
    pub overlap_ends_at: Option<u64>,
}
#[derive(Debug)]
struct EpochKey {
    epoch: u64,
    key: [u8; 32],
}
#[derive(Debug)]
pub struct RecoveryKeyRotation {
    active: EpochKey,
    staged: Option<EpochKey>,
    previous: Option<EpochKey>,
    overlap_ends_at: Option<u64>,
    observed_time: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RotationError {
    InvalidEpoch,
    InvalidKey,
    AlreadyStaged,
    NothingStaged,
    PreviousKeyPresent,
    InvalidOverlap,
    ClockRollback,
    OverlapActive,
    EpochRejected,
}

impl RecoveryKeyRotation {
    pub fn new(epoch: u64, key: [u8; 32]) -> Result<Self, RotationError> {
        if epoch == 0 {
            return Err(RotationError::InvalidEpoch);
        }
        if key == [0; 32] {
            return Err(RotationError::InvalidKey);
        }
        Ok(Self {
            active: EpochKey { epoch, key },
            staged: None,
            previous: None,
            overlap_ends_at: None,
            observed_time: 0,
        })
    }
    pub fn prepare(&mut self, epoch: u64, key: [u8; 32]) -> Result<(), RotationError> {
        if self.staged.is_some() {
            return Err(RotationError::AlreadyStaged);
        }
        if self.previous.is_some() {
            return Err(RotationError::PreviousKeyPresent);
        }
        if epoch
            != self
                .active
                .epoch
                .checked_add(1)
                .ok_or(RotationError::InvalidEpoch)?
        {
            return Err(RotationError::InvalidEpoch);
        }
        if key == [0; 32] || key == self.active.key {
            return Err(RotationError::InvalidKey);
        }
        self.staged = Some(EpochKey { epoch, key });
        Ok(())
    }
    pub fn activate(&mut self, now: u64, overlap: u64) -> Result<(), RotationError> {
        self.observe(now)?;
        if overlap == 0 {
            return Err(RotationError::InvalidOverlap);
        }
        let staged = self.staged.take().ok_or(RotationError::NothingStaged)?;
        let old = std::mem::replace(&mut self.active, staged);
        self.previous = Some(old);
        self.overlap_ends_at = Some(
            now.checked_add(overlap)
                .ok_or(RotationError::InvalidOverlap)?,
        );
        Ok(())
    }
    pub fn accepts(&self, epoch: u64, now: u64) -> Result<(), RotationError> {
        if now < self.observed_time {
            return Err(RotationError::ClockRollback);
        }
        if epoch == self.active.epoch {
            return Ok(());
        }
        if self
            .previous
            .as_ref()
            .is_some_and(|value| value.epoch == epoch)
            && self.overlap_ends_at.is_some_and(|end| now < end)
        {
            return Ok(());
        }
        Err(RotationError::EpochRejected)
    }
    pub fn retire_previous(&mut self, now: u64) -> Result<(), RotationError> {
        self.observe(now)?;
        if self.overlap_ends_at.is_some_and(|end| now < end) {
            return Err(RotationError::OverlapActive);
        }
        let mut previous = self.previous.take().ok_or(RotationError::EpochRejected)?;
        previous.key.zeroize();
        self.overlap_ends_at = None;
        Ok(())
    }
    #[must_use]
    pub fn view(&self) -> RotationView {
        RotationView {
            active_epoch: self.active.epoch,
            staged_epoch: self.staged.as_ref().map(|v| v.epoch),
            previous_epoch: self.previous.as_ref().map(|v| v.epoch),
            overlap_ends_at: self.overlap_ends_at,
        }
    }
    fn observe(&mut self, now: u64) -> Result<(), RotationError> {
        if now < self.observed_time {
            return Err(RotationError::ClockRollback);
        }
        self.observed_time = now;
        Ok(())
    }
}

impl Drop for RecoveryKeyRotation {
    fn drop(&mut self) {
        self.active.key.zeroize();
        if let Some(value) = &mut self.staged {
            value.key.zeroize();
        }
        if let Some(value) = &mut self.previous {
            value.key.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rotation_has_bounded_overlap_then_rejects_old_epoch() {
        let mut keys = RecoveryKeyRotation::new(4, [1; 32]).unwrap();
        keys.prepare(5, [2; 32]).unwrap();
        keys.activate(100, 10).unwrap();
        assert_eq!(keys.accepts(4, 109), Ok(()));
        assert_eq!(keys.retire_previous(109), Err(RotationError::OverlapActive));
        keys.retire_previous(110).unwrap();
        assert_eq!(keys.accepts(4, 110), Err(RotationError::EpochRejected));
        assert_eq!(keys.accepts(5, 110), Ok(()));
    }
    #[test]
    fn skipped_epoch_reuse_and_clock_rollback_fail() {
        let mut keys = RecoveryKeyRotation::new(4, [1; 32]).unwrap();
        assert_eq!(keys.prepare(6, [2; 32]), Err(RotationError::InvalidEpoch));
        assert_eq!(keys.prepare(5, [1; 32]), Err(RotationError::InvalidKey));
        keys.prepare(5, [2; 32]).unwrap();
        keys.activate(10, 2).unwrap();
        assert_eq!(keys.retire_previous(9), Err(RotationError::ClockRollback));
    }
}
