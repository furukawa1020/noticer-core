//! Monotonic fencing leases preventing concurrent recovery authorities.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeaseGrant {
    pub holder: [u8; 16],
    pub fencing_token: u64,
    pub expires_at: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseError {
    InvalidHolder,
    InvalidDuration,
    ClockRollback,
    AlreadyHeld,
    StaleFencingToken,
    Expired,
    Overflow,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RecoveryLease {
    generation: u64,
    active: Option<LeaseGrant>,
    observed_time: u64,
}

impl RecoveryLease {
    pub fn acquire(
        &mut self,
        holder: [u8; 16],
        now: u64,
        duration: u64,
    ) -> Result<LeaseGrant, LeaseError> {
        self.observe(now)?;
        validate(holder, duration)?;
        if self.active.is_some_and(|lease| now < lease.expires_at) {
            return Err(LeaseError::AlreadyHeld);
        }
        self.generation = self.generation.checked_add(1).ok_or(LeaseError::Overflow)?;
        let grant = LeaseGrant {
            holder,
            fencing_token: self.generation,
            expires_at: now.checked_add(duration).ok_or(LeaseError::Overflow)?,
        };
        self.active = Some(grant);
        Ok(grant)
    }

    pub fn renew(
        &mut self,
        grant: LeaseGrant,
        now: u64,
        duration: u64,
    ) -> Result<LeaseGrant, LeaseError> {
        self.observe(now)?;
        validate(grant.holder, duration)?;
        self.authorize(grant.holder, grant.fencing_token, now)?;
        let renewed = LeaseGrant {
            expires_at: now.checked_add(duration).ok_or(LeaseError::Overflow)?,
            ..grant
        };
        self.active = Some(renewed);
        Ok(renewed)
    }

    pub fn release(
        &mut self,
        holder: [u8; 16],
        fencing_token: u64,
        now: u64,
    ) -> Result<(), LeaseError> {
        self.observe(now)?;
        self.authorize(holder, fencing_token, now)?;
        self.active = None;
        Ok(())
    }

    pub fn authorize(
        &self,
        holder: [u8; 16],
        fencing_token: u64,
        now: u64,
    ) -> Result<(), LeaseError> {
        if now < self.observed_time {
            return Err(LeaseError::ClockRollback);
        }
        let active = self.active.ok_or(LeaseError::StaleFencingToken)?;
        if holder != active.holder || fencing_token != active.fencing_token {
            return Err(LeaseError::StaleFencingToken);
        }
        if now >= active.expires_at {
            return Err(LeaseError::Expired);
        }
        Ok(())
    }

    #[must_use]
    pub const fn active(&self) -> Option<LeaseGrant> {
        self.active
    }
    fn observe(&mut self, now: u64) -> Result<(), LeaseError> {
        if now < self.observed_time {
            return Err(LeaseError::ClockRollback);
        }
        self.observed_time = now;
        Ok(())
    }
}

fn validate(holder: [u8; 16], duration: u64) -> Result<(), LeaseError> {
    if holder == [0; 16] {
        Err(LeaseError::InvalidHolder)
    } else if duration == 0 {
        Err(LeaseError::InvalidDuration)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn expired_holder_is_fenced_after_reacquisition() {
        let mut leases = RecoveryLease::default();
        let old = leases.acquire([1; 16], 10, 5).unwrap();
        assert_eq!(leases.acquire([2; 16], 12, 5), Err(LeaseError::AlreadyHeld));
        let new = leases.acquire([2; 16], 15, 5).unwrap();
        assert!(new.fencing_token > old.fencing_token);
        assert_eq!(
            leases.authorize(old.holder, old.fencing_token, 16),
            Err(LeaseError::StaleFencingToken)
        );
        assert_eq!(leases.authorize(new.holder, new.fencing_token, 16), Ok(()));
    }
    #[test]
    fn renewal_release_and_clock_rollback_are_guarded() {
        let mut leases = RecoveryLease::default();
        let grant = leases.acquire([1; 16], 20, 5).unwrap();
        let renewed = leases.renew(grant, 22, 10).unwrap();
        assert_eq!(renewed.expires_at, 32);
        assert_eq!(
            leases.release([1; 16], renewed.fencing_token, 21),
            Err(LeaseError::ClockRollback)
        );
        leases.release([1; 16], renewed.fencing_token, 23).unwrap();
        assert_eq!(leases.active(), None);
    }
}
