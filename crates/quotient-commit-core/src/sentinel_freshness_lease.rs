//! Monotonic freshness lease for runtime assurance evidence.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssuranceFreshnessLease {
    pub issued_millis: u64,
    pub expires_millis: u64,
    pub evidence_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FreshnessError {
    ZeroDigest,
    InvalidInterval,
    NotYetValid,
    Expired,
}

impl AssuranceFreshnessLease {
    pub fn new(
        issued_millis: u64,
        duration_millis: u64,
        evidence_digest: [u8; 32],
    ) -> Result<Self, FreshnessError> {
        if evidence_digest == [0; 32] {
            return Err(FreshnessError::ZeroDigest);
        }
        let expires_millis = issued_millis
            .checked_add(duration_millis)
            .ok_or(FreshnessError::InvalidInterval)?;
        if issued_millis == 0 || duration_millis == 0 {
            return Err(FreshnessError::InvalidInterval);
        }
        Ok(Self {
            issued_millis,
            expires_millis,
            evidence_digest,
        })
    }

    pub fn verify(self, now_millis: u64) -> Result<(), FreshnessError> {
        if now_millis < self.issued_millis {
            return Err(FreshnessError::NotYetValid);
        }
        if now_millis >= self.expires_millis {
            return Err(FreshnessError::Expired);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_evidence_invalidates_the_lease() {
        let lease = AssuranceFreshnessLease::new(10, 5, [1; 32]).unwrap();
        assert_eq!(lease.verify(14), Ok(()));
        assert_eq!(lease.verify(15), Err(FreshnessError::Expired));
    }
}
