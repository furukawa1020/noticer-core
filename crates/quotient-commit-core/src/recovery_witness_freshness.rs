use crate::receipt::hmac_sha256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FreshnessWitness {
    pub epoch: u64,
    pub sequence: u64,
    pub observed_at: u64,
    pub digest: [u8; 32],
    pub authenticator: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FreshnessError {
    EpochMismatch,
    Replay,
    Stale,
    Future,
    AuthenticationFailed,
}

pub fn issue_witness(
    epoch: u64,
    sequence: u64,
    observed_at: u64,
    digest: [u8; 32],
    key: [u8; 32],
) -> FreshnessWitness {
    let mut witness = FreshnessWitness {
        epoch,
        sequence,
        observed_at,
        digest,
        authenticator: [0; 32],
    };
    witness.authenticator = authenticate(witness, key);
    witness
}

pub fn verify_freshness(
    witness: FreshnessWitness,
    expected_epoch: u64,
    after_sequence: u64,
    now: u64,
    maximum_age: u64,
    maximum_future_skew: u64,
    key: [u8; 32],
) -> Result<(), FreshnessError> {
    if witness.authenticator != authenticate(witness, key) {
        return Err(FreshnessError::AuthenticationFailed);
    }
    if witness.epoch != expected_epoch {
        return Err(FreshnessError::EpochMismatch);
    }
    if witness.sequence <= after_sequence {
        return Err(FreshnessError::Replay);
    }
    if witness.observed_at > now.saturating_add(maximum_future_skew) {
        return Err(FreshnessError::Future);
    }
    if now.saturating_sub(witness.observed_at) > maximum_age {
        return Err(FreshnessError::Stale);
    }
    Ok(())
}

fn authenticate(mut witness: FreshnessWitness, key: [u8; 32]) -> [u8; 32] {
    witness.authenticator = [0; 32];
    let mut bytes = Vec::with_capacity(72);
    bytes.extend_from_slice(b"noticer.freshness-witness.v1");
    bytes.extend_from_slice(&witness.epoch.to_be_bytes());
    bytes.extend_from_slice(&witness.sequence.to_be_bytes());
    bytes.extend_from_slice(&witness.observed_at.to_be_bytes());
    bytes.extend_from_slice(&witness.digest);
    hmac_sha256(key, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    const KEY: [u8; 32] = [5; 32];
    #[test]
    fn accepts_fresh_monotonic_witness() {
        let witness = issue_witness(4, 12, 100, [7; 32], KEY);
        assert_eq!(verify_freshness(witness, 4, 11, 105, 10, 2, KEY), Ok(()));
    }
    #[test]
    fn rejects_replay_staleness_and_tampering() {
        let witness = issue_witness(4, 12, 100, [7; 32], KEY);
        assert_eq!(
            verify_freshness(witness, 4, 12, 105, 10, 2, KEY),
            Err(FreshnessError::Replay)
        );
        assert_eq!(
            verify_freshness(witness, 4, 11, 120, 10, 2, KEY),
            Err(FreshnessError::Stale)
        );
        let mut tampered = witness;
        tampered.digest = [8; 32];
        assert_eq!(
            verify_freshness(tampered, 4, 11, 105, 10, 2, KEY),
            Err(FreshnessError::AuthenticationFailed)
        );
    }
}
