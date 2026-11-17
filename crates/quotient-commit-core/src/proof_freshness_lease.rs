use crate::receipt::hmac_sha256;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProofLease {
    pub proof_digest: [u8; 32],
    pub epoch: u64,
    pub sequence: u64,
    pub expires_at: u64,
    pub authenticator: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseError {
    EpochMismatch,
    StaleSequence,
    Expired,
    Authentication,
}
pub fn issue(
    proof_digest: [u8; 32],
    epoch: u64,
    sequence: u64,
    expires_at: u64,
    key: [u8; 32],
) -> ProofLease {
    let mut v = ProofLease {
        proof_digest,
        epoch,
        sequence,
        expires_at,
        authenticator: [0; 32],
    };
    v.authenticator = auth(v, key);
    v
}
pub fn verify(
    v: ProofLease,
    epoch: u64,
    min_sequence: u64,
    now: u64,
    key: [u8; 32],
) -> Result<(), LeaseError> {
    if v.authenticator != auth(v, key) {
        return Err(LeaseError::Authentication);
    }
    if v.epoch != epoch {
        return Err(LeaseError::EpochMismatch);
    }
    if v.sequence < min_sequence {
        return Err(LeaseError::StaleSequence);
    }
    if now > v.expires_at {
        return Err(LeaseError::Expired);
    }
    Ok(())
}
fn auth(mut v: ProofLease, key: [u8; 32]) -> [u8; 32] {
    v.authenticator = [0; 32];
    let mut b = Vec::new();
    b.extend_from_slice(b"noticer.proof-lease.v1");
    b.extend_from_slice(&v.proof_digest);
    b.extend_from_slice(&v.epoch.to_be_bytes());
    b.extend_from_slice(&v.sequence.to_be_bytes());
    b.extend_from_slice(&v.expires_at.to_be_bytes());
    hmac_sha256(key, &b)
}
#[cfg(test)]
mod tests {
    use super::*;
    const K: [u8; 32] = [2; 32];
    #[test]
    fn verifies_fresh() {
        let v = issue([1; 32], 3, 4, 100, K);
        assert_eq!(verify(v, 3, 4, 90, K), Ok(()))
    }
    #[test]
    fn rejects_stale() {
        let v = issue([1; 32], 3, 4, 100, K);
        assert_eq!(verify(v, 3, 5, 90, K), Err(LeaseError::StaleSequence));
    }
}
