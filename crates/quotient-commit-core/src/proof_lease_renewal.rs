use crate::{proof_freshness_lease::ProofLease, receipt::hmac_sha256};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeaseRenewal {
    pub previous: [u8; 32],
    pub new_sequence: u64,
    pub new_expires_at: u64,
    pub authenticator: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RenewalError {
    SequenceNotAdvanced,
    ExpiryNotExtended,
    Authentication,
    PreviousMismatch,
}
pub fn issue(
    previous: ProofLease,
    new_sequence: u64,
    new_expires_at: u64,
    key: [u8; 32],
) -> Result<LeaseRenewal, RenewalError> {
    if new_sequence <= previous.sequence {
        return Err(RenewalError::SequenceNotAdvanced);
    }
    if new_expires_at <= previous.expires_at {
        return Err(RenewalError::ExpiryNotExtended);
    }
    let mut v = LeaseRenewal {
        previous: previous.authenticator,
        new_sequence,
        new_expires_at,
        authenticator: [0; 32],
    };
    v.authenticator = auth(v, key);
    Ok(v)
}
pub fn verify(previous: ProofLease, v: LeaseRenewal, key: [u8; 32]) -> Result<(), RenewalError> {
    if v.previous != previous.authenticator {
        return Err(RenewalError::PreviousMismatch);
    }
    if v.authenticator != auth(v, key) {
        return Err(RenewalError::Authentication);
    }
    if v.new_sequence <= previous.sequence {
        return Err(RenewalError::SequenceNotAdvanced);
    }
    if v.new_expires_at <= previous.expires_at {
        return Err(RenewalError::ExpiryNotExtended);
    }
    Ok(())
}
fn auth(mut v: LeaseRenewal, key: [u8; 32]) -> [u8; 32] {
    v.authenticator = [0; 32];
    let mut b = Vec::new();
    b.extend_from_slice(b"noticer.proof-lease-renewal.v1");
    b.extend_from_slice(&v.previous);
    b.extend_from_slice(&v.new_sequence.to_be_bytes());
    b.extend_from_slice(&v.new_expires_at.to_be_bytes());
    hmac_sha256(key, &b)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof_freshness_lease::issue as lease;
    const K: [u8; 32] = [3; 32];
    #[test]
    fn verifies_renewal() {
        let p = lease([1; 32], 2, 3, 100, K);
        let v = issue(p, 4, 110, K).unwrap();
        assert_eq!(verify(p, v, K), Ok(()))
    }
    #[test]
    fn rejects_stall() {
        let p = lease([1; 32], 2, 3, 100, K);
        assert_eq!(issue(p, 3, 110, K), Err(RenewalError::SequenceNotAdvanced));
    }
}
