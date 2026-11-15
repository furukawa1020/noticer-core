use crate::recovery_delegation_certificate::{verify, DelegationCertificate};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChainError {
    Empty,
    Authentication,
    Disconnected,
    EpochMismatch,
    Expired,
    Escalation,
}
pub fn verify_chain(
    chain: &[DelegationCertificate],
    epoch: u64,
    now: u64,
    key: [u8; 32],
) -> Result<[u8; 16], ChainError> {
    if chain.is_empty() {
        return Err(ChainError::Empty);
    }
    for (i, c) in chain.iter().enumerate() {
        if !verify(*c, key) {
            return Err(ChainError::Authentication);
        }
        if c.epoch != epoch {
            return Err(ChainError::EpochMismatch);
        }
        if now > c.expires_at {
            return Err(ChainError::Expired);
        }
        if i > 0 {
            let p = chain[i - 1];
            if p.subject != c.issuer {
                return Err(ChainError::Disconnected);
            }
            if c.capability > p.capability
                || c.scopes & !p.scopes != 0
                || c.expires_at > p.expires_at
            {
                return Err(ChainError::Escalation);
            }
        }
    }
    Ok(chain.last().expect("nonempty").subject)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        recovery_authority_lattice::RecoveryCapability, recovery_delegation_certificate::issue,
    };
    const K: [u8; 32] = [5; 32];
    #[test]
    fn accepts_chain() {
        let a = issue([1; 16], [2; 16], RecoveryCapability::Release, 3, 7, 100, K);
        let b = issue([2; 16], [3; 16], RecoveryCapability::Restore, 1, 7, 90, K);
        assert_eq!(verify_chain(&[a, b], 7, 80, K), Ok([3; 16]));
    }
    #[test]
    fn rejects_disconnect() {
        let a = issue([1; 16], [2; 16], RecoveryCapability::Release, 3, 7, 100, K);
        let b = issue([9; 16], [3; 16], RecoveryCapability::Restore, 1, 7, 90, K);
        assert_eq!(
            verify_chain(&[a, b], 7, 80, K),
            Err(ChainError::Disconnected)
        );
    }
}
