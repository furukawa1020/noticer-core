use crate::receipt::hmac_sha256;
use std::collections::BTreeSet;
const D: &[u8] = b"noticer.recovery-custody-share.v1\0";
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Custodian {
    pub id: [u8; 16],
    pub key: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CustodyShare {
    pub custodian: [u8; 16],
    pub key_digest: [u8; 32],
    pub epoch: u64,
    pub authenticator: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustodyError {
    Invalid,
    Duplicate,
    Unknown,
    InvalidShare,
    Insufficient,
}
pub fn share(c: Custodian, digest: [u8; 32], epoch: u64) -> Result<CustodyShare, CustodyError> {
    if c.id == [0; 16] || c.key == [0; 32] || digest == [0; 32] || epoch == 0 {
        return Err(CustodyError::Invalid);
    }
    let mut s = CustodyShare {
        custodian: c.id,
        key_digest: digest,
        epoch,
        authenticator: [0; 32],
    };
    s.authenticator = auth(s, c.key);
    Ok(s)
}
pub fn verify(
    shares: &[CustodyShare],
    custodians: &[Custodian],
    threshold: usize,
) -> Result<(), CustodyError> {
    if threshold == 0 || shares.len() < threshold {
        return Err(CustodyError::Insufficient);
    }
    let first = shares.first().ok_or(CustodyError::Insufficient)?;
    let mut ids = BTreeSet::new();
    for s in shares {
        if !ids.insert(s.custodian) {
            return Err(CustodyError::Duplicate);
        }
        if s.key_digest != first.key_digest || s.epoch != first.epoch {
            return Err(CustodyError::InvalidShare);
        }
        let c = custodians
            .iter()
            .find(|c| c.id == s.custodian)
            .ok_or(CustodyError::Unknown)?;
        if s.authenticator != auth(*s, c.key) {
            return Err(CustodyError::InvalidShare);
        }
    }
    Ok(())
}
fn auth(mut s: CustodyShare, k: [u8; 32]) -> [u8; 32] {
    s.authenticator = [0; 32];
    let mut b = Vec::from(D);
    b.extend_from_slice(&s.custodian);
    b.extend_from_slice(&s.key_digest);
    b.extend_from_slice(&s.epoch.to_be_bytes());
    hmac_sha256(k, &b)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn cs() -> Vec<Custodian> {
        (1..=3)
            .map(|i| Custodian {
                id: [i; 16],
                key: [i; 32],
            })
            .collect()
    }
    #[test]
    fn distinct_shares_reach_threshold() {
        let c = cs();
        let s = vec![
            share(c[0], [9; 32], 2).unwrap(),
            share(c[1], [9; 32], 2).unwrap(),
        ];
        assert_eq!(verify(&s, &c, 2), Ok(()))
    }
    #[test]
    fn duplicate_and_low_threshold_fail() {
        let c = cs();
        let s = share(c[0], [9; 32], 2).unwrap();
        assert_eq!(verify(&[s, s], &c, 2), Err(CustodyError::Duplicate));
        assert_eq!(verify(&[s], &c, 2), Err(CustodyError::Insufficient));
    }
}
