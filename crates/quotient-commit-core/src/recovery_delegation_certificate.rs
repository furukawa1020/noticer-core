use crate::{receipt::hmac_sha256, recovery_authority_lattice::RecoveryCapability};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DelegationCertificate {
    pub issuer: [u8; 16],
    pub subject: [u8; 16],
    pub capability: RecoveryCapability,
    pub scopes: u64,
    pub epoch: u64,
    pub expires_at: u64,
    pub authenticator: [u8; 32],
}

pub fn issue(
    issuer: [u8; 16],
    subject: [u8; 16],
    capability: RecoveryCapability,
    scopes: u64,
    epoch: u64,
    expires_at: u64,
    key: [u8; 32],
) -> DelegationCertificate {
    let mut value = DelegationCertificate {
        issuer,
        subject,
        capability,
        scopes,
        epoch,
        expires_at,
        authenticator: [0; 32],
    };
    value.authenticator = authenticate(value, key);
    value
}
pub fn verify(value: DelegationCertificate, key: [u8; 32]) -> bool {
    value.issuer != value.subject
        && value.scopes != 0
        && value.authenticator == authenticate(value, key)
}
fn authenticate(mut value: DelegationCertificate, key: [u8; 32]) -> [u8; 32] {
    value.authenticator = [0; 32];
    let mut b = Vec::new();
    b.extend_from_slice(b"noticer.delegation.v1");
    b.extend_from_slice(&value.issuer);
    b.extend_from_slice(&value.subject);
    b.push(value.capability as u8);
    b.extend_from_slice(&value.scopes.to_be_bytes());
    b.extend_from_slice(&value.epoch.to_be_bytes());
    b.extend_from_slice(&value.expires_at.to_be_bytes());
    hmac_sha256(key, &b)
}

#[cfg(test)]
mod tests {
    use super::*;
    const K: [u8; 32] = [4; 32];
    #[test]
    fn authenticates_delegation() {
        let v = issue([1; 16], [2; 16], RecoveryCapability::Restore, 3, 7, 100, K);
        assert!(verify(v, K));
    }
    #[test]
    fn rejects_tampering() {
        let mut v = issue([1; 16], [2; 16], RecoveryCapability::Restore, 3, 7, 100, K);
        v.scopes = 7;
        assert!(!verify(v, K));
    }
}
