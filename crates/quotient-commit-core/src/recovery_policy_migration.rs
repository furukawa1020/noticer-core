use crate::receipt::hmac_sha256;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyMigration {
    pub old_digest: [u8; 32],
    pub new_digest: [u8; 32],
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub approvals: u16,
    pub threshold: u16,
    pub authenticator: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationError {
    SamePolicy,
    EpochRollback,
    InsufficientApprovals,
    Authentication,
}
pub fn issue(
    old_digest: [u8; 32],
    new_digest: [u8; 32],
    old_epoch: u64,
    new_epoch: u64,
    approvals: u16,
    threshold: u16,
    key: [u8; 32],
) -> Result<PolicyMigration, MigrationError> {
    if old_digest == new_digest {
        return Err(MigrationError::SamePolicy);
    }
    if new_epoch <= old_epoch {
        return Err(MigrationError::EpochRollback);
    }
    if threshold == 0 || approvals < threshold {
        return Err(MigrationError::InsufficientApprovals);
    }
    let mut v = PolicyMigration {
        old_digest,
        new_digest,
        old_epoch,
        new_epoch,
        approvals,
        threshold,
        authenticator: [0; 32],
    };
    v.authenticator = auth(v, key);
    Ok(v)
}
pub fn verify(v: PolicyMigration, key: [u8; 32]) -> Result<(), MigrationError> {
    if v.authenticator != auth(v, key) {
        return Err(MigrationError::Authentication);
    }
    if v.new_epoch <= v.old_epoch {
        return Err(MigrationError::EpochRollback);
    }
    if v.approvals < v.threshold {
        return Err(MigrationError::InsufficientApprovals);
    }
    Ok(())
}
fn auth(mut v: PolicyMigration, key: [u8; 32]) -> [u8; 32] {
    v.authenticator = [0; 32];
    let mut b = Vec::new();
    b.extend_from_slice(b"noticer.policy-migration.v1");
    b.extend_from_slice(&v.old_digest);
    b.extend_from_slice(&v.new_digest);
    b.extend_from_slice(&v.old_epoch.to_be_bytes());
    b.extend_from_slice(&v.new_epoch.to_be_bytes());
    b.extend_from_slice(&v.approvals.to_be_bytes());
    b.extend_from_slice(&v.threshold.to_be_bytes());
    hmac_sha256(key, &b)
}
#[cfg(test)]
mod tests {
    use super::*;
    const K: [u8; 32] = [4; 32];
    #[test]
    fn verifies_migration() {
        let v = issue([1; 32], [2; 32], 7, 8, 2, 2, K).unwrap();
        assert_eq!(verify(v, K), Ok(()))
    }
    #[test]
    fn rejects_rollback() {
        assert_eq!(
            issue([1; 32], [2; 32], 7, 7, 2, 2, K),
            Err(MigrationError::EpochRollback)
        );
    }
}
