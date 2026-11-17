use crate::receipt::hmac_sha256;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditCheckpoint {
    pub length: u64,
    pub root: [u8; 32],
    pub epoch: u64,
    pub authenticator: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointError {
    EmptyLog,
    EmptyRoot,
    Authentication,
}
pub fn issue(
    length: u64,
    root: [u8; 32],
    epoch: u64,
    key: [u8; 32],
) -> Result<AuditCheckpoint, CheckpointError> {
    if length == 0 {
        return Err(CheckpointError::EmptyLog);
    }
    if root == [0; 32] {
        return Err(CheckpointError::EmptyRoot);
    }
    let mut v = AuditCheckpoint {
        length,
        root,
        epoch,
        authenticator: [0; 32],
    };
    v.authenticator = auth(v, key);
    Ok(v)
}
pub fn verify(v: AuditCheckpoint, key: [u8; 32]) -> Result<(), CheckpointError> {
    if v.authenticator != auth(v, key) {
        return Err(CheckpointError::Authentication);
    }
    Ok(())
}
fn auth(mut v: AuditCheckpoint, key: [u8; 32]) -> [u8; 32] {
    v.authenticator = [0; 32];
    let mut b = Vec::new();
    b.extend_from_slice(b"noticer.audit-checkpoint.v1");
    b.extend_from_slice(&v.length.to_be_bytes());
    b.extend_from_slice(&v.root);
    b.extend_from_slice(&v.epoch.to_be_bytes());
    hmac_sha256(key, &b)
}
#[cfg(test)]
mod tests {
    use super::*;
    const K: [u8; 32] = [4; 32];
    #[test]
    fn verifies_checkpoint() {
        let v = issue(3, [1; 32], 2, K).unwrap();
        assert_eq!(verify(v, K), Ok(()))
    }
    #[test]
    fn rejects_tamper() {
        let mut v = issue(3, [1; 32], 2, K).unwrap();
        v.length = 4;
        assert_eq!(verify(v, K), Err(CheckpointError::Authentication));
    }
}
