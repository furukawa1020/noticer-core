use crate::receipt::hmac_sha256;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactionProof {
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
    pub old_length: u64,
    pub retained_start: u64,
    pub retained_end: u64,
    pub epoch: u64,
    pub authenticator: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompactionError {
    SameRoot,
    InvalidRange,
    Authentication,
}
pub fn issue(
    old_root: [u8; 32],
    new_root: [u8; 32],
    old_length: u64,
    retained_start: u64,
    retained_end: u64,
    epoch: u64,
    key: [u8; 32],
) -> Result<CompactionProof, CompactionError> {
    if old_root == new_root {
        return Err(CompactionError::SameRoot);
    }
    if retained_start >= retained_end || retained_end > old_length {
        return Err(CompactionError::InvalidRange);
    }
    let mut v = CompactionProof {
        old_root,
        new_root,
        old_length,
        retained_start,
        retained_end,
        epoch,
        authenticator: [0; 32],
    };
    v.authenticator = auth(v, key);
    Ok(v)
}
pub fn verify(v: CompactionProof, key: [u8; 32]) -> Result<(), CompactionError> {
    if v.retained_start >= v.retained_end || v.retained_end > v.old_length {
        return Err(CompactionError::InvalidRange);
    }
    if v.authenticator != auth(v, key) {
        return Err(CompactionError::Authentication);
    }
    Ok(())
}
fn auth(mut v: CompactionProof, key: [u8; 32]) -> [u8; 32] {
    v.authenticator = [0; 32];
    let mut b = Vec::new();
    b.extend_from_slice(b"noticer.audit-compaction.v1");
    b.extend_from_slice(&v.old_root);
    b.extend_from_slice(&v.new_root);
    for n in [v.old_length, v.retained_start, v.retained_end, v.epoch] {
        b.extend_from_slice(&n.to_be_bytes())
    }
    hmac_sha256(key, &b)
}
#[cfg(test)]
mod tests {
    use super::*;
    const K: [u8; 32] = [6; 32];
    #[test]
    fn verifies_compaction() {
        let v = issue([1; 32], [2; 32], 10, 3, 10, 4, K).unwrap();
        assert_eq!(verify(v, K), Ok(()))
    }
    #[test]
    fn rejects_range() {
        assert_eq!(
            issue([1; 32], [2; 32], 10, 8, 11, 4, K),
            Err(CompactionError::InvalidRange)
        );
    }
}
