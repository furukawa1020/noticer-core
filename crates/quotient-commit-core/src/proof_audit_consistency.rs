use crate::{
    proof_audit_checkpoint::{verify as verify_checkpoint, AuditCheckpoint},
    receipt::hmac_sha256,
};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsistencyProof {
    pub old: AuditCheckpoint,
    pub new: AuditCheckpoint,
    pub prefix_root: [u8; 32],
    pub extension_digest: [u8; 32],
    pub authenticator: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsistencyError {
    CheckpointInvalid,
    LengthRollback,
    EpochRollback,
    PrefixMismatch,
    EmptyExtension,
    Authentication,
}
pub fn issue(
    old: AuditCheckpoint,
    new: AuditCheckpoint,
    extension_digest: [u8; 32],
    key: [u8; 32],
) -> Result<ConsistencyProof, ConsistencyError> {
    validate(old, new, old.root, extension_digest, key)?;
    let mut v = ConsistencyProof {
        old,
        new,
        prefix_root: old.root,
        extension_digest,
        authenticator: [0; 32],
    };
    v.authenticator = auth(v, key);
    Ok(v)
}
pub fn verify(v: ConsistencyProof, key: [u8; 32]) -> Result<(), ConsistencyError> {
    validate(v.old, v.new, v.prefix_root, v.extension_digest, key)?;
    if v.authenticator != auth(v, key) {
        return Err(ConsistencyError::Authentication);
    }
    Ok(())
}
fn validate(
    old: AuditCheckpoint,
    new: AuditCheckpoint,
    prefix: [u8; 32],
    extension: [u8; 32],
    key: [u8; 32],
) -> Result<(), ConsistencyError> {
    verify_checkpoint(old, key).map_err(|_| ConsistencyError::CheckpointInvalid)?;
    verify_checkpoint(new, key).map_err(|_| ConsistencyError::CheckpointInvalid)?;
    if new.length <= old.length {
        return Err(ConsistencyError::LengthRollback);
    }
    if new.epoch < old.epoch {
        return Err(ConsistencyError::EpochRollback);
    }
    if prefix != old.root {
        return Err(ConsistencyError::PrefixMismatch);
    }
    if extension == [0; 32] {
        return Err(ConsistencyError::EmptyExtension);
    }
    Ok(())
}
fn auth(mut v: ConsistencyProof, key: [u8; 32]) -> [u8; 32] {
    v.authenticator = [0; 32];
    let mut b = Vec::new();
    b.extend_from_slice(b"noticer.audit-consistency.v1");
    b.extend_from_slice(&v.old.authenticator);
    b.extend_from_slice(&v.new.authenticator);
    b.extend_from_slice(&v.prefix_root);
    b.extend_from_slice(&v.extension_digest);
    hmac_sha256(key, &b)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof_audit_checkpoint::issue as checkpoint;
    const K: [u8; 32] = [7; 32];
    #[test]
    fn verifies_append() {
        let a = checkpoint(1, [1; 32], 1, K).unwrap();
        let b = checkpoint(2, [2; 32], 1, K).unwrap();
        let p = issue(a, b, [3; 32], K).unwrap();
        assert_eq!(verify(p, K), Ok(()))
    }
    #[test]
    fn rejects_rollback() {
        let a = checkpoint(2, [1; 32], 1, K).unwrap();
        let b = checkpoint(1, [2; 32], 1, K).unwrap();
        assert_eq!(
            issue(a, b, [3; 32], K),
            Err(ConsistencyError::LengthRollback)
        );
    }
}
