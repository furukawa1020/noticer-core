use crate::{
    proof_audit_checkpoint::{verify, AuditCheckpoint},
    receipt::hmac_sha256,
};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainedCheckpoint {
    pub index: u64,
    pub checkpoint: AuditCheckpoint,
    pub previous: [u8; 32],
    pub authenticator: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChainError {
    CheckpointInvalid,
    IndexGap,
    LengthRollback,
    EpochRollback,
    PreviousMismatch,
    Authentication,
}
pub fn append(
    previous: Option<ChainedCheckpoint>,
    checkpoint: AuditCheckpoint,
    key: [u8; 32],
) -> Result<ChainedCheckpoint, ChainError> {
    verify(checkpoint, key).map_err(|_| ChainError::CheckpointInvalid)?;
    if let Some(p) = previous {
        if checkpoint.length <= p.checkpoint.length {
            return Err(ChainError::LengthRollback);
        }
        if checkpoint.epoch < p.checkpoint.epoch {
            return Err(ChainError::EpochRollback);
        }
    }
    let mut v = ChainedCheckpoint {
        index: previous.map_or(0, |p| p.index + 1),
        checkpoint,
        previous: previous.map_or([0; 32], |p| p.authenticator),
        authenticator: [0; 32],
    };
    v.authenticator = auth(v, key);
    Ok(v)
}
pub fn verify_chain(chain: &[ChainedCheckpoint], key: [u8; 32]) -> Result<(), ChainError> {
    let mut prev = None;
    for (i, v) in chain.iter().enumerate() {
        if v.index != i as u64 {
            return Err(ChainError::IndexGap);
        }
        if v.previous != prev.map_or([0; 32], |p: ChainedCheckpoint| p.authenticator) {
            return Err(ChainError::PreviousMismatch);
        }
        if v.authenticator != auth(*v, key) {
            return Err(ChainError::Authentication);
        }
        if let Some(p) = prev {
            if v.checkpoint.length <= p.checkpoint.length {
                return Err(ChainError::LengthRollback);
            }
            if v.checkpoint.epoch < p.checkpoint.epoch {
                return Err(ChainError::EpochRollback);
            }
        }
        prev = Some(*v)
    }
    Ok(())
}
fn auth(mut v: ChainedCheckpoint, key: [u8; 32]) -> [u8; 32] {
    v.authenticator = [0; 32];
    let mut b = Vec::new();
    b.extend_from_slice(b"noticer.audit-checkpoint-chain.v1");
    b.extend_from_slice(&v.index.to_be_bytes());
    b.extend_from_slice(&v.checkpoint.authenticator);
    b.extend_from_slice(&v.previous);
    hmac_sha256(key, &b)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof_audit_checkpoint::issue;
    const K: [u8; 32] = [5; 32];
    #[test]
    fn verifies_chain() {
        let a = append(None, issue(1, [1; 32], 1, K).unwrap(), K).unwrap();
        let b = append(Some(a), issue(2, [2; 32], 1, K).unwrap(), K).unwrap();
        assert_eq!(verify_chain(&[a, b], K), Ok(()))
    }
    #[test]
    fn rejects_rollback() {
        let a = append(None, issue(2, [1; 32], 1, K).unwrap(), K).unwrap();
        assert_eq!(
            append(Some(a), issue(1, [2; 32], 1, K).unwrap(), K),
            Err(ChainError::LengthRollback)
        );
    }
}
