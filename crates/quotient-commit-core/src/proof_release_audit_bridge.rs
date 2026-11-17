use crate::{
    proof_audit_checkpoint::{verify as verify_checkpoint, AuditCheckpoint},
    receipt::hmac_sha256,
    recovery_release_proof_chain::ReleaseProof,
};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleaseAuditBridge {
    pub release_index: u64,
    pub release_authenticator: [u8; 32],
    pub checkpoint_authenticator: [u8; 32],
    pub authenticator: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeError {
    CheckpointInvalid,
    ReleaseOutsideCheckpoint,
    Authentication,
}
pub fn issue(
    release: ReleaseProof,
    checkpoint: AuditCheckpoint,
    key: [u8; 32],
) -> Result<ReleaseAuditBridge, BridgeError> {
    verify_checkpoint(checkpoint, key).map_err(|_| BridgeError::CheckpointInvalid)?;
    if release.index >= checkpoint.length {
        return Err(BridgeError::ReleaseOutsideCheckpoint);
    }
    let mut v = ReleaseAuditBridge {
        release_index: release.index,
        release_authenticator: release.authenticator,
        checkpoint_authenticator: checkpoint.authenticator,
        authenticator: [0; 32],
    };
    v.authenticator = auth(v, key);
    Ok(v)
}
pub fn verify(v: ReleaseAuditBridge, key: [u8; 32]) -> Result<(), BridgeError> {
    if v.authenticator != auth(v, key) {
        return Err(BridgeError::Authentication);
    }
    Ok(())
}
fn auth(mut v: ReleaseAuditBridge, key: [u8; 32]) -> [u8; 32] {
    v.authenticator = [0; 32];
    let mut b = Vec::new();
    b.extend_from_slice(b"noticer.release-audit-bridge.v1");
    b.extend_from_slice(&v.release_index.to_be_bytes());
    b.extend_from_slice(&v.release_authenticator);
    b.extend_from_slice(&v.checkpoint_authenticator);
    hmac_sha256(key, &b)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        proof_audit_checkpoint::issue as checkpoint, recovery_release_proof_chain::append,
    };
    const K: [u8; 32] = [8; 32];
    #[test]
    fn verifies_bridge() {
        let r = append(None, 1, [1; 32], K).unwrap();
        let c = checkpoint(1, [2; 32], 1, K).unwrap();
        let b = issue(r, c, K).unwrap();
        assert_eq!(verify(b, K), Ok(()))
    }
    #[test]
    fn rejects_outside() {
        let r = append(None, 1, [1; 32], K).unwrap();
        let mut r2 = r;
        r2.index = 1;
        let c = checkpoint(1, [2; 32], 1, K).unwrap();
        assert_eq!(issue(r2, c, K), Err(BridgeError::ReleaseOutsideCheckpoint));
    }
}
