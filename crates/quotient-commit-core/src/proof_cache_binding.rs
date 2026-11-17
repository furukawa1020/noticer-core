use crate::receipt::hmac_sha256;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheBinding {
    pub policy_digest: [u8; 32],
    pub epoch: u64,
    pub verifier_set_digest: [u8; 32],
    pub proof_digest: [u8; 32],
    pub expires_at: u64,
    pub authenticator: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheError {
    ContextMismatch,
    Expired,
    Authentication,
}
pub fn issue(
    policy_digest: [u8; 32],
    epoch: u64,
    verifier_set_digest: [u8; 32],
    proof_digest: [u8; 32],
    expires_at: u64,
    key: [u8; 32],
) -> CacheBinding {
    let mut v = CacheBinding {
        policy_digest,
        epoch,
        verifier_set_digest,
        proof_digest,
        expires_at,
        authenticator: [0; 32],
    };
    v.authenticator = auth(v, key);
    v
}
pub fn verify(
    v: CacheBinding,
    policy: [u8; 32],
    epoch: u64,
    verifiers: [u8; 32],
    now: u64,
    key: [u8; 32],
) -> Result<(), CacheError> {
    if v.authenticator != auth(v, key) {
        return Err(CacheError::Authentication);
    }
    if v.policy_digest != policy || v.epoch != epoch || v.verifier_set_digest != verifiers {
        return Err(CacheError::ContextMismatch);
    }
    if now > v.expires_at {
        return Err(CacheError::Expired);
    }
    Ok(())
}
fn auth(mut v: CacheBinding, key: [u8; 32]) -> [u8; 32] {
    v.authenticator = [0; 32];
    let mut b = Vec::new();
    b.extend_from_slice(b"noticer.proof-cache-binding.v1");
    b.extend_from_slice(&v.policy_digest);
    b.extend_from_slice(&v.epoch.to_be_bytes());
    b.extend_from_slice(&v.verifier_set_digest);
    b.extend_from_slice(&v.proof_digest);
    b.extend_from_slice(&v.expires_at.to_be_bytes());
    hmac_sha256(key, &b)
}
#[cfg(test)]
mod tests {
    use super::*;
    const K: [u8; 32] = [9; 32];
    #[test]
    fn verifies_context() {
        let v = issue([1; 32], 2, [3; 32], [4; 32], 100, K);
        assert_eq!(verify(v, [1; 32], 2, [3; 32], 90, K), Ok(()))
    }
    #[test]
    fn rejects_replay() {
        let v = issue([1; 32], 2, [3; 32], [4; 32], 100, K);
        assert_eq!(
            verify(v, [1; 32], 3, [3; 32], 90, K),
            Err(CacheError::ContextMismatch)
        );
    }
}
