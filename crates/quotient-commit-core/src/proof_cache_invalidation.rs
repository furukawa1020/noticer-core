use crate::{proof_cache_binding::CacheBinding, receipt::hmac_sha256};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum InvalidationReason {
    PolicyChanged = 1,
    VerifierSetChanged = 2,
    EpochAdvanced = 3,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidationWitness {
    pub old_binding: [u8; 32],
    pub reason: InvalidationReason,
    pub new_context_digest: [u8; 32],
    pub epoch: u64,
    pub authenticator: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidationError {
    EmptyContext,
    BindingMismatch,
    Authentication,
}
pub fn issue(
    old: CacheBinding,
    reason: InvalidationReason,
    new_context_digest: [u8; 32],
    epoch: u64,
    key: [u8; 32],
) -> Result<InvalidationWitness, InvalidationError> {
    if new_context_digest == [0; 32] {
        return Err(InvalidationError::EmptyContext);
    }
    let mut v = InvalidationWitness {
        old_binding: old.authenticator,
        reason,
        new_context_digest,
        epoch,
        authenticator: [0; 32],
    };
    v.authenticator = auth(v, key);
    Ok(v)
}
pub fn verify(
    old: CacheBinding,
    v: InvalidationWitness,
    key: [u8; 32],
) -> Result<(), InvalidationError> {
    if v.old_binding != old.authenticator {
        return Err(InvalidationError::BindingMismatch);
    }
    if v.authenticator != auth(v, key) {
        return Err(InvalidationError::Authentication);
    }
    Ok(())
}
fn auth(mut v: InvalidationWitness, key: [u8; 32]) -> [u8; 32] {
    v.authenticator = [0; 32];
    let mut b = Vec::new();
    b.extend_from_slice(b"noticer.cache-invalidation.v1");
    b.extend_from_slice(&v.old_binding);
    b.push(v.reason as u8);
    b.extend_from_slice(&v.new_context_digest);
    b.extend_from_slice(&v.epoch.to_be_bytes());
    hmac_sha256(key, &b)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof_cache_binding::issue as cache;
    const K: [u8; 32] = [1; 32];
    #[test]
    fn verifies_invalidation() {
        let c = cache([1; 32], 2, [3; 32], [4; 32], 100, K);
        let v = issue(c, InvalidationReason::PolicyChanged, [5; 32], 3, K).unwrap();
        assert_eq!(verify(c, v, K), Ok(()))
    }
    #[test]
    fn rejects_other_entry() {
        let c = cache([1; 32], 2, [3; 32], [4; 32], 100, K);
        let other = cache([9; 32], 2, [3; 32], [4; 32], 100, K);
        let v = issue(c, InvalidationReason::PolicyChanged, [5; 32], 3, K).unwrap();
        assert_eq!(verify(other, v, K), Err(InvalidationError::BindingMismatch));
    }
}
