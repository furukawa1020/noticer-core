//! Minimal authenticated state for cold-start recovery bootstrap.
use crate::receipt::hmac_sha256;
const DOMAIN: &[u8] = b"noticer.recovery-bootstrap-capsule.v1\0";
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootstrapCapsule {
    pub version: u8,
    pub epoch: u64,
    pub rollback_anchor: [u8; 32],
    pub policy_digest: [u8; 32],
    pub key_binding: [u8; 32],
    pub authenticator: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapError {
    InvalidKey,
    InvalidEpoch,
    MissingBinding,
    AuthenticationFailed,
    Rollback,
}
pub fn seal(
    epoch: u64,
    anchor: [u8; 32],
    policy: [u8; 32],
    binding: [u8; 32],
    key: [u8; 32],
) -> Result<BootstrapCapsule, BootstrapError> {
    validate(epoch, anchor, policy, binding, key)?;
    let mut c = BootstrapCapsule {
        version: 1,
        epoch,
        rollback_anchor: anchor,
        policy_digest: policy,
        key_binding: binding,
        authenticator: [0; 32],
    };
    c.authenticator = auth(c, key);
    Ok(c)
}
pub fn open(
    c: BootstrapCapsule,
    minimum_epoch: u64,
    key: [u8; 32],
) -> Result<BootstrapCapsule, BootstrapError> {
    validate(
        c.epoch,
        c.rollback_anchor,
        c.policy_digest,
        c.key_binding,
        key,
    )?;
    if c.epoch < minimum_epoch {
        return Err(BootstrapError::Rollback);
    }
    if c.version != 1 || c.authenticator != auth(c, key) {
        return Err(BootstrapError::AuthenticationFailed);
    }
    Ok(c)
}
fn validate(
    epoch: u64,
    a: [u8; 32],
    p: [u8; 32],
    b: [u8; 32],
    k: [u8; 32],
) -> Result<(), BootstrapError> {
    if k == [0; 32] {
        return Err(BootstrapError::InvalidKey);
    }
    if epoch == 0 {
        return Err(BootstrapError::InvalidEpoch);
    }
    if [a, p, b].contains(&[0; 32]) {
        return Err(BootstrapError::MissingBinding);
    }
    Ok(())
}
fn auth(mut c: BootstrapCapsule, k: [u8; 32]) -> [u8; 32] {
    c.authenticator = [0; 32];
    let mut b = Vec::new();
    b.extend_from_slice(DOMAIN);
    b.push(c.version);
    b.extend_from_slice(&c.epoch.to_be_bytes());
    b.extend_from_slice(&c.rollback_anchor);
    b.extend_from_slice(&c.policy_digest);
    b.extend_from_slice(&c.key_binding);
    hmac_sha256(k, &b)
}
#[cfg(test)]
mod tests {
    use super::*;
    const K: [u8; 32] = [4; 32];
    #[test]
    fn capsule_round_trips_at_epoch_floor() {
        let c = seal(7, [1; 32], [2; 32], [3; 32], K).unwrap();
        assert_eq!(open(c, 7, K), Ok(c));
        assert_eq!(open(c, 8, K), Err(BootstrapError::Rollback))
    }
    #[test]
    fn substitution_fails() {
        let mut c = seal(7, [1; 32], [2; 32], [3; 32], K).unwrap();
        c.policy_digest = [9; 32];
        assert_eq!(open(c, 0, K), Err(BootstrapError::AuthenticationFailed));
    }
}
