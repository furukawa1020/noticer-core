//! Authenticated and replay-safe cross-region recovery handoff.
use crate::receipt::hmac_sha256;
use std::collections::BTreeSet;
const DOMAIN: &[u8] = b"noticer.recovery-cross-region.v1\0";
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionHandoff {
    pub source: [u8; 8],
    pub target: [u8; 8],
    pub epoch: u64,
    pub fencing_token: u64,
    pub nonce: [u8; 16],
    pub expires_at: u64,
    pub authenticator: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffError {
    InvalidKey,
    InvalidRegion,
    InvalidEpoch,
    InvalidNonce,
    Expired,
    StaleFence,
    Replay,
    AuthenticationFailed,
}
pub fn issue(
    source: [u8; 8],
    target: [u8; 8],
    epoch: u64,
    fence: u64,
    nonce: [u8; 16],
    expires: u64,
    key: [u8; 32],
) -> Result<RegionHandoff, HandoffError> {
    validate(source, target, epoch, fence, nonce, key)?;
    let mut h = RegionHandoff {
        source,
        target,
        epoch,
        fencing_token: fence,
        nonce,
        expires_at: expires,
        authenticator: [0; 32],
    };
    h.authenticator = auth(h, key);
    Ok(h)
}
#[derive(Default)]
pub struct RegionHandoffAcceptor {
    used: BTreeSet<(u64, [u8; 16])>,
    minimum_fence: u64,
}
impl RegionHandoffAcceptor {
    pub fn accept(
        &mut self,
        h: RegionHandoff,
        now: u64,
        key: [u8; 32],
    ) -> Result<(), HandoffError> {
        validate(h.source, h.target, h.epoch, h.fencing_token, h.nonce, key)?;
        if h.authenticator != auth(h, key) {
            return Err(HandoffError::AuthenticationFailed);
        }
        if now > h.expires_at {
            return Err(HandoffError::Expired);
        }
        if h.fencing_token < self.minimum_fence {
            return Err(HandoffError::StaleFence);
        }
        if !self.used.insert((h.epoch, h.nonce)) {
            return Err(HandoffError::Replay);
        }
        self.minimum_fence = h.fencing_token;
        Ok(())
    }
}
fn validate(
    s: [u8; 8],
    t: [u8; 8],
    e: u64,
    f: u64,
    n: [u8; 16],
    k: [u8; 32],
) -> Result<(), HandoffError> {
    if k == [0; 32] {
        return Err(HandoffError::InvalidKey);
    }
    if s == [0; 8] || t == [0; 8] || s == t {
        return Err(HandoffError::InvalidRegion);
    }
    if e == 0 || f == 0 {
        return Err(HandoffError::InvalidEpoch);
    }
    if n == [0; 16] {
        return Err(HandoffError::InvalidNonce);
    }
    Ok(())
}
fn auth(mut h: RegionHandoff, k: [u8; 32]) -> [u8; 32] {
    h.authenticator = [0; 32];
    let mut b = Vec::new();
    b.extend_from_slice(DOMAIN);
    b.extend_from_slice(&h.source);
    b.extend_from_slice(&h.target);
    b.extend_from_slice(&h.epoch.to_be_bytes());
    b.extend_from_slice(&h.fencing_token.to_be_bytes());
    b.extend_from_slice(&h.nonce);
    b.extend_from_slice(&h.expires_at.to_be_bytes());
    hmac_sha256(k, &b)
}
#[cfg(test)]
mod tests {
    use super::*;
    const K: [u8; 32] = [3; 32];
    #[test]
    fn handoff_is_single_use() {
        let h = issue([1; 8], [2; 8], 3, 9, [4; 16], 100, K).unwrap();
        let mut a = RegionHandoffAcceptor::default();
        assert_eq!(a.accept(h, 50, K), Ok(()));
        assert_eq!(a.accept(h, 50, K), Err(HandoffError::Replay))
    }
    #[test]
    fn loop_expiry_and_stale_fence_fail() {
        assert_eq!(
            issue([1; 8], [1; 8], 3, 9, [4; 16], 100, K),
            Err(HandoffError::InvalidRegion)
        );
        let mut a = RegionHandoffAcceptor::default();
        a.accept(issue([1; 8], [2; 8], 3, 9, [1; 16], 100, K).unwrap(), 50, K)
            .unwrap();
        assert_eq!(
            a.accept(issue([1; 8], [2; 8], 3, 8, [2; 16], 100, K).unwrap(), 50, K),
            Err(HandoffError::StaleFence)
        );
    }
}
