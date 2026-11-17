use crate::{receipt::hmac_sha256, recovery_invariant_monitor::Invariant};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ViolationCapsule {
    pub invariant: Invariant,
    pub epoch: u64,
    pub sequence: u64,
    pub context_digest: [u8; 32],
    pub authenticator: [u8; 32],
}
pub fn issue(
    invariant: Invariant,
    epoch: u64,
    sequence: u64,
    context_digest: [u8; 32],
    key: [u8; 32],
) -> Option<ViolationCapsule> {
    if context_digest == [0; 32] {
        return None;
    }
    let mut v = ViolationCapsule {
        invariant,
        epoch,
        sequence,
        context_digest,
        authenticator: [0; 32],
    };
    v.authenticator = auth(v, key);
    Some(v)
}
pub fn verify(v: ViolationCapsule, key: [u8; 32]) -> bool {
    v.context_digest != [0; 32] && v.authenticator == auth(v, key)
}
fn auth(mut v: ViolationCapsule, key: [u8; 32]) -> [u8; 32] {
    v.authenticator = [0; 32];
    let mut b = Vec::new();
    b.extend_from_slice(b"noticer.violation-capsule.v1");
    b.push(v.invariant as u8);
    b.extend_from_slice(&v.epoch.to_be_bytes());
    b.extend_from_slice(&v.sequence.to_be_bytes());
    b.extend_from_slice(&v.context_digest);
    hmac_sha256(key, &b)
}
#[cfg(test)]
mod tests {
    use super::*;
    const K: [u8; 32] = [9; 32];
    #[test]
    fn authenticates_public_context() {
        let v = issue(Invariant::Authority, 2, 3, [1; 32], K).unwrap();
        assert!(verify(v, K))
    }
    #[test]
    fn rejects_tamper() {
        let mut v = issue(Invariant::CausalCut, 2, 3, [1; 32], K).unwrap();
        v.sequence = 4;
        assert!(!verify(v, K));
    }
}
