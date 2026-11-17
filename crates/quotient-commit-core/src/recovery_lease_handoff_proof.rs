use crate::receipt::hmac_sha256;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeaseHandoffProof {
    pub lease: [u8; 16],
    pub old_holder: [u8; 16],
    pub new_holder: [u8; 16],
    pub old_fence: u64,
    pub new_fence: u64,
    pub epoch: u64,
    pub authenticator: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffError {
    SameHolder,
    InvalidFence,
    Authentication,
}
pub fn issue(
    lease: [u8; 16],
    old_holder: [u8; 16],
    new_holder: [u8; 16],
    old_fence: u64,
    epoch: u64,
    key: [u8; 32],
) -> Result<LeaseHandoffProof, HandoffError> {
    if old_holder == new_holder {
        return Err(HandoffError::SameHolder);
    }
    let mut v = LeaseHandoffProof {
        lease,
        old_holder,
        new_holder,
        old_fence,
        new_fence: old_fence + 1,
        epoch,
        authenticator: [0; 32],
    };
    v.authenticator = auth(v, key);
    Ok(v)
}
pub fn verify(v: LeaseHandoffProof, key: [u8; 32]) -> Result<(), HandoffError> {
    if v.old_holder == v.new_holder {
        return Err(HandoffError::SameHolder);
    }
    if v.new_fence != v.old_fence + 1 {
        return Err(HandoffError::InvalidFence);
    }
    if v.authenticator != auth(v, key) {
        return Err(HandoffError::Authentication);
    }
    Ok(())
}
fn auth(mut v: LeaseHandoffProof, key: [u8; 32]) -> [u8; 32] {
    v.authenticator = [0; 32];
    let mut b = Vec::new();
    b.extend_from_slice(b"noticer.lease-handoff-proof.v1");
    b.extend_from_slice(&v.lease);
    b.extend_from_slice(&v.old_holder);
    b.extend_from_slice(&v.new_holder);
    b.extend_from_slice(&v.old_fence.to_be_bytes());
    b.extend_from_slice(&v.new_fence.to_be_bytes());
    b.extend_from_slice(&v.epoch.to_be_bytes());
    hmac_sha256(key, &b)
}
#[cfg(test)]
mod tests {
    use super::*;
    const K: [u8; 32] = [3; 32];
    #[test]
    fn verifies_handoff() {
        let v = issue([1; 16], [2; 16], [3; 16], 7, 4, K).unwrap();
        assert_eq!(verify(v, K), Ok(()))
    }
    #[test]
    fn rejects_fence_tamper() {
        let mut v = issue([1; 16], [2; 16], [3; 16], 7, 4, K).unwrap();
        v.new_fence = 9;
        assert_eq!(verify(v, K), Err(HandoffError::InvalidFence));
    }
}
