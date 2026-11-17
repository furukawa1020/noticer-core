use crate::receipt::hmac_sha256;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProofFragment {
    pub index: u16,
    pub total: u16,
    pub payload_digest: [u8; 32],
    pub proof_root: [u8; 32],
    pub authenticator: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FragmentError {
    InvalidIndex,
    EmptyDigest,
    Authentication,
}
pub fn issue(
    index: u16,
    total: u16,
    payload_digest: [u8; 32],
    proof_root: [u8; 32],
    key: [u8; 32],
) -> Result<ProofFragment, FragmentError> {
    if total == 0 || index >= total {
        return Err(FragmentError::InvalidIndex);
    }
    if payload_digest == [0; 32] || proof_root == [0; 32] {
        return Err(FragmentError::EmptyDigest);
    }
    let mut v = ProofFragment {
        index,
        total,
        payload_digest,
        proof_root,
        authenticator: [0; 32],
    };
    v.authenticator = auth(v, key);
    Ok(v)
}
pub fn verify(v: ProofFragment, key: [u8; 32]) -> Result<(), FragmentError> {
    if v.total == 0 || v.index >= v.total {
        return Err(FragmentError::InvalidIndex);
    }
    if v.authenticator != auth(v, key) {
        return Err(FragmentError::Authentication);
    }
    Ok(())
}
fn auth(mut v: ProofFragment, key: [u8; 32]) -> [u8; 32] {
    v.authenticator = [0; 32];
    let mut b = Vec::new();
    b.extend_from_slice(b"noticer.proof-fragment.v1");
    b.extend_from_slice(&v.index.to_be_bytes());
    b.extend_from_slice(&v.total.to_be_bytes());
    b.extend_from_slice(&v.payload_digest);
    b.extend_from_slice(&v.proof_root);
    hmac_sha256(key, &b)
}
#[cfg(test)]
mod tests {
    use super::*;
    const K: [u8; 32] = [7; 32];
    #[test]
    fn verifies_fragment() {
        let v = issue(0, 2, [1; 32], [2; 32], K).unwrap();
        assert_eq!(verify(v, K), Ok(()))
    }
    #[test]
    fn rejects_index() {
        assert_eq!(
            issue(2, 2, [1; 32], [2; 32], K),
            Err(FragmentError::InvalidIndex)
        );
    }
}
