use crate::receipt::hmac_sha256;
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ProducerFamily {
    Native = 1,
    Wasm = 2,
    Independent = 3,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProducerIdentity {
    pub producer: [u8; 16],
    pub family: ProducerFamily,
    pub key_epoch: u64,
    pub public_key_digest: [u8; 32],
    pub authenticator: [u8; 32],
}
pub fn issue(
    producer: [u8; 16],
    family: ProducerFamily,
    key_epoch: u64,
    public_key_digest: [u8; 32],
    authority_key: [u8; 32],
) -> Option<ProducerIdentity> {
    if public_key_digest == [0; 32] {
        return None;
    }
    let mut v = ProducerIdentity {
        producer,
        family,
        key_epoch,
        public_key_digest,
        authenticator: [0; 32],
    };
    v.authenticator = auth(v, authority_key);
    Some(v)
}
pub fn verify(v: ProducerIdentity, key: [u8; 32]) -> bool {
    v.public_key_digest != [0; 32] && v.authenticator == auth(v, key)
}
fn auth(mut v: ProducerIdentity, key: [u8; 32]) -> [u8; 32] {
    v.authenticator = [0; 32];
    let mut b = Vec::new();
    b.extend_from_slice(b"noticer.producer-identity.v1");
    b.extend_from_slice(&v.producer);
    b.push(v.family as u8);
    b.extend_from_slice(&v.key_epoch.to_be_bytes());
    b.extend_from_slice(&v.public_key_digest);
    hmac_sha256(key, &b)
}
#[cfg(test)]
mod tests {
    use super::*;
    const K: [u8; 32] = [1; 32];
    #[test]
    fn verifies_identity() {
        let v = issue([2; 16], ProducerFamily::Native, 3, [4; 32], K).unwrap();
        assert!(verify(v, K))
    }
    #[test]
    fn rejects_family_tamper() {
        let mut v = issue([2; 16], ProducerFamily::Native, 3, [4; 32], K).unwrap();
        v.family = ProducerFamily::Wasm;
        assert!(!verify(v, K));
    }
}
