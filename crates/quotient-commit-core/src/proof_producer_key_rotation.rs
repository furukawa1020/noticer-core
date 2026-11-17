use crate::receipt::hmac_sha256;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProducerKeyRotation {
    pub producer: [u8; 16],
    pub old_digest: [u8; 32],
    pub new_digest: [u8; 32],
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub authenticator: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RotationError {
    SameKey,
    InvalidEpoch,
    Authentication,
}
pub fn issue(
    producer: [u8; 16],
    old_digest: [u8; 32],
    new_digest: [u8; 32],
    old_epoch: u64,
    new_epoch: u64,
    key: [u8; 32],
) -> Result<ProducerKeyRotation, RotationError> {
    if old_digest == new_digest {
        return Err(RotationError::SameKey);
    }
    if new_epoch != old_epoch + 1 {
        return Err(RotationError::InvalidEpoch);
    }
    let mut v = ProducerKeyRotation {
        producer,
        old_digest,
        new_digest,
        old_epoch,
        new_epoch,
        authenticator: [0; 32],
    };
    v.authenticator = auth(v, key);
    Ok(v)
}
pub fn verify(v: ProducerKeyRotation, key: [u8; 32]) -> Result<(), RotationError> {
    if v.new_epoch != v.old_epoch + 1 {
        return Err(RotationError::InvalidEpoch);
    }
    if v.authenticator != auth(v, key) {
        return Err(RotationError::Authentication);
    }
    Ok(())
}
fn auth(mut v: ProducerKeyRotation, key: [u8; 32]) -> [u8; 32] {
    v.authenticator = [0; 32];
    let mut b = Vec::new();
    b.extend_from_slice(b"noticer.producer-key-rotation.v1");
    b.extend_from_slice(&v.producer);
    b.extend_from_slice(&v.old_digest);
    b.extend_from_slice(&v.new_digest);
    b.extend_from_slice(&v.old_epoch.to_be_bytes());
    b.extend_from_slice(&v.new_epoch.to_be_bytes());
    hmac_sha256(key, &b)
}
#[cfg(test)]
mod tests {
    use super::*;
    const K: [u8; 32] = [2; 32];
    #[test]
    fn verifies_rotation() {
        let v = issue([1; 16], [2; 32], [3; 32], 4, 5, K).unwrap();
        assert_eq!(verify(v, K), Ok(()))
    }
    #[test]
    fn rejects_epoch_gap() {
        assert_eq!(
            issue([1; 16], [2; 32], [3; 32], 4, 6, K),
            Err(RotationError::InvalidEpoch)
        );
    }
}
