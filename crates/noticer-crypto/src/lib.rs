#![forbid(unsafe_code)]
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use noticer_protocol::{CapabilityBody, SIGN_DOMAIN};
use noticer_types::{CapabilityId, Epoch};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
pub fn generate() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}
pub fn sign(key: &SigningKey, body: &CapabilityBody) -> [u8; 64] {
    let mut m = SIGN_DOMAIN.to_vec();
    m.extend(body.encode());
    key.sign(&m).to_bytes()
}
pub fn verify(key: &VerifyingKey, body: &CapabilityBody, sig: &[u8; 64]) -> bool {
    let mut m = SIGN_DOMAIN.to_vec();
    m.extend(body.encode());
    key.verify(&m, &Signature::from_bytes(sig)).is_ok()
}
pub fn capability_id(body: &CapabilityBody, sig: &[u8; 64]) -> CapabilityId {
    let mut h = Sha256::new();
    h.update(b"NOTICER_CAPABILITY_ID_V1");
    h.update(body.encode());
    h.update(sig);
    CapabilityId(h.finalize().into())
}
pub fn audience_binding(service: &[u8], key: &VerifyingKey, epoch: Epoch) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"NOTICER_AUDIENCE_V1");
    h.update(service);
    h.update(key.as_bytes());
    h.update(epoch.0.to_be_bytes());
    h.finalize().into()
}
