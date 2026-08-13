#![forbid(unsafe_code)]

//! Domain-separated ATv2 cryptographic key schedule and operations.

use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use noticer_aetp::{PairwiseServiceAlias, ServiceBinding};
use noticer_protocol::{KeyId, TokenId, WireServiceAlias, CIPHERTEXT_SIZE, SIGNED_PLAINTEXT_SIZE};
use sha2::{Digest, Sha256};
use std::fmt;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

type HmacSha256 = Hmac<Sha256>;

pub struct CryptographicRootSecret([u8; 32]);

impl CryptographicRootSecret {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for CryptographicRootSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CryptographicRootSecret(<redacted>)")
    }
}

impl Drop for CryptographicRootSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub struct IssuerKeyMaterial {
    service: ServiceBinding,
    epoch: u32,
    key_id: KeyId,
    alias: PairwiseServiceAlias,
    signing_key: Zeroizing<[u8; 32]>,
    aead_key: Zeroizing<[u8; 32]>,
    nonce_key: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for IssuerKeyMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuerKeyMaterial")
            .field("service", &self.service)
            .field("epoch", &self.epoch)
            .field("key_id", &self.key_id)
            .field("secret", &"<redacted>")
            .finish()
    }
}

#[derive(Clone)]
pub struct VerifierKeyMaterial {
    service: ServiceBinding,
    epoch: u32,
    key_id: KeyId,
    alias: PairwiseServiceAlias,
    verifying_key: VerifyingKey,
    aead_key: Zeroizing<[u8; 32]>,
    nonce_key: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for VerifierKeyMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifierKeyMaterial")
            .field("service", &self.service)
            .field("epoch", &self.epoch)
            .field("key_id", &self.key_id)
            .field("secret", &"<redacted>")
            .finish()
    }
}

pub fn derive_issuer_keys(
    root: &CryptographicRootSecret,
    service: ServiceBinding,
    epoch: u32,
) -> Result<IssuerKeyMaterial, CryptoError> {
    let signing_key = Zeroizing::new(expand(&root.0, b"NOTICER_AT_V2_SIGN_KEY", service, epoch)?);
    let aead_key = Zeroizing::new(expand(&root.0, b"NOTICER_AT_V2_AEAD_KEY", service, epoch)?);
    let nonce_key = Zeroizing::new(expand(&root.0, b"NOTICER_AT_V2_NONCE_KEY", service, epoch)?);
    let alias_bytes = expand(&root.0, b"NOTICER_AT_V2_SERVICE_ALIAS", service, epoch)?;
    let alias = PairwiseServiceAlias(alias_bytes);
    let key_id = make_key_id(
        &SigningKey::from_bytes(&signing_key).verifying_key(),
        service,
        epoch,
    );
    Ok(IssuerKeyMaterial {
        service,
        epoch,
        key_id,
        alias,
        signing_key,
        aead_key,
        nonce_key,
    })
}

fn expand(
    root: &[u8; 32],
    domain: &[u8],
    service: ServiceBinding,
    epoch: u32,
) -> Result<[u8; 32], CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(Some(b"NOTICER_AT_V2_HKDF_SALT"), root);
    let mut info = Vec::with_capacity(domain.len() + 20);
    info.extend_from_slice(domain);
    info.extend_from_slice(&service.0);
    info.extend_from_slice(&epoch.to_le_bytes());
    let mut output = [0_u8; 32];
    hkdf.expand(&info, &mut output)
        .map_err(|_| CryptoError::KeyDerivation)?;
    Ok(output)
}

fn make_key_id(key: &VerifyingKey, service: ServiceBinding, epoch: u32) -> KeyId {
    let mut digest = Sha256::new();
    digest.update(b"NOTICER_AT_V2_KEY_ID");
    digest.update(key.as_bytes());
    digest.update(service.0);
    digest.update(epoch.to_le_bytes());
    let output: [u8; 32] = digest.finalize().into();
    KeyId(output[..8].try_into().expect("fixed digest prefix"))
}

impl IssuerKeyMaterial {
    pub const fn service(&self) -> ServiceBinding {
        self.service
    }

    pub const fn epoch(&self) -> u32 {
        self.epoch
    }

    pub const fn key_id(&self) -> KeyId {
        self.key_id
    }

    pub fn wire_alias(&self) -> WireServiceAlias {
        WireServiceAlias(self.alias.0[..8].try_into().expect("fixed alias prefix"))
    }

    pub const fn full_alias(&self) -> PairwiseServiceAlias {
        self.alias
    }

    pub fn verifier_material(&self) -> VerifierKeyMaterial {
        VerifierKeyMaterial {
            service: self.service,
            epoch: self.epoch,
            key_id: self.key_id,
            alias: self.alias,
            verifying_key: SigningKey::from_bytes(&self.signing_key).verifying_key(),
            aead_key: self.aead_key.clone(),
            nonce_key: self.nonce_key.clone(),
        }
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        SigningKey::from_bytes(&self.signing_key)
            .sign(message)
            .to_bytes()
    }

    pub fn nonce(&self, public_bucket: u32, sequence: u32) -> [u8; 24] {
        derive_nonce(
            &self.nonce_key,
            self.service,
            self.epoch,
            public_bucket,
            sequence,
        )
    }

    pub fn token_id(&self, public_bucket: u32, sequence: u32) -> TokenId {
        derive_token_id(
            &self.nonce_key,
            self.service,
            self.epoch,
            public_bucket,
            sequence,
        )
    }

    pub fn seal(
        &self,
        nonce: &[u8; 24],
        aad: &[u8],
        plaintext: &[u8; SIGNED_PLAINTEXT_SIZE],
    ) -> Result<[u8; CIPHERTEXT_SIZE], CryptoError> {
        let cipher = XChaCha20Poly1305::new_from_slice(self.aead_key.as_ref())
            .map_err(|_| CryptoError::InvalidKey)?;
        let sealed = cipher
            .encrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::Authentication)?;
        sealed.try_into().map_err(|_| CryptoError::Authentication)
    }
}

impl VerifierKeyMaterial {
    pub const fn service(&self) -> ServiceBinding {
        self.service
    }

    pub const fn epoch(&self) -> u32 {
        self.epoch
    }

    pub const fn key_id(&self) -> KeyId {
        self.key_id
    }

    pub fn wire_alias(&self) -> WireServiceAlias {
        WireServiceAlias(self.alias.0[..8].try_into().expect("fixed alias prefix"))
    }

    pub fn expected_nonce(&self, public_bucket: u32, sequence: u32) -> [u8; 24] {
        derive_nonce(
            &self.nonce_key,
            self.service,
            self.epoch,
            public_bucket,
            sequence,
        )
    }

    pub fn open(
        &self,
        nonce: &[u8; 24],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<[u8; SIGNED_PLAINTEXT_SIZE], CryptoError> {
        let cipher = XChaCha20Poly1305::new_from_slice(self.aead_key.as_ref())
            .map_err(|_| CryptoError::InvalidKey)?;
        let opened = cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::Authentication)?;
        opened.try_into().map_err(|_| CryptoError::Authentication)
    }

    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<(), CryptoError> {
        let signature = Signature::from_bytes(signature);
        self.verifying_key
            .verify(message, &signature)
            .map_err(|_| CryptoError::Signature)
    }
}

fn derive_nonce(
    key: &[u8; 32],
    service: ServiceBinding,
    epoch: u32,
    public_bucket: u32,
    sequence: u32,
) -> [u8; 24] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts 32-byte keys");
    mac.update(b"NOTICER_AT_V2_NONCE");
    mac.update(&service.0);
    mac.update(&epoch.to_le_bytes());
    mac.update(&public_bucket.to_le_bytes());
    mac.update(&sequence.to_le_bytes());
    let output = mac.finalize().into_bytes();
    output[..24].try_into().expect("fixed HMAC prefix")
}

fn derive_token_id(
    key: &[u8; 32],
    service: ServiceBinding,
    epoch: u32,
    public_bucket: u32,
    sequence: u32,
) -> TokenId {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts 32-byte keys");
    mac.update(b"NOTICER_AT_V2_TOKEN_ID");
    mac.update(&service.0);
    mac.update(&epoch.to_le_bytes());
    mac.update(&public_bucket.to_le_bytes());
    mac.update(&sequence.to_le_bytes());
    let output = mac.finalize().into_bytes();
    TokenId(output[..16].try_into().expect("fixed HMAC prefix"))
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum CryptoError {
    #[error("key derivation failed")]
    KeyDerivation,
    #[error("invalid key material")]
    InvalidKey,
    #[error("authenticated encryption failed")]
    Authentication,
    #[error("signature verification failed")]
    Signature,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_and_epoch_keys_are_separated() {
        let root = CryptographicRootSecret::new([9; 32]);
        let a = derive_issuer_keys(&root, ServiceBinding([1; 16]), 4).unwrap();
        let b = derive_issuer_keys(&root, ServiceBinding([2; 16]), 4).unwrap();
        let c = derive_issuer_keys(&root, ServiceBinding([1; 16]), 5).unwrap();
        assert_ne!(a.key_id(), b.key_id());
        assert_ne!(a.key_id(), c.key_id());
        assert_ne!(a.wire_alias(), b.wire_alias());
    }

    #[test]
    fn debug_output_redacts_secrets() {
        let root = CryptographicRootSecret::new([0xAB; 32]);
        let keys = derive_issuer_keys(&root, ServiceBinding([1; 16]), 1).unwrap();
        assert!(format!("{root:?}").contains("redacted"));
        assert!(format!("{keys:?}").contains("redacted"));
        assert!(!format!("{keys:?}").contains("171"));
    }
}
