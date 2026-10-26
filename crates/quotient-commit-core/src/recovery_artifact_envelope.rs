//! Authenticated, size-bounded envelopes for recovery artifacts.

use crate::receipt::hmac_sha256;
use crate::sha256::sha256;

const DOMAIN: &[u8] = b"noticer.recovery-artifact-envelope.v1\0";
pub const MAX_ARTIFACT_BYTES: usize = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ArtifactKind {
    ProofBundle = 1,
    Checkpoint = 2,
    AuditTranscript = 3,
    ReadinessManifest = 4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactEnvelope {
    pub version: u8,
    pub kind: ArtifactKind,
    pub payload: Vec<u8>,
    pub content_digest: [u8; 32],
    pub authenticator: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvelopeError {
    InvalidKey,
    EmptyArtifact,
    Oversize,
    DigestMismatch,
    AuthenticationFailed,
}

pub fn seal(
    kind: ArtifactKind,
    payload: Vec<u8>,
    key: [u8; 32],
) -> Result<ArtifactEnvelope, EnvelopeError> {
    validate_payload(&payload)?;
    if key == [0; 32] {
        return Err(EnvelopeError::InvalidKey);
    }
    let mut value = ArtifactEnvelope {
        version: 1,
        kind,
        content_digest: sha256(&payload),
        payload,
        authenticator: [0; 32],
    };
    value.authenticator = authenticate(&value, key);
    Ok(value)
}

pub fn open(
    value: &ArtifactEnvelope,
    expected: ArtifactKind,
    key: [u8; 32],
) -> Result<Vec<u8>, EnvelopeError> {
    validate_payload(&value.payload)?;
    if key == [0; 32] {
        return Err(EnvelopeError::InvalidKey);
    }
    if value.version != 1
        || value.kind != expected
        || value.authenticator != authenticate(value, key)
    {
        return Err(EnvelopeError::AuthenticationFailed);
    }
    if value.content_digest != sha256(&value.payload) {
        return Err(EnvelopeError::DigestMismatch);
    }
    Ok(value.payload.clone())
}

fn validate_payload(payload: &[u8]) -> Result<(), EnvelopeError> {
    if payload.is_empty() {
        Err(EnvelopeError::EmptyArtifact)
    } else if payload.len() > MAX_ARTIFACT_BYTES {
        Err(EnvelopeError::Oversize)
    } else {
        Ok(())
    }
}
fn authenticate(value: &ArtifactEnvelope, key: [u8; 32]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(DOMAIN.len() + 2 + 8 + 32 + value.payload.len());
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&[value.version, value.kind as u8]);
    bytes.extend_from_slice(&(value.payload.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&value.content_digest);
    bytes.extend_from_slice(&value.payload);
    hmac_sha256(key, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    const KEY: [u8; 32] = [9; 32];
    #[test]
    fn round_trip_binds_kind_and_content() {
        let value = seal(ArtifactKind::ProofBundle, b"proof".to_vec(), KEY).unwrap();
        assert_eq!(
            open(&value, ArtifactKind::ProofBundle, KEY).unwrap(),
            b"proof"
        );
        assert_eq!(
            open(&value, ArtifactKind::Checkpoint, KEY),
            Err(EnvelopeError::AuthenticationFailed)
        );
        let mut changed = value;
        changed.payload[0] ^= 1;
        assert!(open(&changed, ArtifactKind::ProofBundle, KEY).is_err());
    }
    #[test]
    fn empty_oversize_and_zero_key_are_rejected() {
        assert_eq!(
            seal(ArtifactKind::Checkpoint, vec![], KEY),
            Err(EnvelopeError::EmptyArtifact)
        );
        assert_eq!(
            seal(
                ArtifactKind::Checkpoint,
                vec![0; MAX_ARTIFACT_BYTES + 1],
                KEY
            ),
            Err(EnvelopeError::Oversize)
        );
        assert_eq!(
            seal(ArtifactKind::Checkpoint, vec![1], [0; 32]),
            Err(EnvelopeError::InvalidKey)
        );
    }
}
