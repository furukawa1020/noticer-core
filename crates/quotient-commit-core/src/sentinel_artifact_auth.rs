//! Domain-separated authentication for runtime assurance artifacts.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssuranceArtifactKind {
    Checkpoint,
    Alarm,
    Revocation,
    IncidentCapsule,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssuranceArtifactTag(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactAuthError {
    ZeroKey,
    EmptyArtifact,
    TagMismatch,
}

pub fn authenticate(
    kind: AssuranceArtifactKind,
    artifact: &[u8],
    key: [u8; 32],
) -> Result<AssuranceArtifactTag, ArtifactAuthError> {
    if key == [0; 32] {
        return Err(ArtifactAuthError::ZeroKey);
    }
    if artifact.is_empty() {
        return Err(ArtifactAuthError::EmptyArtifact);
    }
    let mut bytes = b"noticer.quotient-sentinel.artifact-auth.v1\0".to_vec();
    bytes.push(kind as u8);
    bytes.extend_from_slice(&key);
    bytes.extend_from_slice(artifact);
    Ok(AssuranceArtifactTag(crate::sha256::sha256(&bytes)))
}

pub fn verify(
    kind: AssuranceArtifactKind,
    artifact: &[u8],
    key: [u8; 32],
    tag: AssuranceArtifactTag,
) -> Result<(), ArtifactAuthError> {
    if authenticate(kind, artifact, key)? == tag {
        Ok(())
    } else {
        Err(ArtifactAuthError::TagMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_substitution_and_bit_mutation_are_detected() {
        let tag = authenticate(AssuranceArtifactKind::Alarm, b"alarm", [1; 32]).unwrap();
        assert_eq!(
            verify(AssuranceArtifactKind::Checkpoint, b"alarm", [1; 32], tag),
            Err(ArtifactAuthError::TagMismatch)
        );
        assert_eq!(
            verify(AssuranceArtifactKind::Alarm, b"alarn", [1; 32], tag),
            Err(ArtifactAuthError::TagMismatch)
        );
    }
}
