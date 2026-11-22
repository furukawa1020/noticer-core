//! Domain-separated authentication for trial artifacts.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrialArtifactKind {
    Sample,
    Summary,
    Manifest,
    ClaimCapsule,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrialArtifactTag(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrialAuthError {
    ZeroKey,
    EmptyArtifact,
    TagMismatch,
}

pub fn authenticate(
    kind: TrialArtifactKind,
    artifact: &[u8],
    key: [u8; 32],
) -> Result<TrialArtifactTag, TrialAuthError> {
    if key == [0; 32] {
        return Err(TrialAuthError::ZeroKey);
    }
    if artifact.is_empty() {
        return Err(TrialAuthError::EmptyArtifact);
    }
    let mut bytes = b"noticer.quotient-trial.artifact-auth.v1\0".to_vec();
    bytes.push(kind as u8);
    bytes.extend_from_slice(&key);
    bytes.extend_from_slice(artifact);
    Ok(TrialArtifactTag(crate::sha256::sha256(&bytes)))
}

pub fn verify(
    kind: TrialArtifactKind,
    artifact: &[u8],
    key: [u8; 32],
    tag: TrialArtifactTag,
) -> Result<(), TrialAuthError> {
    if authenticate(kind, artifact, key)? == tag {
        Ok(())
    } else {
        Err(TrialAuthError::TagMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn artifact_kind_substitution_is_detected() {
        let tag = authenticate(TrialArtifactKind::Summary, b"result", [1; 32]).unwrap();
        assert_eq!(
            verify(TrialArtifactKind::Manifest, b"result", [1; 32], tag),
            Err(TrialAuthError::TagMismatch)
        );
    }
}
