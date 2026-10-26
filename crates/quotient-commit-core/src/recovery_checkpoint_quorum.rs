//! Threshold approval certificates for recovery checkpoints.

use crate::receipt::hmac_sha256;

const DOMAIN: &[u8] = b"noticer.recovery-checkpoint-quorum.v1\0";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct VerifierId(pub [u8; 16]);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifierKey {
    pub id: VerifierId,
    pub key: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApprovalShare {
    pub verifier_id: VerifierId,
    pub checkpoint_digest: [u8; 32],
    pub epoch: u64,
    pub authenticator: [u8; 32],
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuorumCertificate {
    pub checkpoint_digest: [u8; 32],
    pub epoch: u64,
    pub threshold: u16,
    pub shares: Vec<ApprovalShare>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuorumError {
    InvalidKey,
    InvalidCheckpoint,
    InvalidEpoch,
    InvalidThreshold,
    UnknownVerifier,
    InvalidShare,
    DuplicateVerifier,
    InsufficientQuorum,
}

pub fn approve(
    id: VerifierId,
    checkpoint_digest: [u8; 32],
    epoch: u64,
    key: [u8; 32],
) -> Result<ApprovalShare, QuorumError> {
    if key == [0; 32] {
        return Err(QuorumError::InvalidKey);
    }
    if checkpoint_digest == [0; 32] {
        return Err(QuorumError::InvalidCheckpoint);
    }
    if epoch == 0 {
        return Err(QuorumError::InvalidEpoch);
    }
    Ok(ApprovalShare {
        verifier_id: id,
        checkpoint_digest,
        epoch,
        authenticator: authenticate(id, checkpoint_digest, epoch, key),
    })
}

pub fn certify(
    mut shares: Vec<ApprovalShare>,
    threshold: u16,
    verifiers: &[VerifierKey],
) -> Result<QuorumCertificate, QuorumError> {
    if threshold == 0 || usize::from(threshold) > verifiers.len() {
        return Err(QuorumError::InvalidThreshold);
    }
    let Some(first) = shares.first().copied() else {
        return Err(QuorumError::InsufficientQuorum);
    };
    shares.sort_by_key(|share| share.verifier_id);
    for (index, share) in shares.iter().enumerate() {
        if index > 0 && shares[index - 1].verifier_id == share.verifier_id {
            return Err(QuorumError::DuplicateVerifier);
        }
        if share.checkpoint_digest != first.checkpoint_digest || share.epoch != first.epoch {
            return Err(QuorumError::InvalidShare);
        }
        let verifier = verifiers
            .iter()
            .find(|entry| entry.id == share.verifier_id)
            .ok_or(QuorumError::UnknownVerifier)?;
        if verifier.key == [0; 32]
            || share.authenticator
                != authenticate(
                    share.verifier_id,
                    share.checkpoint_digest,
                    share.epoch,
                    verifier.key,
                )
        {
            return Err(QuorumError::InvalidShare);
        }
    }
    if shares.len() < usize::from(threshold) {
        return Err(QuorumError::InsufficientQuorum);
    }
    Ok(QuorumCertificate {
        checkpoint_digest: first.checkpoint_digest,
        epoch: first.epoch,
        threshold,
        shares,
    })
}

pub fn verify(
    certificate: &QuorumCertificate,
    verifiers: &[VerifierKey],
) -> Result<(), QuorumError> {
    let rebuilt = certify(certificate.shares.clone(), certificate.threshold, verifiers)?;
    if &rebuilt == certificate {
        Ok(())
    } else {
        Err(QuorumError::InvalidShare)
    }
}

fn authenticate(id: VerifierId, digest: [u8; 32], epoch: u64, key: [u8; 32]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(DOMAIN.len() + 56);
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&id.0);
    bytes.extend_from_slice(&digest);
    bytes.extend_from_slice(&epoch.to_be_bytes());
    hmac_sha256(key, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn verifiers() -> Vec<VerifierKey> {
        (1..=3)
            .map(|n| VerifierKey {
                id: VerifierId([n; 16]),
                key: [n; 32],
            })
            .collect()
    }
    #[test]
    fn threshold_certificate_is_sorted_and_verifiable() {
        let keys = verifiers();
        let shares = vec![
            approve(keys[1].id, [8; 32], 4, keys[1].key).unwrap(),
            approve(keys[0].id, [8; 32], 4, keys[0].key).unwrap(),
        ];
        let certificate = certify(shares, 2, &keys).unwrap();
        assert_eq!(certificate.shares[0].verifier_id, keys[0].id);
        assert_eq!(verify(&certificate, &keys), Ok(()));
    }
    #[test]
    fn duplicate_insufficient_and_tampered_shares_fail() {
        let keys = verifiers();
        let share = approve(keys[0].id, [8; 32], 4, keys[0].key).unwrap();
        assert_eq!(
            certify(vec![share], 2, &keys),
            Err(QuorumError::InsufficientQuorum)
        );
        assert_eq!(
            certify(vec![share, share], 2, &keys),
            Err(QuorumError::DuplicateVerifier)
        );
        let mut bad = approve(keys[1].id, [8; 32], 4, keys[1].key).unwrap();
        bad.authenticator[0] ^= 1;
        assert_eq!(
            certify(vec![share, bad], 2, &keys),
            Err(QuorumError::InvalidShare)
        );
    }
}
