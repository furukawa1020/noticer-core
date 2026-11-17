use crate::receipt::hmac_sha256;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleaseProof {
    pub index: u64,
    pub epoch: u64,
    pub decision_commitment: [u8; 32],
    pub previous: [u8; 32],
    pub authenticator: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChainError {
    EmptyCommitment,
    IndexGap,
    EpochRollback,
    PreviousMismatch,
    Authentication,
}
pub fn append(
    previous: Option<ReleaseProof>,
    epoch: u64,
    decision_commitment: [u8; 32],
    key: [u8; 32],
) -> Result<ReleaseProof, ChainError> {
    if decision_commitment == [0; 32] {
        return Err(ChainError::EmptyCommitment);
    }
    let (index, prev) = previous.map_or((0, [0; 32]), |p| (p.index + 1, p.authenticator));
    if let Some(p) = previous {
        if epoch < p.epoch {
            return Err(ChainError::EpochRollback);
        }
    }
    let mut v = ReleaseProof {
        index,
        epoch,
        decision_commitment,
        previous: prev,
        authenticator: [0; 32],
    };
    v.authenticator = auth(v, key);
    Ok(v)
}
pub fn verify(chain: &[ReleaseProof], key: [u8; 32]) -> Result<(), ChainError> {
    let mut prev = [0; 32];
    let mut epoch = 0;
    for (i, v) in chain.iter().enumerate() {
        if v.index != i as u64 {
            return Err(ChainError::IndexGap);
        }
        if v.epoch < epoch {
            return Err(ChainError::EpochRollback);
        }
        if v.previous != prev {
            return Err(ChainError::PreviousMismatch);
        }
        if v.authenticator != auth(*v, key) {
            return Err(ChainError::Authentication);
        }
        prev = v.authenticator;
        epoch = v.epoch;
    }
    Ok(())
}
fn auth(mut v: ReleaseProof, key: [u8; 32]) -> [u8; 32] {
    v.authenticator = [0; 32];
    let mut b = Vec::new();
    b.extend_from_slice(b"noticer.release-proof-chain.v1");
    b.extend_from_slice(&v.index.to_be_bytes());
    b.extend_from_slice(&v.epoch.to_be_bytes());
    b.extend_from_slice(&v.decision_commitment);
    b.extend_from_slice(&v.previous);
    hmac_sha256(key, &b)
}
#[cfg(test)]
mod tests {
    use super::*;
    const K: [u8; 32] = [5; 32];
    #[test]
    fn verifies_chain() {
        let a = append(None, 1, [1; 32], K).unwrap();
        let b = append(Some(a), 2, [2; 32], K).unwrap();
        assert_eq!(verify(&[a, b], K), Ok(()))
    }
    #[test]
    fn rejects_reorder() {
        let a = append(None, 1, [1; 32], K).unwrap();
        let b = append(Some(a), 2, [2; 32], K).unwrap();
        assert_eq!(verify(&[b, a], K), Err(ChainError::IndexGap));
    }
}
