use crate::receipt::hmac_sha256;
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RegionId(pub [u8; 8]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionVote {
    pub region: RegionId,
    pub candidate: [u8; 32],
    pub epoch: u64,
    pub authenticator: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegionQuorumError {
    InvalidThreshold,
    DuplicateRegion,
    CandidateMismatch,
    EpochMismatch,
    AuthenticationFailed,
    InsufficientVotes,
}

pub fn issue_vote(region: RegionId, candidate: [u8; 32], epoch: u64, key: [u8; 32]) -> RegionVote {
    RegionVote {
        region,
        candidate,
        epoch,
        authenticator: authenticate(region, candidate, epoch, key),
    }
}

pub fn verify_quorum(
    votes: &[RegionVote],
    threshold: usize,
    candidate: [u8; 32],
    epoch: u64,
    key: [u8; 32],
) -> Result<(), RegionQuorumError> {
    if threshold == 0 {
        return Err(RegionQuorumError::InvalidThreshold);
    }
    let mut regions = BTreeSet::new();
    for vote in votes {
        if !regions.insert(vote.region) {
            return Err(RegionQuorumError::DuplicateRegion);
        }
        if vote.candidate != candidate {
            return Err(RegionQuorumError::CandidateMismatch);
        }
        if vote.epoch != epoch {
            return Err(RegionQuorumError::EpochMismatch);
        }
        if vote.authenticator != authenticate(vote.region, vote.candidate, vote.epoch, key) {
            return Err(RegionQuorumError::AuthenticationFailed);
        }
    }
    if regions.len() < threshold {
        return Err(RegionQuorumError::InsufficientVotes);
    }
    Ok(())
}

fn authenticate(region: RegionId, candidate: [u8; 32], epoch: u64, key: [u8; 32]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(48);
    bytes.extend_from_slice(b"noticer.region-quorum.v1");
    bytes.extend_from_slice(&region.0);
    bytes.extend_from_slice(&candidate);
    bytes.extend_from_slice(&epoch.to_be_bytes());
    hmac_sha256(key, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    const KEY: [u8; 32] = [6; 32];

    #[test]
    fn accepts_distinct_region_quorum() {
        let candidate = [9; 32];
        let votes = [
            issue_vote(RegionId([1; 8]), candidate, 4, KEY),
            issue_vote(RegionId([2; 8]), candidate, 4, KEY),
        ];
        assert_eq!(verify_quorum(&votes, 2, candidate, 4, KEY), Ok(()));
    }

    #[test]
    fn rejects_duplicate_region_and_substitution() {
        let candidate = [9; 32];
        let vote = issue_vote(RegionId([1; 8]), candidate, 4, KEY);
        assert_eq!(
            verify_quorum(&[vote, vote], 2, candidate, 4, KEY),
            Err(RegionQuorumError::DuplicateRegion)
        );
        assert_eq!(
            verify_quorum(&[vote], 1, [8; 32], 4, KEY),
            Err(RegionQuorumError::CandidateMismatch)
        );
    }
}
