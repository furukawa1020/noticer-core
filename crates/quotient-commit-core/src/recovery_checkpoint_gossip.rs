use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GossipRegion(pub [u8; 8]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckpointObservation {
    pub region: GossipRegion,
    pub epoch: u64,
    pub generation: u64,
    pub digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GossipError {
    InvalidQuorum,
    DuplicateRegion,
    Rollback,
    Equivocation,
    InsufficientObservations,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GossipCertificate {
    pub epoch: u64,
    pub generation: u64,
    pub digest: [u8; 32],
    pub regions: usize,
}

pub fn certify(
    observations: &[CheckpointObservation],
    quorum: usize,
    minimum_epoch: u64,
    minimum_generation: u64,
) -> Result<GossipCertificate, GossipError> {
    if quorum == 0 {
        return Err(GossipError::InvalidQuorum);
    }
    let mut regions = BTreeSet::new();
    let mut candidates = BTreeMap::new();
    for observation in observations {
        if !regions.insert(observation.region) {
            return Err(GossipError::DuplicateRegion);
        }
        if observation.epoch < minimum_epoch
            || (observation.epoch == minimum_epoch && observation.generation < minimum_generation)
        {
            return Err(GossipError::Rollback);
        }
        let position = (observation.epoch, observation.generation);
        if let Some(existing) = candidates.insert(position, observation.digest) {
            if existing != observation.digest {
                return Err(GossipError::Equivocation);
            }
        }
    }
    let latest = observations
        .iter()
        .max_by_key(|item| (item.epoch, item.generation))
        .ok_or(GossipError::InsufficientObservations)?;
    let count = observations
        .iter()
        .filter(|item| {
            item.epoch == latest.epoch
                && item.generation == latest.generation
                && item.digest == latest.digest
        })
        .count();
    if count < quorum {
        return Err(GossipError::InsufficientObservations);
    }
    Ok(GossipCertificate {
        epoch: latest.epoch,
        generation: latest.generation,
        digest: latest.digest,
        regions: count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn observation(region: u8, generation: u64, digest: u8) -> CheckpointObservation {
        CheckpointObservation {
            region: GossipRegion([region; 8]),
            epoch: 3,
            generation,
            digest: [digest; 32],
        }
    }
    #[test]
    fn certifies_matching_latest_checkpoint() {
        let result = certify(&[observation(1, 5, 7), observation(2, 5, 7)], 2, 3, 4).unwrap();
        assert_eq!(result.regions, 2);
    }
    #[test]
    fn rejects_fork_and_rollback() {
        assert_eq!(
            certify(&[observation(1, 5, 7), observation(2, 5, 8)], 2, 3, 4),
            Err(GossipError::Equivocation)
        );
        assert_eq!(
            certify(&[observation(1, 2, 7)], 1, 3, 4),
            Err(GossipError::Rollback)
        );
    }
}
