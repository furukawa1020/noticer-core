use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReplicaRegion(pub [u8; 8]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Replica {
    pub region: ReplicaRegion,
    pub digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplicationManifest {
    pub artifact_digest: [u8; 32],
    pub required_replicas: usize,
    pub replicas: Vec<Replica>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifestError {
    InvalidRequirement,
    EmptyDigest,
    DuplicateRegion,
    DigestMismatch,
    InsufficientReplicas,
}

impl ReplicationManifest {
    pub fn verify(&self) -> Result<(), ManifestError> {
        if self.required_replicas == 0 {
            return Err(ManifestError::InvalidRequirement);
        }
        if self.artifact_digest == [0; 32] {
            return Err(ManifestError::EmptyDigest);
        }
        let mut regions = BTreeSet::new();
        for replica in &self.replicas {
            if !regions.insert(replica.region) {
                return Err(ManifestError::DuplicateRegion);
            }
            if replica.digest != self.artifact_digest {
                return Err(ManifestError::DigestMismatch);
            }
        }
        if regions.len() < self.required_replicas {
            return Err(ManifestError::InsufficientReplicas);
        }
        Ok(())
    }

    pub fn canonical_regions(&self) -> Vec<ReplicaRegion> {
        let mut regions = self
            .replicas
            .iter()
            .map(|replica| replica.region)
            .collect::<Vec<_>>();
        regions.sort();
        regions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn replica(region: u8, digest: u8) -> Replica {
        Replica {
            region: ReplicaRegion([region; 8]),
            digest: [digest; 32],
        }
    }
    #[test]
    fn verifies_and_canonicalizes_replicas() {
        let manifest = ReplicationManifest {
            artifact_digest: [7; 32],
            required_replicas: 2,
            replicas: vec![replica(2, 7), replica(1, 7)],
        };
        assert_eq!(manifest.verify(), Ok(()));
        assert_eq!(
            manifest.canonical_regions(),
            vec![ReplicaRegion([1; 8]), ReplicaRegion([2; 8])]
        );
    }
    #[test]
    fn rejects_missing_duplicate_and_mismatched_replicas() {
        let insufficient = ReplicationManifest {
            artifact_digest: [7; 32],
            required_replicas: 2,
            replicas: vec![replica(1, 7)],
        };
        assert_eq!(
            insufficient.verify(),
            Err(ManifestError::InsufficientReplicas)
        );
        let duplicate = ReplicationManifest {
            artifact_digest: [7; 32],
            required_replicas: 2,
            replicas: vec![replica(1, 7), replica(1, 7)],
        };
        assert_eq!(duplicate.verify(), Err(ManifestError::DuplicateRegion));
        let mismatch = ReplicationManifest {
            artifact_digest: [7; 32],
            required_replicas: 1,
            replicas: vec![replica(1, 8)],
        };
        assert_eq!(mismatch.verify(), Err(ManifestError::DigestMismatch));
    }
}
