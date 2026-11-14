//! Deterministic retention and erasure policy for recovery artifacts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactClass {
    Proof,
    Audit,
    Telemetry,
    Incident,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetentionPolicy {
    pub proof_ttl: u64,
    pub audit_ttl: u64,
    pub telemetry_ttl: u64,
    pub incident_ttl: u64,
    pub capacity: usize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedArtifact {
    pub digest: [u8; 32],
    pub class: ArtifactClass,
    pub created_at: u64,
    pub legal_hold: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PruningReport {
    pub removed: Vec<[u8; 32]>,
    pub retained: usize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetentionError {
    InvalidPolicy,
    InvalidArtifact,
    IllegalHold,
    Duplicate,
    CapacityBlocked,
}
#[derive(Debug)]
pub struct RetentionStore {
    policy: RetentionPolicy,
    artifacts: Vec<RetainedArtifact>,
}
impl RetentionStore {
    pub fn new(policy: RetentionPolicy) -> Result<Self, RetentionError> {
        if policy.capacity == 0
            || [
                policy.proof_ttl,
                policy.audit_ttl,
                policy.telemetry_ttl,
                policy.incident_ttl,
            ]
            .contains(&0)
        {
            Err(RetentionError::InvalidPolicy)
        } else {
            Ok(Self {
                policy,
                artifacts: Vec::new(),
            })
        }
    }
    pub fn insert(&mut self, value: RetainedArtifact) -> Result<(), RetentionError> {
        if value.digest == [0; 32] {
            return Err(RetentionError::InvalidArtifact);
        }
        if value.legal_hold && !matches!(value.class, ArtifactClass::Proof | ArtifactClass::Audit) {
            return Err(RetentionError::IllegalHold);
        }
        if self.artifacts.iter().any(|a| a.digest == value.digest) {
            return Err(RetentionError::Duplicate);
        }
        self.artifacts.push(value);
        Ok(())
    }
    pub fn prune(&mut self, now: u64) -> Result<PruningReport, RetentionError> {
        let mut removed = Vec::new();
        self.artifacts.retain(|a| {
            let expired = now >= a.created_at.saturating_add(ttl(self.policy, a.class));
            if expired && !a.legal_hold {
                removed.push(a.digest);
                false
            } else {
                true
            }
        });
        self.artifacts.sort_by_key(|a| (a.created_at, a.digest));
        while self.artifacts.len() > self.policy.capacity {
            let Some(index) = self.artifacts.iter().position(|a| !a.legal_hold) else {
                return Err(RetentionError::CapacityBlocked);
            };
            removed.push(self.artifacts.remove(index).digest);
        }
        Ok(PruningReport {
            removed,
            retained: self.artifacts.len(),
        })
    }
    #[must_use]
    pub fn artifacts(&self) -> &[RetainedArtifact] {
        &self.artifacts
    }
}
fn ttl(p: RetentionPolicy, c: ArtifactClass) -> u64 {
    match c {
        ArtifactClass::Proof => p.proof_ttl,
        ArtifactClass::Audit => p.audit_ttl,
        ArtifactClass::Telemetry => p.telemetry_ttl,
        ArtifactClass::Incident => p.incident_ttl,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn p() -> RetentionPolicy {
        RetentionPolicy {
            proof_ttl: 10,
            audit_ttl: 20,
            telemetry_ttl: 5,
            incident_ttl: 4,
            capacity: 2,
        }
    }
    #[test]
    fn expiration_and_capacity_are_deterministic() {
        let mut s = RetentionStore::new(p()).unwrap();
        s.insert(RetainedArtifact {
            digest: [1; 32],
            class: ArtifactClass::Proof,
            created_at: 1,
            legal_hold: true,
        })
        .unwrap();
        s.insert(RetainedArtifact {
            digest: [2; 32],
            class: ArtifactClass::Telemetry,
            created_at: 1,
            legal_hold: false,
        })
        .unwrap();
        s.insert(RetainedArtifact {
            digest: [3; 32],
            class: ArtifactClass::Audit,
            created_at: 2,
            legal_hold: false,
        })
        .unwrap();
        let r = s.prune(6).unwrap();
        assert_eq!(r.removed, vec![[2; 32]]);
        assert_eq!(r.retained, 2);
    }
    #[test]
    fn private_classes_cannot_be_held() {
        let mut s = RetentionStore::new(p()).unwrap();
        assert_eq!(
            s.insert(RetainedArtifact {
                digest: [1; 32],
                class: ArtifactClass::Incident,
                created_at: 1,
                legal_hold: true
            }),
            Err(RetentionError::IllegalHold)
        );
    }
}
