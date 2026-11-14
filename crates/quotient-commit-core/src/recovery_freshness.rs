//! Freshness oracle for recovery evidence classes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EvidenceClass {
    Proof,
    Quorum,
    Lease,
    Audit,
    Slo,
    Attestation,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FreshnessPolicy {
    pub maximum_age: u64,
    pub maximum_future_skew: u64,
    pub policy_epoch: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimedEvidence {
    pub class: EvidenceClass,
    pub policy_epoch: u64,
    pub issued_at: u64,
    pub digest: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FreshnessReason {
    InvalidEvidence,
    EpochMismatch,
    Expired,
    FutureDated,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FreshnessReport {
    pub passed: bool,
    pub reasons: Vec<(EvidenceClass, FreshnessReason)>,
}
#[must_use]
pub fn evaluate(policy: FreshnessPolicy, now: u64, evidence: &[TimedEvidence]) -> FreshnessReport {
    let mut reasons = Vec::new();
    for e in evidence {
        if e.digest == [0; 32] || e.issued_at == 0 {
            reasons.push((e.class, FreshnessReason::InvalidEvidence))
        }
        if e.policy_epoch != policy.policy_epoch || policy.policy_epoch == 0 {
            reasons.push((e.class, FreshnessReason::EpochMismatch))
        }
        if e.issued_at > now.saturating_add(policy.maximum_future_skew) {
            reasons.push((e.class, FreshnessReason::FutureDated))
        } else if now.saturating_sub(e.issued_at) > policy.maximum_age {
            reasons.push((e.class, FreshnessReason::Expired))
        }
    }
    reasons.sort();
    reasons.dedup();
    FreshnessReport {
        passed: reasons.is_empty(),
        reasons,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn e(t: u64) -> TimedEvidence {
        TimedEvidence {
            class: EvidenceClass::Proof,
            policy_epoch: 2,
            issued_at: t,
            digest: [1; 32],
        }
    }
    fn p() -> FreshnessPolicy {
        FreshnessPolicy {
            maximum_age: 10,
            maximum_future_skew: 2,
            policy_epoch: 2,
        }
    }
    #[test]
    fn fresh_evidence_passes() {
        assert!(evaluate(p(), 100, &[e(95)]).passed)
    }
    #[test]
    fn stale_future_and_epoch_mismatch_fail() {
        assert_eq!(
            evaluate(p(), 100, &[e(89)]).reasons,
            vec![(EvidenceClass::Proof, FreshnessReason::Expired)]
        );
        assert_eq!(
            evaluate(p(), 100, &[e(103)]).reasons,
            vec![(EvidenceClass::Proof, FreshnessReason::FutureDated)]
        );
        let mut x = e(95);
        x.policy_epoch = 3;
        assert_eq!(
            evaluate(p(), 100, &[x]).reasons,
            vec![(EvidenceClass::Proof, FreshnessReason::EpochMismatch)]
        );
    }
}
