//! Multi-signal canary gate before full recovery deployment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanaryPolicy {
    pub minimum_samples: u32,
    pub minimum_proof_bps: u16,
    pub minimum_fail_closed_bps: u16,
    pub maximum_duration_ms: u64,
    pub maximum_privacy_spend: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanarySample {
    pub requests: u32,
    pub proofs_verified: u32,
    pub attacks: u32,
    pub attacks_blocked: u32,
    pub maximum_duration_ms: u64,
    pub privacy_spend: u64,
}
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CanaryReason {
    InsufficientSamples,
    ProofRegression,
    FailClosedRegression,
    DurationBreach,
    PrivacyBreach,
    InvalidSample,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanaryDecision {
    pub promote: bool,
    pub reasons: Vec<CanaryReason>,
}
#[must_use]
pub fn evaluate(p: CanaryPolicy, s: CanarySample) -> CanaryDecision {
    let mut r = Vec::new();
    if s.proofs_verified > s.requests
        || s.attacks_blocked > s.attacks
        || p.minimum_proof_bps > 10_000
        || p.minimum_fail_closed_bps > 10_000
    {
        r.push(CanaryReason::InvalidSample)
    }
    if s.requests < p.minimum_samples {
        r.push(CanaryReason::InsufficientSamples)
    }
    if ratio(s.proofs_verified, s.requests) < p.minimum_proof_bps {
        r.push(CanaryReason::ProofRegression)
    }
    if s.attacks > 0 && ratio(s.attacks_blocked, s.attacks) < p.minimum_fail_closed_bps {
        r.push(CanaryReason::FailClosedRegression)
    }
    if s.maximum_duration_ms > p.maximum_duration_ms {
        r.push(CanaryReason::DurationBreach)
    }
    if s.privacy_spend > p.maximum_privacy_spend {
        r.push(CanaryReason::PrivacyBreach)
    }
    r.sort();
    r.dedup();
    CanaryDecision {
        promote: r.is_empty(),
        reasons: r,
    }
}
fn ratio(n: u32, d: u32) -> u16 {
    if d == 0 {
        0
    } else {
        ((u64::from(n) * 10_000 / u64::from(d)).min(10_000)) as u16
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn p() -> CanaryPolicy {
        CanaryPolicy {
            minimum_samples: 100,
            minimum_proof_bps: 9_900,
            minimum_fail_closed_bps: 10_000,
            maximum_duration_ms: 500,
            maximum_privacy_spend: 20,
        }
    }
    #[test]
    fn healthy_canary_promotes() {
        assert!(
            evaluate(
                p(),
                CanarySample {
                    requests: 100,
                    proofs_verified: 100,
                    attacks: 2,
                    attacks_blocked: 2,
                    maximum_duration_ms: 400,
                    privacy_spend: 10
                }
            )
            .promote
        )
    }
    #[test]
    fn independent_breaches_block() {
        let d = evaluate(
            p(),
            CanarySample {
                requests: 50,
                proofs_verified: 40,
                attacks: 2,
                attacks_blocked: 1,
                maximum_duration_ms: 600,
                privacy_spend: 21,
            },
        );
        assert_eq!(d.reasons.len(), 5);
        assert!(!d.promote)
    }
}
