//! Privacy-safe aggregate SLO evaluation for recovery operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SloPolicy {
    pub maximum_duration_ms: u64,
    pub minimum_verification_bps: u16,
    pub minimum_fail_closed_bps: u16,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SloSample {
    pub recoveries: u32,
    pub verified: u32,
    pub attacks: u32,
    pub failed_closed: u32,
    pub maximum_duration_ms: u64,
}
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SloReason {
    DurationBreach,
    VerificationBreach,
    FailClosedBreach,
    InvalidSample,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SloReport {
    pub passed: bool,
    pub verification_bps: u16,
    pub fail_closed_bps: u16,
    pub reasons: Vec<SloReason>,
}
pub fn evaluate(policy: SloPolicy, sample: SloSample) -> SloReport {
    let mut reasons = Vec::new();
    if policy.maximum_duration_ms == 0
        || policy.minimum_verification_bps > 10_000
        || policy.minimum_fail_closed_bps > 10_000
        || sample.recoveries == 0
        || sample.verified > sample.recoveries
        || sample.failed_closed > sample.attacks
    {
        reasons.push(SloReason::InvalidSample);
    }
    let verification = ratio(sample.verified, sample.recoveries);
    let fail_closed = if sample.attacks == 0 {
        10_000
    } else {
        ratio(sample.failed_closed, sample.attacks)
    };
    if sample.maximum_duration_ms > policy.maximum_duration_ms {
        reasons.push(SloReason::DurationBreach)
    }
    if verification < policy.minimum_verification_bps {
        reasons.push(SloReason::VerificationBreach)
    }
    if fail_closed < policy.minimum_fail_closed_bps {
        reasons.push(SloReason::FailClosedBreach)
    }
    reasons.sort();
    reasons.dedup();
    SloReport {
        passed: reasons.is_empty(),
        verification_bps: verification,
        fail_closed_bps: fail_closed,
        reasons,
    }
}
#[must_use]
pub fn canonical_json(r: &SloReport) -> String {
    let reasons = r
        .reasons
        .iter()
        .map(|v| format!("\"{}\"", name(*v)))
        .collect::<Vec<_>>()
        .join(",");
    format!("{{\"schema\":\"noticer.recovery-slo.v1\",\"passed\":{},\"verification_bps\":{},\"fail_closed_bps\":{},\"reasons\":[{}]}}",r.passed,r.verification_bps,r.fail_closed_bps,reasons)
}
fn ratio(n: u32, d: u32) -> u16 {
    if d == 0 {
        0
    } else {
        ((u64::from(n) * 10_000) / u64::from(d)).min(10_000) as u16
    }
}
fn name(v: SloReason) -> &'static str {
    match v {
        SloReason::DurationBreach => "duration_breach",
        SloReason::VerificationBreach => "verification_breach",
        SloReason::FailClosedBreach => "fail_closed_breach",
        SloReason::InvalidSample => "invalid_sample",
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn p() -> SloPolicy {
        SloPolicy {
            maximum_duration_ms: 1_000,
            minimum_verification_bps: 9_900,
            minimum_fail_closed_bps: 10_000,
        }
    }
    #[test]
    fn healthy_aggregate_passes() {
        let r = evaluate(
            p(),
            SloSample {
                recoveries: 100,
                verified: 100,
                attacks: 4,
                failed_closed: 4,
                maximum_duration_ms: 900,
            },
        );
        assert!(r.passed);
        assert_eq!(r.verification_bps, 10_000)
    }
    #[test]
    fn breaches_have_stable_reasons() {
        let r = evaluate(
            p(),
            SloSample {
                recoveries: 100,
                verified: 90,
                attacks: 4,
                failed_closed: 3,
                maximum_duration_ms: 1_001,
            },
        );
        assert_eq!(
            r.reasons,
            vec![
                SloReason::DurationBreach,
                SloReason::VerificationBreach,
                SloReason::FailClosedBreach
            ]
        );
        assert!(canonical_json(&r).contains("duration_breach"));
    }
}
