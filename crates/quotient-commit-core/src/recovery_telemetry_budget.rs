//! Budgeted, bucketed recovery telemetry without per-subject identifiers.
use crate::receipt::hmac_sha256;
const DOMAIN: &[u8] = b"noticer.quotient-commit.recovery-telemetry-budget.v1\0";
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TelemetryEvent {
    CeremonyCompleted,
    CeremonyAborted,
    CrashRestart,
    BacklogHalt,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TelemetryPolicy {
    pub epoch: u64,
    pub maximum_releases: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TelemetryRelease {
    pub policy_epoch: u64,
    pub release_sequence: u32,
    pub completed_bucket: u8,
    pub aborted_bucket: u8,
    pub restart_bucket: u8,
    pub backlog_halt_bucket: u8,
    pub authenticator: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TelemetryBudgetError {
    InvalidKey,
    InvalidPolicy,
    BudgetExceeded,
}
#[derive(Debug)]
pub struct RecoveryTelemetryBudget {
    policy: TelemetryPolicy,
    key: [u8; 32],
    releases: u32,
    counts: [u64; 4],
}
impl RecoveryTelemetryBudget {
    pub fn new(policy: TelemetryPolicy, key: [u8; 32]) -> Result<Self, TelemetryBudgetError> {
        if key == [0; 32] {
            return Err(TelemetryBudgetError::InvalidKey);
        }
        if policy.epoch == 0 || policy.maximum_releases == 0 {
            return Err(TelemetryBudgetError::InvalidPolicy);
        }
        Ok(Self {
            policy,
            key,
            releases: 0,
            counts: [0; 4],
        })
    }
    pub fn observe(&mut self, event: TelemetryEvent) {
        let index = match event {
            TelemetryEvent::CeremonyCompleted => 0,
            TelemetryEvent::CeremonyAborted => 1,
            TelemetryEvent::CrashRestart => 2,
            TelemetryEvent::BacklogHalt => 3,
        };
        self.counts[index] = self.counts[index].saturating_add(1);
    }
    pub fn release(&mut self) -> Result<TelemetryRelease, TelemetryBudgetError> {
        if self.releases >= self.policy.maximum_releases {
            return Err(TelemetryBudgetError::BudgetExceeded);
        }
        self.releases += 1;
        let mut value = TelemetryRelease {
            policy_epoch: self.policy.epoch,
            release_sequence: self.releases,
            completed_bucket: bucket(self.counts[0]),
            aborted_bucket: bucket(self.counts[1]),
            restart_bucket: bucket(self.counts[2]),
            backlog_halt_bucket: bucket(self.counts[3]),
            authenticator: [0; 32],
        };
        value.authenticator = authenticate(value, self.key);
        Ok(value)
    }
}
fn bucket(value: u64) -> u8 {
    match value {
        0 => 0,
        1 => 1,
        2..=3 => 2,
        4..=7 => 3,
        _ => 4,
    }
}
fn authenticate(mut v: TelemetryRelease, key: [u8; 32]) -> [u8; 32] {
    v.authenticator = [0; 32];
    let mut b = Vec::with_capacity(DOMAIN.len() + 17);
    b.extend_from_slice(DOMAIN);
    b.extend_from_slice(&v.policy_epoch.to_be_bytes());
    b.extend_from_slice(&v.release_sequence.to_be_bytes());
    b.extend_from_slice(&[
        v.completed_bucket,
        v.aborted_bucket,
        v.restart_bucket,
        v.backlog_halt_bucket,
    ]);
    hmac_sha256(key, &b)
}
#[must_use]
pub fn canonical_json(v: TelemetryRelease) -> String {
    format!("{{\"schema\":\"noticer.recovery-telemetry.v1\",\"policy_epoch\":{},\"release_sequence\":{},\"buckets\":{{\"completed\":{},\"aborted\":{},\"restart\":{},\"backlog_halt\":{}}},\"authenticator\":\"{}\"}}",v.policy_epoch,v.release_sequence,v.completed_bucket,v.aborted_bucket,v.restart_bucket,v.backlog_halt_bucket,hex(v.authenticator))
}
fn hex(v: [u8; 32]) -> String {
    v.iter().map(|b| format!("{b:02x}")).collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    const KEY: [u8; 32] = [7; 32];
    fn run() -> TelemetryRelease {
        let mut b = RecoveryTelemetryBudget::new(
            TelemetryPolicy {
                epoch: 1,
                maximum_releases: 2,
            },
            KEY,
        )
        .unwrap();
        for _ in 0..5 {
            b.observe(TelemetryEvent::CrashRestart)
        }
        b.observe(TelemetryEvent::CeremonyCompleted);
        b.release().unwrap()
    }
    #[test]
    fn deterministic_buckets_hide_exact_counts() {
        let a = run();
        let b = run();
        assert_eq!(a, b);
        assert_eq!(a.restart_bucket, 3);
        let json = canonical_json(a);
        for x in ["transaction", "subject", "identity", "biosignal", "device"] {
            assert!(!json.contains(x));
        }
    }
    #[test]
    fn release_budget_fails_closed() {
        let mut b = RecoveryTelemetryBudget::new(
            TelemetryPolicy {
                epoch: 1,
                maximum_releases: 1,
            },
            KEY,
        )
        .unwrap();
        b.release().unwrap();
        assert_eq!(b.release(), Err(TelemetryBudgetError::BudgetExceeded));
    }
    #[test]
    fn adjacent_counts_share_buckets() {
        let mut a = RecoveryTelemetryBudget::new(
            TelemetryPolicy {
                epoch: 1,
                maximum_releases: 1,
            },
            KEY,
        )
        .unwrap();
        let mut b = RecoveryTelemetryBudget::new(
            TelemetryPolicy {
                epoch: 1,
                maximum_releases: 1,
            },
            KEY,
        )
        .unwrap();
        for _ in 0..4 {
            a.observe(TelemetryEvent::CeremonyAborted)
        }
        for _ in 0..7 {
            b.observe(TelemetryEvent::CeremonyAborted)
        }
        assert_eq!(
            a.release().unwrap().aborted_bucket,
            b.release().unwrap().aborted_bucket
        );
    }
}
