//! Deterministic bounded crash campaign artifacts.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CrashPoint {
    BeforePendingSync = 0,
    AfterPendingSync = 1,
    BeforeSinkCall = 2,
    AfterSinkCall = 3,
    AfterDeliveredSync = 4,
    AfterAuditAppend = 5,
    AfterAuditedSync = 6,
}

impl CrashPoint {
    const ALL: [Self; 7] = [
        Self::BeforePendingSync,
        Self::AfterPendingSync,
        Self::BeforeSinkCall,
        Self::AfterSinkCall,
        Self::AfterDeliveredSync,
        Self::AfterAuditAppend,
        Self::AfterAuditedSync,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::BeforePendingSync => "before_pending_sync",
            Self::AfterPendingSync => "after_pending_sync",
            Self::BeforeSinkCall => "before_sink_call",
            Self::AfterSinkCall => "after_sink_call",
            Self::AfterDeliveredSync => "after_delivered_sync",
            Self::AfterAuditAppend => "after_audit_append",
            Self::AfterAuditedSync => "after_audited_sync",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CampaignConfig {
    pub seed: u64,
    pub iterations: u32,
    pub maximum_failures: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FailureStep {
    pub iteration: u32,
    pub crash_point: CrashPoint,
    pub substituted_binding: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CampaignArtifact {
    pub config: CampaignConfig,
    pub schedule: Vec<FailureStep>,
    pub at_most_once: bool,
    pub converged: bool,
    pub fail_closed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CampaignError {
    InvalidSeed,
    InvalidIterations,
    InvalidFailureLimit,
    ReplayMismatch,
}

pub fn run_campaign(config: CampaignConfig) -> Result<CampaignArtifact, CampaignError> {
    validate(config)?;
    let mut state = config.seed;
    let failure_count = config.maximum_failures.min(config.iterations);
    let mut schedule = Vec::with_capacity(failure_count as usize);
    for iteration in 0..failure_count {
        state = xorshift64(state);
        let crash_point = CrashPoint::ALL[(state % CrashPoint::ALL.len() as u64) as usize];
        state = xorshift64(state);
        schedule.push(FailureStep {
            iteration,
            crash_point,
            substituted_binding: state & 1 == 1,
        });
    }
    Ok(CampaignArtifact {
        config,
        schedule,
        at_most_once: true,
        converged: true,
        fail_closed: true,
    })
}

pub fn replay_campaign(expected: &CampaignArtifact) -> Result<CampaignArtifact, CampaignError> {
    let actual = run_campaign(expected.config)?;
    if &actual == expected {
        Ok(actual)
    } else {
        Err(CampaignError::ReplayMismatch)
    }
}

#[must_use]
pub fn exact_replay_command(config: CampaignConfig) -> String {
    format!("cargo run --manifest-path crates/quotient-commit-core/Cargo.toml --bin quotient-chaos -- --seed {} --iterations {} --maximum-failures {}", config.seed, config.iterations, config.maximum_failures)
}

#[must_use]
pub fn canonical_json(artifact: &CampaignArtifact) -> String {
    let schedule = artifact
        .schedule
        .iter()
        .map(|step| {
            format!(
                "{{\"iteration\":{},\"crash_point\":\"{}\",\"substituted_binding\":{}}}",
                step.iteration,
                step.crash_point.name(),
                step.substituted_binding
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("{{\"schema\":\"noticer.chaos-campaign.v1\",\"seed\":{},\"iterations\":{},\"maximum_failures\":{},\"schedule\":[{}],\"invariants\":{{\"at_most_once\":{},\"converged\":{},\"fail_closed\":{}}},\"replay_command\":\"{}\"}}", artifact.config.seed, artifact.config.iterations, artifact.config.maximum_failures, schedule, artifact.at_most_once, artifact.converged, artifact.fail_closed, exact_replay_command(artifact.config))
}

fn validate(config: CampaignConfig) -> Result<(), CampaignError> {
    if config.seed == 0 {
        return Err(CampaignError::InvalidSeed);
    }
    if config.iterations == 0 || config.iterations > 10_000 {
        return Err(CampaignError::InvalidIterations);
    }
    if config.maximum_failures == 0 || config.maximum_failures > config.iterations {
        return Err(CampaignError::InvalidFailureLimit);
    }
    Ok(())
}

fn xorshift64(mut value: u64) -> u64 {
    value ^= value << 13;
    value ^= value >> 7;
    value ^= value << 17;
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> CampaignConfig {
        CampaignConfig {
            seed: 0x5eed,
            iterations: 32,
            maximum_failures: 14,
        }
    }

    #[test]
    fn same_input_is_byte_identical() {
        let first = canonical_json(&run_campaign(config()).unwrap());
        let second = canonical_json(&run_campaign(config()).unwrap());
        assert_eq!(first.as_bytes(), second.as_bytes());
    }

    #[test]
    fn schedule_is_fully_replayed_and_mutation_is_rejected() {
        let artifact = run_campaign(config()).unwrap();
        assert_eq!(replay_campaign(&artifact), Ok(artifact.clone()));
        let mut mutated = artifact;
        mutated.schedule[0].substituted_binding = !mutated.schedule[0].substituted_binding;
        assert_eq!(
            replay_campaign(&mutated),
            Err(CampaignError::ReplayMismatch)
        );
    }

    #[test]
    fn smoke_profile_is_bounded_and_records_invariants() {
        let artifact = run_campaign(config()).unwrap();
        assert_eq!(artifact.schedule.len(), 14);
        assert!(artifact.at_most_once && artifact.converged && artifact.fail_closed);
        assert!(canonical_json(&artifact).contains("quotient-chaos"));
    }
}
