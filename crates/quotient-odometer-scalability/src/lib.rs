#![forbid(unsafe_code)]

use quotient_accountant_core::{BudgetKey, ComposedMomentProfile, ConditionalMomentBound};
use quotient_odometer::{OdometerError, PrivacyOdometer, TimeUniformConfig};
use std::time::Instant;

pub const RELEASES: u64 = 10_000;
pub const SERVICES: usize = 4;
pub const COALITIONS: usize = 3;
const Q64: u128 = 1_u128 << 64;
const ORDERS: [u16; 4] = [2, 4, 8, 16];
const UTILITY_BUDGET: u128 = 32 * Q64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScalabilityReport {
    pub releases: u64,
    pub service_trackers: usize,
    pub coalition_trackers: usize,
    pub odometer_advances: u64,
    pub elapsed_nanos: u128,
    pub releases_per_second: u64,
    pub peak_epsilon_q64_64: u128,
    pub composition_only_q64_64: u128,
    pub tightness_parts_per_million: u64,
    pub useful_releases: u64,
    pub utility_parts_per_million: u64,
}

impl ScalabilityReport {
    pub fn validate(&self) -> Result<(), BenchmarkError> {
        if self.releases != RELEASES
            || self.service_trackers != SERVICES
            || self.coalition_trackers != COALITIONS
            || self.odometer_advances != RELEASES * 2
        {
            return Err(BenchmarkError::CoverageGate);
        }
        if self.elapsed_nanos == 0 || self.releases_per_second == 0 {
            return Err(BenchmarkError::TimingUnavailable);
        }
        if self.peak_epsilon_q64_64 < self.composition_only_q64_64
            || self.composition_only_q64_64 == 0
            || self.tightness_parts_per_million < 1_000_000
            || self.utility_parts_per_million > 1_000_000
            || self.useful_releases > RELEASES
        {
            return Err(BenchmarkError::MetricInvariant);
        }
        Ok(())
    }

    pub fn json(&self) -> String {
        format!(
            "{{\"schema\":\"noticer.quotient-odometer-scalability.v1\",\"releases\":{},\"services\":{},\"coalitions\":{},\"odometer_advances\":{},\"elapsed_nanos\":{},\"releases_per_second\":{},\"peak_epsilon_q64_64\":{},\"composition_only_q64_64\":{},\"tightness_ppm\":{},\"useful_releases\":{},\"utility_ppm\":{}}}",
            self.releases,
            self.service_trackers,
            self.coalition_trackers,
            self.odometer_advances,
            self.elapsed_nanos,
            self.releases_per_second,
            self.peak_epsilon_q64_64,
            self.composition_only_q64_64,
            self.tightness_parts_per_million,
            self.useful_releases,
            self.utility_parts_per_million
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BenchmarkError {
    Odometer(OdometerError),
    ArithmeticOverflow,
    CoverageGate,
    TimingUnavailable,
    MetricInvariant,
}

impl From<OdometerError> for BenchmarkError {
    fn from(value: OdometerError) -> Self {
        Self::Odometer(value)
    }
}

pub fn run_scalability_benchmark() -> Result<ScalabilityReport, BenchmarkError> {
    let config = TimeUniformConfig {
        beta_numerator: 1,
        beta_denominator: 1_000_000,
        log_inverse_beta_q64_64_upper: 14 * Q64,
        maximum_releases: RELEASES,
    };
    let mut services = build_trackers(SERVICES, 0x10, config)?;
    let mut coalitions = build_trackers(COALITIONS, 0x80, config)?;
    let mut service_releases = [0_u64; SERVICES];
    let mut coalition_releases = [0_u64; COALITIONS];
    let mut peak = 0_u128;
    let mut composition_only = 0_u128;
    let mut useful_releases = 0_u64;
    let start = Instant::now();

    for global_release in 1..=RELEASES {
        let service = ((global_release - 1) as usize) % SERVICES;
        let coalition = ((global_release * 7 + (global_release / 11)) as usize) % COALITIONS;
        service_releases[service] += 1;
        coalition_releases[coalition] += 1;

        let service_profile = profile(
            key(service as u8, 0x10),
            service_releases[service],
            transcript(global_release, service as u8, 0x10),
        )?;
        let service_bound = services[service].advance(&service_profile)?;
        peak = peak.max(service_bound.epsilon_q64_64_upper);
        composition_only = composition_only.max(composition_oracle(&service_profile)?);

        let coalition_profile = profile(
            key(coalition as u8, 0x80),
            coalition_releases[coalition],
            transcript(global_release, coalition as u8, 0x80),
        )?;
        let coalition_bound = coalitions[coalition].advance(&coalition_profile)?;
        peak = peak.max(coalition_bound.epsilon_q64_64_upper);
        composition_only = composition_only.max(composition_oracle(&coalition_profile)?);

        if service_bound.epsilon_q64_64_upper <= UTILITY_BUDGET
            && coalition_bound.epsilon_q64_64_upper <= UTILITY_BUDGET
        {
            useful_releases += 1;
        }
    }

    let elapsed_nanos = start.elapsed().as_nanos().max(1);
    let report = ScalabilityReport {
        releases: RELEASES,
        service_trackers: SERVICES,
        coalition_trackers: COALITIONS,
        odometer_advances: RELEASES * 2,
        elapsed_nanos,
        releases_per_second: ((u128::from(RELEASES) * 1_000_000_000) / elapsed_nanos)
            .try_into()
            .unwrap_or(u64::MAX),
        peak_epsilon_q64_64: peak,
        composition_only_q64_64: composition_only,
        tightness_parts_per_million: ratio_ppm(peak, composition_only)?,
        useful_releases,
        utility_parts_per_million: ((u128::from(useful_releases) * 1_000_000)
            / u128::from(RELEASES)) as u64,
    };
    report.validate()?;
    Ok(report)
}

fn build_trackers(
    count: usize,
    domain: u8,
    config: TimeUniformConfig,
) -> Result<Vec<PrivacyOdometer>, BenchmarkError> {
    (0..count)
        .map(|index| {
            PrivacyOdometer::new(
                key(index as u8, domain),
                &ORDERS,
                [domain.wrapping_add(index as u8).wrapping_add(1); 32],
                config,
            )
            .map_err(Into::into)
        })
        .collect()
}

fn key(index: u8, domain: u8) -> BudgetKey {
    BudgetKey {
        secret_family_hash: [domain; 32],
        coalition_hash: [index.wrapping_add(1); 32],
        action_quotient_hash: [domain ^ index ^ 0x5a; 32],
        secret_model_version: 1,
        policy_epoch: 1,
    }
}

fn transcript(global_release: u64, index: u8, domain: u8) -> [u8; 32] {
    let mut hash = [0_u8; 32];
    hash[..8].copy_from_slice(&global_release.to_le_bytes());
    hash[8] = index;
    hash[9] = domain;
    hash[31] = 1;
    hash
}

fn profile(
    budget_key: BudgetKey,
    releases: u64,
    hash: [u8; 32],
) -> Result<ComposedMomentProfile, BenchmarkError> {
    let moments = ORDERS
        .iter()
        .map(|&alpha| {
            u128::from(releases)
                .checked_mul(Q64 / 16)
                .and_then(|base| base.checked_mul(u128::from(alpha)))
                .map(|value| ConditionalMomentBound {
                    alpha,
                    log_moment_q64_64_upper: value,
                })
                .ok_or(BenchmarkError::ArithmeticOverflow)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ComposedMomentProfile {
        budget_key,
        moments,
        releases,
        last_profile_epoch: 1,
        last_public_transcript_hash: hash,
    })
}

fn composition_oracle(profile: &ComposedMomentProfile) -> Result<u128, BenchmarkError> {
    profile
        .moments
        .iter()
        .map(|moment| {
            let denominator = u128::from(moment.alpha - 1);
            moment
                .log_moment_q64_64_upper
                .checked_add(denominator - 1)
                .map(|value| value / denominator)
                .ok_or(BenchmarkError::ArithmeticOverflow)
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .min()
        .ok_or(BenchmarkError::MetricInvariant)
}

fn ratio_ppm(numerator: u128, denominator: u128) -> Result<u64, BenchmarkError> {
    numerator
        .checked_mul(1_000_000)
        .map(|value| value / denominator)
        .and_then(|value| value.try_into().ok())
        .ok_or(BenchmarkError::ArithmeticOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ten_thousand_release_campaign_satisfies_all_gates() {
        let report = run_scalability_benchmark().unwrap();
        assert_eq!(report.releases, 10_000);
        assert_eq!(report.odometer_advances, 20_000);
        assert!(report.tightness_parts_per_million >= 1_000_000);
        assert!(report.useful_releases > 0);
        assert!(report.useful_releases < RELEASES);
    }

    #[test]
    fn non_timing_metrics_are_reproducible() {
        let left = run_scalability_benchmark().unwrap();
        let right = run_scalability_benchmark().unwrap();
        assert_eq!(left.peak_epsilon_q64_64, right.peak_epsilon_q64_64);
        assert_eq!(left.composition_only_q64_64, right.composition_only_q64_64);
        assert_eq!(
            left.tightness_parts_per_million,
            right.tightness_parts_per_million
        );
        assert_eq!(
            left.utility_parts_per_million,
            right.utility_parts_per_million
        );
    }

    #[test]
    fn report_is_machine_readable_and_schema_tagged() {
        let json = run_scalability_benchmark().unwrap().json();
        assert!(json.starts_with("{\"schema\":\"noticer.quotient-odometer-scalability.v1\""));
        assert!(json.contains("\"releases\":10000"));
    }
}
