#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use quotient_accountant_core::{BudgetKey, ComposedMomentProfile};

pub const MAX_ALPHA_ORDERS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimeUniformConfig {
    pub beta_numerator: u64,
    pub beta_denominator: u64,
    pub log_inverse_beta_q64_64_upper: u128,
    pub maximum_releases: u64,
}

impl TimeUniformConfig {
    pub const fn validate(self) -> Result<Self, OdometerError> {
        if self.beta_numerator == 0
            || self.beta_denominator == 0
            || self.beta_numerator >= self.beta_denominator
            || self.log_inverse_beta_q64_64_upper == 0
            || self.maximum_releases == 0
        {
            Err(OdometerError::InvalidConfig)
        } else {
            Ok(self)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundMeaning {
    ProfileBasedTimeUniformUpperBound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimeUniformBound {
    pub releases: u64,
    pub selected_alpha: u16,
    pub epsilon_q64_64_upper: u128,
    pub beta_numerator: u64,
    pub beta_denominator: u64,
    pub meaning: BoundMeaning,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyOdometer {
    budget_key: BudgetKey,
    config: TimeUniformConfig,
    alpha_orders: Vec<u16>,
    last_log_moments: Vec<u128>,
    releases: u64,
    maximum_reported_epsilon: u128,
    last_transcript_hash: [u8; 32],
}

impl PrivacyOdometer {
    pub fn new(
        budget_key: BudgetKey,
        alpha_orders: &[u16],
        initial_transcript_hash: [u8; 32],
        config: TimeUniformConfig,
    ) -> Result<Self, OdometerError> {
        budget_key
            .validate()
            .map_err(|_| OdometerError::InvalidBudgetKey)?;
        config.validate()?;
        validate_orders(alpha_orders)?;
        if initial_transcript_hash == [0; 32] {
            return Err(OdometerError::ZeroTranscriptHash);
        }
        Ok(Self {
            budget_key,
            config,
            alpha_orders: alpha_orders.to_vec(),
            last_log_moments: alloc::vec![0; alpha_orders.len()],
            releases: 0,
            maximum_reported_epsilon: 0,
            last_transcript_hash: initial_transcript_hash,
        })
    }

    pub fn advance(
        &mut self,
        snapshot: &ComposedMomentProfile,
    ) -> Result<TimeUniformBound, OdometerError> {
        self.validate_snapshot(snapshot)?;
        let (selected_alpha, current_epsilon) =
            select_bound(&self.alpha_orders, snapshot, self.config)?;
        let epsilon_q64_64_upper = current_epsilon.max(self.maximum_reported_epsilon);

        self.last_log_moments = snapshot
            .moments
            .iter()
            .map(|moment| moment.log_moment_q64_64_upper)
            .collect();
        self.releases = snapshot.releases;
        self.maximum_reported_epsilon = epsilon_q64_64_upper;
        self.last_transcript_hash = snapshot.last_public_transcript_hash;

        Ok(TimeUniformBound {
            releases: self.releases,
            selected_alpha,
            epsilon_q64_64_upper,
            beta_numerator: self.config.beta_numerator,
            beta_denominator: self.config.beta_denominator,
            meaning: BoundMeaning::ProfileBasedTimeUniformUpperBound,
        })
    }

    pub const fn releases(&self) -> u64 {
        self.releases
    }

    fn validate_snapshot(&self, snapshot: &ComposedMomentProfile) -> Result<(), OdometerError> {
        if snapshot.budget_key != self.budget_key {
            return Err(OdometerError::IncompatibleBudgetKey);
        }
        if snapshot.releases != self.releases + 1 {
            return Err(OdometerError::ReleaseSequenceDiscontinuity);
        }
        if snapshot.releases > self.config.maximum_releases {
            return Err(OdometerError::ResourceLimit);
        }
        if snapshot.last_public_transcript_hash == [0; 32] {
            return Err(OdometerError::ZeroTranscriptHash);
        }
        if snapshot.last_public_transcript_hash == self.last_transcript_hash {
            return Err(OdometerError::TranscriptReplay);
        }
        if snapshot.moments.len() != self.alpha_orders.len() {
            return Err(OdometerError::AlphaGridMismatch);
        }
        for ((moment, &alpha), &previous) in snapshot
            .moments
            .iter()
            .zip(&self.alpha_orders)
            .zip(&self.last_log_moments)
        {
            if moment.alpha != alpha {
                return Err(OdometerError::AlphaGridMismatch);
            }
            if moment.log_moment_q64_64_upper < previous {
                return Err(OdometerError::MomentRollback);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OdometerError {
    InvalidBudgetKey,
    InvalidConfig,
    EmptyOrders,
    InvalidOrder,
    NonCanonicalOrders,
    ResourceLimit,
    ZeroTranscriptHash,
    IncompatibleBudgetKey,
    ReleaseSequenceDiscontinuity,
    TranscriptReplay,
    AlphaGridMismatch,
    MomentRollback,
    ArithmeticOverflow,
}

fn select_bound(
    orders: &[u16],
    snapshot: &ComposedMomentProfile,
    config: TimeUniformConfig,
) -> Result<(u16, u128), OdometerError> {
    let mut selected = None;
    for (&alpha, moment) in orders.iter().zip(&snapshot.moments) {
        let numerator = moment
            .log_moment_q64_64_upper
            .checked_add(config.log_inverse_beta_q64_64_upper)
            .ok_or(OdometerError::ArithmeticOverflow)?;
        let denominator = u128::from(alpha - 1);
        let candidate = ceil_div(numerator, denominator)?;
        if selected.is_none_or(|(_, current)| candidate < current) {
            selected = Some((alpha, candidate));
        }
    }
    selected.ok_or(OdometerError::EmptyOrders)
}

fn ceil_div(numerator: u128, denominator: u128) -> Result<u128, OdometerError> {
    if denominator == 0 {
        return Err(OdometerError::InvalidOrder);
    }
    let quotient = numerator / denominator;
    let remainder = numerator % denominator;
    quotient
        .checked_add(u128::from(remainder != 0))
        .ok_or(OdometerError::ArithmeticOverflow)
}

fn validate_orders(orders: &[u16]) -> Result<(), OdometerError> {
    if orders.is_empty() {
        return Err(OdometerError::EmptyOrders);
    }
    if orders.len() > MAX_ALPHA_ORDERS {
        return Err(OdometerError::ResourceLimit);
    }
    let mut previous = 1;
    for &alpha in orders {
        if alpha <= 1 {
            return Err(OdometerError::InvalidOrder);
        }
        if alpha <= previous {
            return Err(OdometerError::NonCanonicalOrders);
        }
        previous = alpha;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use quotient_accountant_core::ConditionalMomentBound;

    const Q64: u128 = 1_u128 << 64;

    fn key() -> BudgetKey {
        BudgetKey {
            secret_family_hash: [1; 32],
            coalition_hash: [2; 32],
            action_quotient_hash: [3; 32],
            secret_model_version: 4,
            policy_epoch: 5,
        }
    }

    fn config() -> TimeUniformConfig {
        TimeUniformConfig {
            beta_numerator: 1,
            beta_denominator: 1_000_000,
            log_inverse_beta_q64_64_upper: 14 * Q64,
            maximum_releases: 10_000,
        }
    }

    fn snapshot(releases: u64, transcript: u8, values: [u128; 3]) -> ComposedMomentProfile {
        ComposedMomentProfile {
            budget_key: key(),
            moments: vec![
                ConditionalMomentBound {
                    alpha: 2,
                    log_moment_q64_64_upper: values[0],
                },
                ConditionalMomentBound {
                    alpha: 4,
                    log_moment_q64_64_upper: values[1],
                },
                ConditionalMomentBound {
                    alpha: 8,
                    log_moment_q64_64_upper: values[2],
                },
            ],
            releases,
            last_profile_epoch: 1,
            last_public_transcript_hash: [transcript; 32],
        }
    }

    fn odometer() -> PrivacyOdometer {
        PrivacyOdometer::new(key(), &[2, 4, 8], [9; 32], config()).unwrap()
    }

    #[test]
    fn time_uniform_report_selects_smallest_alpha_bound() {
        let mut odometer = odometer();
        let report = odometer
            .advance(&snapshot(1, 10, [Q64, 3 * Q64, 7 * Q64]))
            .unwrap();
        assert_eq!(report.selected_alpha, 8);
        assert_eq!(report.epsilon_q64_64_upper, 3 * Q64);
        assert_eq!(
            report.meaning,
            BoundMeaning::ProfileBasedTimeUniformUpperBound
        );
    }

    #[test]
    fn every_reported_prefix_is_monotone_under_adaptive_stopping() {
        let mut odometer = odometer();
        let first = odometer.advance(&snapshot(1, 10, [Q64, Q64, Q64])).unwrap();
        let second = odometer
            .advance(&snapshot(2, 11, [2 * Q64, 4 * Q64, 8 * Q64]))
            .unwrap();
        assert!(second.epsilon_q64_64_upper >= first.epsilon_q64_64_upper);
    }

    #[test]
    fn zero_profile_still_reports_declared_time_uniform_penalty() {
        let mut odometer = odometer();
        let report = odometer.advance(&snapshot(1, 10, [0, 0, 0])).unwrap();
        assert!(report.epsilon_q64_64_upper > 0);
        assert_eq!(report.selected_alpha, 8);
    }

    #[test]
    fn moment_sequence_and_transcript_rollback_fail_closed() {
        let mut odometer = odometer();
        odometer.advance(&snapshot(1, 10, [Q64, Q64, Q64])).unwrap();
        assert_eq!(
            odometer.advance(&snapshot(2, 11, [0, Q64, Q64])),
            Err(OdometerError::MomentRollback)
        );
        assert_eq!(
            odometer.advance(&snapshot(2, 10, [Q64, Q64, Q64])),
            Err(OdometerError::TranscriptReplay)
        );
        assert_eq!(
            odometer.advance(&snapshot(3, 11, [Q64, Q64, Q64])),
            Err(OdometerError::ReleaseSequenceDiscontinuity)
        );
    }

    #[test]
    fn incompatible_budget_key_and_resource_limit_are_rejected() {
        let mut odometer = odometer();
        let mut wrong = snapshot(1, 10, [0, 0, 0]);
        wrong.budget_key.policy_epoch += 1;
        assert_eq!(
            odometer.advance(&wrong),
            Err(OdometerError::IncompatibleBudgetKey)
        );

        let mut limited_config = config();
        limited_config.maximum_releases = 1;
        let mut limited = PrivacyOdometer::new(key(), &[2, 4, 8], [9; 32], limited_config).unwrap();
        limited.advance(&snapshot(1, 10, [0, 0, 0])).unwrap();
        assert_eq!(
            limited.advance(&snapshot(2, 11, [0, 0, 0])),
            Err(OdometerError::ResourceLimit)
        );
    }

    #[test]
    fn invalid_beta_and_arithmetic_overflow_fail_closed() {
        let mut invalid = config();
        invalid.beta_numerator = invalid.beta_denominator;
        assert_eq!(
            PrivacyOdometer::new(key(), &[2], [9; 32], invalid),
            Err(OdometerError::InvalidConfig)
        );
        let mut odometer = odometer();
        assert_eq!(
            odometer.advance(&snapshot(1, 10, [u128::MAX, u128::MAX, u128::MAX])),
            Err(OdometerError::ArithmeticOverflow)
        );
        assert_eq!(odometer.releases(), 0);
    }
}
