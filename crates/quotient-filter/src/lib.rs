#![no_std]
#![forbid(unsafe_code)]

use quotient_accountant_core::ComposedMomentProfile;
use quotient_odometer::{OdometerError, PrivacyOdometer, TimeUniformBound};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseDisposition {
    Allow,
    Delay,
    Coarsen,
    LocalOnly,
    Deny,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilterPolicy {
    pub allow_max_epsilon_q64_64: u128,
    pub delay_max_epsilon_q64_64: u128,
    pub coarsen_max_epsilon_q64_64: u128,
    pub local_only_max_epsilon_q64_64: u128,
}

impl FilterPolicy {
    pub const fn validate(self) -> Result<(), FilterPolicyError> {
        if self.allow_max_epsilon_q64_64 > self.delay_max_epsilon_q64_64
            || self.delay_max_epsilon_q64_64 > self.coarsen_max_epsilon_q64_64
            || self.coarsen_max_epsilon_q64_64 > self.local_only_max_epsilon_q64_64
        {
            return Err(FilterPolicyError::NonMonotoneThresholds);
        }
        Ok(())
    }

    #[must_use]
    pub const fn classify(self, epsilon_q64_64_upper: u128) -> ReleaseDisposition {
        if epsilon_q64_64_upper <= self.allow_max_epsilon_q64_64 {
            ReleaseDisposition::Allow
        } else if epsilon_q64_64_upper <= self.delay_max_epsilon_q64_64 {
            ReleaseDisposition::Delay
        } else if epsilon_q64_64_upper <= self.coarsen_max_epsilon_q64_64 {
            ReleaseDisposition::Coarsen
        } else if epsilon_q64_64_upper <= self.local_only_max_epsilon_q64_64 {
            ReleaseDisposition::LocalOnly
        } else {
            ReleaseDisposition::Deny
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilterPolicyError {
    NonMonotoneThresholds,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionReason {
    AccountedPrefix,
    AccountingRejected,
}

#[derive(Debug)]
pub struct FilterDecision {
    pub disposition: ReleaseDisposition,
    pub reason: DecisionReason,
    pub bound: Option<TimeUniformBound>,
    pub accounting_error: Option<OdometerError>,
}

impl FilterDecision {
    #[must_use]
    pub const fn is_release_allowed(&self) -> bool {
        matches!(self.disposition, ReleaseDisposition::Allow)
    }
}

pub struct PreReleaseFilter {
    odometer: PrivacyOdometer,
    policy: FilterPolicy,
}

impl PreReleaseFilter {
    pub fn new(odometer: PrivacyOdometer, policy: FilterPolicy) -> Result<Self, FilterPolicyError> {
        policy.validate()?;
        Ok(Self { odometer, policy })
    }

    #[must_use]
    pub const fn policy(&self) -> FilterPolicy {
        self.policy
    }

    pub fn evaluate(&mut self, candidate: &ComposedMomentProfile) -> FilterDecision {
        match self.odometer.advance(candidate) {
            Ok(bound) => FilterDecision {
                disposition: self.policy.classify(bound.epsilon_q64_64_upper),
                reason: DecisionReason::AccountedPrefix,
                bound: Some(bound),
                accounting_error: None,
            },
            Err(error) => FilterDecision {
                disposition: ReleaseDisposition::Deny,
                reason: DecisionReason::AccountingRejected,
                bound: None,
                accounting_error: Some(error),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const Q64: u128 = 1_u128 << 64;

    const POLICY: FilterPolicy = FilterPolicy {
        allow_max_epsilon_q64_64: 2 * Q64,
        delay_max_epsilon_q64_64: 3 * Q64,
        coarsen_max_epsilon_q64_64: 4 * Q64,
        local_only_max_epsilon_q64_64: 5 * Q64,
    };

    #[test]
    fn classifies_every_fail_closed_stage_at_exact_boundaries() {
        assert_eq!(POLICY.classify(2 * Q64), ReleaseDisposition::Allow);
        assert_eq!(POLICY.classify(3 * Q64), ReleaseDisposition::Delay);
        assert_eq!(POLICY.classify(4 * Q64), ReleaseDisposition::Coarsen);
        assert_eq!(POLICY.classify(5 * Q64), ReleaseDisposition::LocalOnly);
        assert_eq!(POLICY.classify(5 * Q64 + 1), ReleaseDisposition::Deny);
    }

    #[test]
    fn rejects_non_monotone_policy() {
        let invalid = FilterPolicy {
            allow_max_epsilon_q64_64: 3,
            delay_max_epsilon_q64_64: 2,
            coarsen_max_epsilon_q64_64: 4,
            local_only_max_epsilon_q64_64: 5,
        };
        assert_eq!(
            invalid.validate(),
            Err(FilterPolicyError::NonMonotoneThresholds)
        );
    }

    #[test]
    fn zero_threshold_policy_is_well_defined() {
        let zero = FilterPolicy {
            allow_max_epsilon_q64_64: 0,
            delay_max_epsilon_q64_64: 0,
            coarsen_max_epsilon_q64_64: 0,
            local_only_max_epsilon_q64_64: 0,
        };
        assert_eq!(zero.validate(), Ok(()));
        assert_eq!(zero.classify(0), ReleaseDisposition::Allow);
        assert_eq!(zero.classify(1), ReleaseDisposition::Deny);
    }
}
