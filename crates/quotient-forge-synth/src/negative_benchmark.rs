//! Frozen negative corpus separating bounded unrealizability from invalid input.

use quotient_forge_check::ActionId;

use crate::generic_benchmark::generic_benchmark_case;
use crate::SynthesisProblem;

pub const NEGATIVE_BENCHMARK_FAMILY_IDS: [&str; 8] = [
    "negative_missing_authorized_output",
    "negative_secret_dependent_retry",
    "negative_impossible_deadline",
    "negative_failure_leak",
    "negative_quotient_merge",
    "negative_private_carryover",
    "negative_observer_omission",
    "negative_unauthorized_cover_action",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NegativeBenchmarkSplit {
    Train,
    Development,
    HeldOut,
}

impl NegativeBenchmarkSplit {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Train => "train",
            Self::Development => "development",
            Self::HeldOut => "held_out",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NegativeExpectedStatus {
    UnsatAtBound,
    InvalidSpec,
}

impl NegativeExpectedStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsatAtBound => "UNSAT_AT_BOUND",
            Self::InvalidSpec => "INVALID_SPEC",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefutationReason {
    MissingAuthorizedOutput,
    SecretDependentRetry,
    ImpossibleDeadline,
    FailureFieldPrivateFlow,
    PrivateFieldNotErased,
    PrivateCarryover,
    ActionServiceObserverMissing,
    UnauthorizedCoverAction,
}

impl RefutationReason {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::MissingAuthorizedOutput => "MISSING_AUTHORIZED_OUTPUT",
            Self::SecretDependentRetry => "SECRET_DEPENDENT_RETRY",
            Self::ImpossibleDeadline => "IMPOSSIBLE_DEADLINE",
            Self::FailureFieldPrivateFlow => "FAILURE_FIELD_PRIVATE_FLOW",
            Self::PrivateFieldNotErased => "PRIVATE_FIELD_NOT_ERASED",
            Self::PrivateCarryover => "PRIVATE_CARRYOVER",
            Self::ActionServiceObserverMissing => "ACTION_SERVICE_OBSERVER_MISSING",
            Self::UnauthorizedCoverAction => "UNAUTHORIZED_COVER_ACTION",
        }
    }

    #[must_use]
    pub const fn diagnostic_code(self) -> Option<&'static str> {
        match self {
            Self::SecretDependentRetry | Self::FailureFieldPrivateFlow | Self::PrivateCarryover => {
                Some("QF031")
            }
            Self::ImpossibleDeadline | Self::ActionServiceObserverMissing => Some("QF033"),
            Self::PrivateFieldNotErased => Some("QF035"),
            Self::MissingAuthorizedOutput | Self::UnauthorizedCoverAction => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NegativeLowering {
    Bounded {
        problem: SynthesisProblem,
        state_bound: u32,
    },
    InvalidSpec {
        diagnostic_code: &'static str,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegativeBenchmarkCase {
    pub family_id: &'static str,
    pub split: NegativeBenchmarkSplit,
    pub expected_status: NegativeExpectedStatus,
    pub reason: RefutationReason,
    pub difficulty_tier: &'static str,
    pub lowering: NegativeLowering,
}

#[derive(Clone, Copy)]
struct Definition {
    family_id: &'static str,
    split: NegativeBenchmarkSplit,
    expected_status: NegativeExpectedStatus,
    reason: RefutationReason,
    difficulty_tier: &'static str,
}

const DEFINITIONS: [Definition; 8] = [
    Definition {
        family_id: "negative_missing_authorized_output",
        split: NegativeBenchmarkSplit::Train,
        expected_status: NegativeExpectedStatus::UnsatAtBound,
        reason: RefutationReason::MissingAuthorizedOutput,
        difficulty_tier: "D1",
    },
    Definition {
        family_id: "negative_secret_dependent_retry",
        split: NegativeBenchmarkSplit::Train,
        expected_status: NegativeExpectedStatus::InvalidSpec,
        reason: RefutationReason::SecretDependentRetry,
        difficulty_tier: "D1",
    },
    Definition {
        family_id: "negative_impossible_deadline",
        split: NegativeBenchmarkSplit::Development,
        expected_status: NegativeExpectedStatus::InvalidSpec,
        reason: RefutationReason::ImpossibleDeadline,
        difficulty_tier: "D2",
    },
    Definition {
        family_id: "negative_failure_leak",
        split: NegativeBenchmarkSplit::Development,
        expected_status: NegativeExpectedStatus::InvalidSpec,
        reason: RefutationReason::FailureFieldPrivateFlow,
        difficulty_tier: "D2",
    },
    Definition {
        family_id: "negative_quotient_merge",
        split: NegativeBenchmarkSplit::Development,
        expected_status: NegativeExpectedStatus::InvalidSpec,
        reason: RefutationReason::PrivateFieldNotErased,
        difficulty_tier: "D2",
    },
    Definition {
        family_id: "negative_private_carryover",
        split: NegativeBenchmarkSplit::HeldOut,
        expected_status: NegativeExpectedStatus::InvalidSpec,
        reason: RefutationReason::PrivateCarryover,
        difficulty_tier: "D3",
    },
    Definition {
        family_id: "negative_observer_omission",
        split: NegativeBenchmarkSplit::HeldOut,
        expected_status: NegativeExpectedStatus::InvalidSpec,
        reason: RefutationReason::ActionServiceObserverMissing,
        difficulty_tier: "D3",
    },
    Definition {
        family_id: "negative_unauthorized_cover_action",
        split: NegativeBenchmarkSplit::HeldOut,
        expected_status: NegativeExpectedStatus::UnsatAtBound,
        reason: RefutationReason::UnauthorizedCoverAction,
        difficulty_tier: "D4",
    },
];

#[must_use]
pub fn negative_benchmark_cases() -> Vec<NegativeBenchmarkCase> {
    DEFINITIONS.iter().copied().map(build_case).collect()
}

#[must_use]
pub fn negative_benchmark_case(family_id: &str) -> Option<NegativeBenchmarkCase> {
    DEFINITIONS
        .iter()
        .copied()
        .find(|definition| definition.family_id == family_id)
        .map(build_case)
}

fn build_case(definition: Definition) -> NegativeBenchmarkCase {
    let lowering = match definition.reason {
        RefutationReason::MissingAuthorizedOutput => {
            let mut problem = base_problem();
            problem.outputs.truncate(1);
            NegativeLowering::Bounded {
                problem,
                state_bound: 3,
            }
        }
        RefutationReason::UnauthorizedCoverAction => {
            let mut problem = base_problem();
            problem.outputs[1].actions[0].action = ActionId::from("cover");
            NegativeLowering::Bounded {
                problem,
                state_bound: 3,
            }
        }
        reason => NegativeLowering::InvalidSpec {
            diagnostic_code: reason
                .diagnostic_code()
                .expect("invalid definitions have a diagnostic"),
        },
    };
    NegativeBenchmarkCase {
        family_id: definition.family_id,
        split: definition.split,
        expected_status: definition.expected_status,
        reason: definition.reason,
        difficulty_tier: definition.difficulty_tier,
        lowering,
    }
}

fn base_problem() -> SynthesisProblem {
    generic_benchmark_case("generic_delayed_notification")
        .expect("frozen generic base case")
        .problem
}
