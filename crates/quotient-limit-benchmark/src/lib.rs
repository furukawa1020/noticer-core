#![no_std]
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Split {
    Development,
    HeldOut,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Category {
    Readiness,
    Deadline,
    Observer,
    Fault,
    Action,
    Longitudinal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultClass {
    None,
    OneErasure,
    BurstErasure,
    Reconnect,
    Duplicate,
    PublicFailure,
}

impl FaultClass {
    pub const fn is_nontrivial(self) -> bool {
        !matches!(self, Self::None)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BenchmarkFamily {
    pub id: &'static str,
    pub category: Category,
    pub split: Split,
    pub private_histories: u16,
    pub explicit_trace_horizon: u16,
    pub sequence_horizon: u16,
    pub observers: u8,
    pub services: u8,
    pub fault: FaultClass,
    pub procedural_seed: u64,
    pub has_handwritten_template: bool,
    pub has_known_optimum: bool,
}

const fn development(
    id: &'static str,
    category: Category,
    seed: u64,
    fault: FaultClass,
) -> BenchmarkFamily {
    BenchmarkFamily {
        id,
        category,
        split: Split::Development,
        private_histories: 4,
        explicit_trace_horizon: 16,
        sequence_horizon: 64,
        observers: 1,
        services: 1,
        fault,
        procedural_seed: seed,
        has_handwritten_template: true,
        has_known_optimum: true,
    }
}

const fn held_out(
    id: &'static str,
    category: Category,
    seed: u64,
    fault: FaultClass,
    services: u8,
) -> BenchmarkFamily {
    BenchmarkFamily {
        id,
        category,
        split: Split::HeldOut,
        private_histories: 8,
        explicit_trace_horizon: 16,
        sequence_horizon: 64,
        observers: 2,
        services,
        fault,
        procedural_seed: seed,
        has_handwritten_template: false,
        has_known_optimum: false,
    }
}

pub const BENCHMARK_FAMILIES: &[BenchmarkFamily] = &[
    development(
        "readiness.two_ready_times",
        Category::Readiness,
        1001,
        FaultClass::None,
    ),
    development(
        "readiness.four_ready_times",
        Category::Readiness,
        1002,
        FaultClass::None,
    ),
    development(
        "readiness.wide_span",
        Category::Readiness,
        1003,
        FaultClass::OneErasure,
    ),
    development(
        "readiness.narrow_span",
        Category::Readiness,
        1004,
        FaultClass::None,
    ),
    development(
        "deadline.generous",
        Category::Deadline,
        2001,
        FaultClass::None,
    ),
    development(
        "deadline.tight",
        Category::Deadline,
        2002,
        FaultClass::OneErasure,
    ),
    development(
        "deadline.impossible",
        Category::Deadline,
        2003,
        FaultClass::None,
    ),
    development(
        "deadline.multiple",
        Category::Deadline,
        2004,
        FaultClass::PublicFailure,
    ),
    development(
        "observer.presence",
        Category::Observer,
        3001,
        FaultClass::None,
    ),
    development(
        "observer.timing",
        Category::Observer,
        3002,
        FaultClass::OneErasure,
    ),
    development("observer.size", Category::Observer, 3003, FaultClass::None),
    development(
        "observer.failure",
        Category::Observer,
        3004,
        FaultClass::PublicFailure,
    ),
    development(
        "observer.service",
        Category::Observer,
        3005,
        FaultClass::Duplicate,
    ),
    held_out(
        "observer.collusion",
        Category::Observer,
        3901,
        FaultClass::BurstErasure,
        4,
    ),
    held_out(
        "observer.full_trace",
        Category::Observer,
        3902,
        FaultClass::PublicFailure,
        4,
    ),
    development("fault.none", Category::Fault, 4001, FaultClass::None),
    development(
        "fault.one_erasure",
        Category::Fault,
        4002,
        FaultClass::OneErasure,
    ),
    held_out(
        "fault.burst_erasure",
        Category::Fault,
        4901,
        FaultClass::BurstErasure,
        4,
    ),
    held_out(
        "fault.reconnect",
        Category::Fault,
        4902,
        FaultClass::Reconnect,
        3,
    ),
    development(
        "fault.duplicate",
        Category::Fault,
        4005,
        FaultClass::Duplicate,
    ),
    development(
        "fault.public_failure",
        Category::Fault,
        4006,
        FaultClass::PublicFailure,
    ),
    development("action.one", Category::Action, 5001, FaultClass::None),
    development(
        "action.multiple_types",
        Category::Action,
        5002,
        FaultClass::OneErasure,
    ),
    development(
        "action.repeated",
        Category::Action,
        5003,
        FaultClass::Duplicate,
    ),
    development(
        "action.exactly_once",
        Category::Action,
        5004,
        FaultClass::Reconnect,
    ),
    held_out(
        "action.optional",
        Category::Action,
        5901,
        FaultClass::PublicFailure,
        2,
    ),
    held_out(
        "action.ordered",
        Category::Action,
        5902,
        FaultClass::BurstErasure,
        3,
    ),
    development(
        "longitudinal.independent_buckets",
        Category::Longitudinal,
        6001,
        FaultClass::None,
    ),
    development(
        "longitudinal.public_handoff",
        Category::Longitudinal,
        6002,
        FaultClass::OneErasure,
    ),
    held_out(
        "longitudinal.invalid_private_carryover",
        Category::Longitudinal,
        6901,
        FaultClass::Reconnect,
        2,
    ),
    held_out(
        "longitudinal.shared_randomness",
        Category::Longitudinal,
        6902,
        FaultClass::Duplicate,
        4,
    ),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NegativeExpectation {
    Infeasible,
    JointPrivacyViolation,
    StateLowerBoundViolation,
    TracePrivacyViolation,
    CompositionViolation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NegativeModel {
    pub id: &'static str,
    pub name: &'static str,
    pub expectation: NegativeExpectation,
}

pub const NEGATIVE_MODELS: &[NegativeModel] = &[
    NegativeModel {
        id: "N0",
        name: "immediate_hidden_ready_time",
        expectation: NegativeExpectation::TracePrivacyViolation,
    },
    NegativeModel {
        id: "N1",
        name: "deadline_before_latest_readiness",
        expectation: NegativeExpectation::Infeasible,
    },
    NegativeModel {
        id: "N2",
        name: "no_cover_hidden_pre_admission",
        expectation: NegativeExpectation::Infeasible,
    },
    NegativeModel {
        id: "N3",
        name: "marginal_only_collusion",
        expectation: NegativeExpectation::JointPrivacyViolation,
    },
    NegativeModel {
        id: "N4",
        name: "recover_all_unbounded_drops",
        expectation: NegativeExpectation::Infeasible,
    },
    NegativeModel {
        id: "N5",
        name: "zero_state_exactly_once",
        expectation: NegativeExpectation::StateLowerBoundViolation,
    },
    NegativeModel {
        id: "N6",
        name: "secret_dependent_retry",
        expectation: NegativeExpectation::TracePrivacyViolation,
    },
    NegativeModel {
        id: "N7",
        name: "private_carryover_composition",
        expectation: NegativeExpectation::CompositionViolation,
    },
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CorpusSummary {
    pub family_count: usize,
    pub held_out_count: usize,
    pub negative_count: usize,
    pub maximum_explicit_horizon: u16,
    pub maximum_sequence_horizon: u16,
    pub maximum_services: u8,
    pub distinct_fault_classes: usize,
}

pub fn validate_frozen_corpus() -> Result<CorpusSummary, CorpusError> {
    if BENCHMARK_FAMILIES.len() < 24 {
        return Err(CorpusError::InsufficientFamilies);
    }
    let mut held_out_count = 0;
    let mut maximum_explicit_horizon = 0;
    let mut maximum_sequence_horizon = 0;
    let mut maximum_services = 0;
    let mut faults = [false; 6];

    for (index, family) in BENCHMARK_FAMILIES.iter().enumerate() {
        if family.id.is_empty() || family.private_histories < 2 || family.procedural_seed == 0 {
            return Err(CorpusError::InvalidFamily(family.id));
        }
        if BENCHMARK_FAMILIES[..index]
            .iter()
            .any(|prior| prior.id == family.id)
        {
            return Err(CorpusError::DuplicateFamily(family.id));
        }
        maximum_explicit_horizon = maximum_explicit_horizon.max(family.explicit_trace_horizon);
        maximum_sequence_horizon = maximum_sequence_horizon.max(family.sequence_horizon);
        maximum_services = maximum_services.max(family.services);
        faults[fault_index(family.fault)] = true;
        if family.split == Split::HeldOut {
            held_out_count += 1;
            if family.has_handwritten_template
                || family.has_known_optimum
                || family.observers < 2
                || family.services < 2
                || !family.fault.is_nontrivial()
            {
                return Err(CorpusError::InvalidHeldOutFamily(family.id));
            }
        }
    }

    if held_out_count < 8 {
        return Err(CorpusError::InsufficientHeldOutFamilies);
    }
    if maximum_explicit_horizon < 16 || maximum_sequence_horizon < 64 {
        return Err(CorpusError::HorizonGate);
    }
    if maximum_services < 4 {
        return Err(CorpusError::ServiceGate);
    }
    let distinct_fault_classes = faults.into_iter().filter(|present| *present).count();
    if distinct_fault_classes < 4 {
        return Err(CorpusError::FaultGate);
    }
    if NEGATIVE_MODELS.len() < 8 {
        return Err(CorpusError::NegativeModelGate);
    }
    for (index, model) in NEGATIVE_MODELS.iter().enumerate() {
        if model.id != negative_id(index) {
            return Err(CorpusError::NegativeModelOrder);
        }
    }

    Ok(CorpusSummary {
        family_count: BENCHMARK_FAMILIES.len(),
        held_out_count,
        negative_count: NEGATIVE_MODELS.len(),
        maximum_explicit_horizon,
        maximum_sequence_horizon,
        maximum_services,
        distinct_fault_classes,
    })
}

const fn fault_index(fault: FaultClass) -> usize {
    match fault {
        FaultClass::None => 0,
        FaultClass::OneErasure => 1,
        FaultClass::BurstErasure => 2,
        FaultClass::Reconnect => 3,
        FaultClass::Duplicate => 4,
        FaultClass::PublicFailure => 5,
    }
}

const fn negative_id(index: usize) -> &'static str {
    match index {
        0 => "N0",
        1 => "N1",
        2 => "N2",
        3 => "N3",
        4 => "N4",
        5 => "N5",
        6 => "N6",
        7 => "N7",
        _ => "",
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CorpusError {
    InsufficientFamilies,
    InsufficientHeldOutFamilies,
    InvalidFamily(&'static str),
    DuplicateFamily(&'static str),
    InvalidHeldOutFamily(&'static str),
    HorizonGate,
    ServiceGate,
    FaultGate,
    NegativeModelGate,
    NegativeModelOrder,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_corpus_satisfies_all_gates() {
        let summary = validate_frozen_corpus().unwrap();
        assert_eq!(summary.family_count, 31);
        assert_eq!(summary.held_out_count, 8);
        assert_eq!(summary.negative_count, 8);
        assert!(summary.maximum_explicit_horizon >= 16);
        assert!(summary.maximum_sequence_horizon >= 64);
        assert!(summary.maximum_services >= 4);
        assert!(summary.distinct_fault_classes >= 4);
    }

    #[test]
    fn held_out_families_are_template_and_optimum_blind() {
        for family in BENCHMARK_FAMILIES
            .iter()
            .filter(|family| family.split == Split::HeldOut)
        {
            assert!(!family.has_handwritten_template);
            assert!(!family.has_known_optimum);
            assert!(family.observers >= 2);
            assert!(family.services >= 2);
            assert!(family.fault.is_nontrivial());
        }
    }

    #[test]
    fn split_is_by_unique_family_identifier() {
        for (index, family) in BENCHMARK_FAMILIES.iter().enumerate() {
            assert!(!BENCHMARK_FAMILIES[..index]
                .iter()
                .any(|prior| prior.id == family.id));
        }
    }
}
