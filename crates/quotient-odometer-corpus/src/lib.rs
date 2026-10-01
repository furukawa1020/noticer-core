#![no_std]
#![forbid(unsafe_code)]

pub const CORPUS_SCHEMA: &str = "noticer.quotient-odometer-corpus.v1";
pub const CORPUS_VERSION: u16 = 1;
pub const REQUIRED_CASES_PER_AXIS_AND_SPLIT: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Split {
    Development = 0,
    HeldOut = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PrivacyAxis {
    Exact = 0,
    Approximate = 1,
    Adaptive = 2,
    Concurrent = 3,
    Coalition = 4,
    Longitudinal = 5,
    Crash = 6,
}

impl PrivacyAxis {
    const ALL: [Self; 7] = [
        Self::Exact,
        Self::Approximate,
        Self::Adaptive,
        Self::Concurrent,
        Self::Coalition,
        Self::Longitudinal,
        Self::Crash,
    ];

    const fn index(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum OracleExpectation {
    WithinBudget = 0,
    ExcessDetected = 1,
    AdmissionRejected = 2,
    RecoveryPreservesSpend = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CorpusCase {
    pub id: &'static str,
    pub family_id: &'static str,
    pub split: Split,
    pub axis: PrivacyAxis,
    pub rounds: u16,
    pub services: u8,
    pub principals: u8,
    pub crash_points: u8,
    pub adaptive_selector: bool,
    pub procedural_seed: u64,
    pub expectation: Option<OracleExpectation>,
    pub calibration_visible: bool,
}

#[allow(clippy::too_many_arguments)]
const fn development(
    id: &'static str,
    family_id: &'static str,
    axis: PrivacyAxis,
    seed: u64,
    rounds: u16,
    services: u8,
    principals: u8,
    crash_points: u8,
    adaptive_selector: bool,
    expectation: OracleExpectation,
) -> CorpusCase {
    CorpusCase {
        id,
        family_id,
        split: Split::Development,
        axis,
        rounds,
        services,
        principals,
        crash_points,
        adaptive_selector,
        procedural_seed: seed,
        expectation: Some(expectation),
        calibration_visible: true,
    }
}

#[allow(clippy::too_many_arguments)]
const fn held_out(
    id: &'static str,
    family_id: &'static str,
    axis: PrivacyAxis,
    seed: u64,
    rounds: u16,
    services: u8,
    principals: u8,
    crash_points: u8,
    adaptive_selector: bool,
) -> CorpusCase {
    CorpusCase {
        id,
        family_id,
        split: Split::HeldOut,
        axis,
        rounds,
        services,
        principals,
        crash_points,
        adaptive_selector,
        procedural_seed: seed,
        expectation: None,
        calibration_visible: false,
    }
}

pub const FROZEN_CORPUS: &[CorpusCase] = &[
    development(
        "dev.exact.single",
        "dev-exact-basic",
        PrivacyAxis::Exact,
        1101,
        16,
        1,
        1,
        0,
        false,
        OracleExpectation::WithinBudget,
    ),
    development(
        "dev.exact.exhaust",
        "dev-exact-exhaust",
        PrivacyAxis::Exact,
        1102,
        32,
        1,
        1,
        0,
        false,
        OracleExpectation::ExcessDetected,
    ),
    development(
        "dev.approx.delta",
        "dev-approx-delta",
        PrivacyAxis::Approximate,
        1201,
        32,
        1,
        1,
        0,
        false,
        OracleExpectation::WithinBudget,
    ),
    development(
        "dev.approx.reject",
        "dev-approx-reject",
        PrivacyAxis::Approximate,
        1202,
        48,
        2,
        1,
        0,
        false,
        OracleExpectation::AdmissionRejected,
    ),
    development(
        "dev.adaptive.selector",
        "dev-adaptive-selector",
        PrivacyAxis::Adaptive,
        1301,
        64,
        2,
        1,
        0,
        true,
        OracleExpectation::WithinBudget,
    ),
    development(
        "dev.adaptive.shopping",
        "dev-adaptive-shopping",
        PrivacyAxis::Adaptive,
        1302,
        96,
        3,
        1,
        0,
        true,
        OracleExpectation::ExcessDetected,
    ),
    development(
        "dev.concurrent.interleave",
        "dev-concurrent-interleave",
        PrivacyAxis::Concurrent,
        1401,
        64,
        4,
        1,
        0,
        true,
        OracleExpectation::WithinBudget,
    ),
    development(
        "dev.concurrent.race",
        "dev-concurrent-race",
        PrivacyAxis::Concurrent,
        1402,
        96,
        8,
        1,
        0,
        true,
        OracleExpectation::AdmissionRejected,
    ),
    development(
        "dev.coalition.pair",
        "dev-coalition-pair",
        PrivacyAxis::Coalition,
        1501,
        48,
        2,
        2,
        0,
        false,
        OracleExpectation::WithinBudget,
    ),
    development(
        "dev.coalition.escalate",
        "dev-coalition-escalate",
        PrivacyAxis::Coalition,
        1502,
        96,
        4,
        4,
        0,
        true,
        OracleExpectation::ExcessDetected,
    ),
    development(
        "dev.longitudinal.epochs",
        "dev-longitudinal-epochs",
        PrivacyAxis::Longitudinal,
        1601,
        128,
        2,
        1,
        0,
        false,
        OracleExpectation::WithinBudget,
    ),
    development(
        "dev.longitudinal.handoff",
        "dev-longitudinal-handoff",
        PrivacyAxis::Longitudinal,
        1602,
        192,
        3,
        2,
        0,
        true,
        OracleExpectation::AdmissionRejected,
    ),
    development(
        "dev.crash.single",
        "dev-crash-single",
        PrivacyAxis::Crash,
        1701,
        48,
        1,
        1,
        1,
        false,
        OracleExpectation::RecoveryPreservesSpend,
    ),
    development(
        "dev.crash.rollback",
        "dev-crash-rollback",
        PrivacyAxis::Crash,
        1702,
        96,
        2,
        1,
        3,
        true,
        OracleExpectation::ExcessDetected,
    ),
    held_out(
        "held.exact.boundary",
        "held-exact-boundary",
        PrivacyAxis::Exact,
        9101,
        33,
        2,
        1,
        0,
        false,
    ),
    held_out(
        "held.exact.sequence",
        "held-exact-sequence",
        PrivacyAxis::Exact,
        9102,
        127,
        3,
        1,
        0,
        true,
    ),
    held_out(
        "held.approx.rare",
        "held-approx-rare",
        PrivacyAxis::Approximate,
        9201,
        65,
        2,
        1,
        0,
        true,
    ),
    held_out(
        "held.approx.compose",
        "held-approx-compose",
        PrivacyAxis::Approximate,
        9202,
        129,
        4,
        2,
        0,
        true,
    ),
    held_out(
        "held.adaptive.churn",
        "held-adaptive-churn",
        PrivacyAxis::Adaptive,
        9301,
        97,
        5,
        2,
        0,
        true,
    ),
    held_out(
        "held.adaptive.shared",
        "held-adaptive-shared",
        PrivacyAxis::Adaptive,
        9302,
        193,
        6,
        3,
        0,
        true,
    ),
    held_out(
        "held.concurrent.fanout",
        "held-concurrent-fanout",
        PrivacyAxis::Concurrent,
        9401,
        129,
        8,
        2,
        0,
        true,
    ),
    held_out(
        "held.concurrent.reorder",
        "held-concurrent-reorder",
        PrivacyAxis::Concurrent,
        9402,
        257,
        12,
        3,
        0,
        true,
    ),
    held_out(
        "held.coalition.partial",
        "held-coalition-partial",
        PrivacyAxis::Coalition,
        9501,
        97,
        5,
        4,
        0,
        true,
    ),
    held_out(
        "held.coalition.rotate",
        "held-coalition-rotate",
        PrivacyAxis::Coalition,
        9502,
        193,
        7,
        6,
        0,
        true,
    ),
    held_out(
        "held.longitudinal.rotate",
        "held-longitudinal-rotate",
        PrivacyAxis::Longitudinal,
        9601,
        257,
        4,
        3,
        0,
        true,
    ),
    held_out(
        "held.longitudinal.rejoin",
        "held-longitudinal-rejoin",
        PrivacyAxis::Longitudinal,
        9602,
        513,
        6,
        4,
        0,
        true,
    ),
    held_out(
        "held.crash.window",
        "held-crash-window",
        PrivacyAxis::Crash,
        9701,
        129,
        3,
        2,
        4,
        true,
    ),
    held_out(
        "held.crash.fork",
        "held-crash-fork",
        PrivacyAxis::Crash,
        9702,
        257,
        5,
        3,
        8,
        true,
    ),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CorpusSummary {
    pub case_count: usize,
    pub development_count: usize,
    pub held_out_count: usize,
    pub maximum_rounds: u16,
    pub maximum_services: u8,
    pub maximum_principals: u8,
    pub maximum_crash_points: u8,
    pub fingerprint: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CorpusError {
    WrongSchemaVersion,
    WrongCaseCount,
    EmptyIdentifier,
    DuplicateCaseId,
    DuplicateSeed,
    FamilySplitLeakage,
    InvalidDimensions(&'static str),
    HeldOutOracleLeakage(&'static str),
    DevelopmentOracleMissing(&'static str),
    AxisCoverage { split: Split, axis: PrivacyAxis },
    AdaptiveCoverage { split: Split },
    CrashCoverage { split: Split },
    ScaleGate,
}

pub fn validate_frozen_corpus() -> Result<CorpusSummary, CorpusError> {
    if CORPUS_SCHEMA != "noticer.quotient-odometer-corpus.v1" || CORPUS_VERSION != 1 {
        return Err(CorpusError::WrongSchemaVersion);
    }
    validate_corpus(FROZEN_CORPUS)
}

pub fn validate_corpus(cases: &[CorpusCase]) -> Result<CorpusSummary, CorpusError> {
    if cases.len() != 28 {
        return Err(CorpusError::WrongCaseCount);
    }

    let mut coverage = [[0_usize; 7]; 2];
    let mut adaptive = [0_usize; 2];
    let mut crashes = [0_usize; 2];
    let mut development_count = 0;
    let mut held_out_count = 0;
    let mut maximum_rounds = 0;
    let mut maximum_services = 0;
    let mut maximum_principals = 0;
    let mut maximum_crash_points = 0;

    for (index, case) in cases.iter().enumerate() {
        if case.id.is_empty() || case.family_id.is_empty() {
            return Err(CorpusError::EmptyIdentifier);
        }
        if case.rounds == 0
            || case.services == 0
            || case.principals == 0
            || case.procedural_seed == 0
        {
            return Err(CorpusError::InvalidDimensions(case.id));
        }
        for prior in &cases[..index] {
            if prior.id == case.id {
                return Err(CorpusError::DuplicateCaseId);
            }
            if prior.procedural_seed == case.procedural_seed {
                return Err(CorpusError::DuplicateSeed);
            }
            if prior.family_id == case.family_id && prior.split != case.split {
                return Err(CorpusError::FamilySplitLeakage);
            }
        }

        let split_index = case.split as usize;
        coverage[split_index][case.axis.index()] += 1;
        adaptive[split_index] += usize::from(case.adaptive_selector);
        crashes[split_index] += usize::from(case.crash_points > 0);
        maximum_rounds = maximum_rounds.max(case.rounds);
        maximum_services = maximum_services.max(case.services);
        maximum_principals = maximum_principals.max(case.principals);
        maximum_crash_points = maximum_crash_points.max(case.crash_points);

        match case.split {
            Split::Development => {
                development_count += 1;
                if case.expectation.is_none() || !case.calibration_visible {
                    return Err(CorpusError::DevelopmentOracleMissing(case.id));
                }
            }
            Split::HeldOut => {
                held_out_count += 1;
                if case.expectation.is_some() || case.calibration_visible {
                    return Err(CorpusError::HeldOutOracleLeakage(case.id));
                }
            }
        }
    }

    for split in [Split::Development, Split::HeldOut] {
        for axis in PrivacyAxis::ALL {
            if coverage[split as usize][axis.index()] < REQUIRED_CASES_PER_AXIS_AND_SPLIT {
                return Err(CorpusError::AxisCoverage { split, axis });
            }
        }
        if adaptive[split as usize] < 4 {
            return Err(CorpusError::AdaptiveCoverage { split });
        }
        if crashes[split as usize] < 2 {
            return Err(CorpusError::CrashCoverage { split });
        }
    }

    if maximum_rounds < 512
        || maximum_services < 8
        || maximum_principals < 4
        || maximum_crash_points < 4
    {
        return Err(CorpusError::ScaleGate);
    }

    Ok(CorpusSummary {
        case_count: cases.len(),
        development_count,
        held_out_count,
        maximum_rounds,
        maximum_services,
        maximum_principals,
        maximum_crash_points,
        fingerprint: corpus_fingerprint(cases),
    })
}

pub fn corpus_fingerprint(cases: &[CorpusCase]) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for case in cases {
        hash_text(&mut hash, case.id);
        hash_text(&mut hash, case.family_id);
        for byte in [
            case.split as u8,
            case.axis as u8,
            case.services,
            case.principals,
            case.crash_points,
            u8::from(case.adaptive_selector),
            u8::from(case.calibration_visible),
        ] {
            hash_byte(&mut hash, byte);
        }
        for byte in case.rounds.to_le_bytes() {
            hash_byte(&mut hash, byte);
        }
        for byte in case.procedural_seed.to_le_bytes() {
            hash_byte(&mut hash, byte);
        }
        hash_byte(
            &mut hash,
            case.expectation.map_or(0xff, |value| value as u8),
        );
    }
    hash
}

fn hash_text(hash: &mut u64, value: &str) {
    for byte in value.as_bytes() {
        hash_byte(hash, *byte);
    }
    hash_byte(hash, 0);
}

fn hash_byte(hash: &mut u64, byte: u8) {
    *hash ^= u64::from(byte);
    *hash = hash.wrapping_mul(0x100000001b3);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_corpus_passes_all_contract_gates() {
        let summary = validate_frozen_corpus().unwrap();
        assert_eq!(summary.case_count, 28);
        assert_eq!(summary.development_count, 14);
        assert_eq!(summary.held_out_count, 14);
        assert!(summary.fingerprint != 0);
    }

    #[test]
    fn held_out_cases_expose_no_oracle_or_calibration_signal() {
        for case in FROZEN_CORPUS
            .iter()
            .filter(|case| case.split == Split::HeldOut)
        {
            assert_eq!(case.expectation, None);
            assert!(!case.calibration_visible);
        }
    }

    #[test]
    fn fingerprint_is_order_and_content_sensitive() {
        let original = corpus_fingerprint(FROZEN_CORPUS);
        let mut changed = FROZEN_CORPUS.to_vec();
        changed.swap(0, 1);
        assert_ne!(original, corpus_fingerprint(&changed));
        changed.swap(0, 1);
        changed[0].rounds += 1;
        assert_ne!(original, corpus_fingerprint(&changed));
    }

    #[test]
    fn family_split_leakage_is_rejected() {
        let mut changed = FROZEN_CORPUS.to_vec();
        changed[14].family_id = changed[0].family_id;
        assert_eq!(
            validate_corpus(&changed),
            Err(CorpusError::FamilySplitLeakage)
        );
    }

    #[test]
    fn held_out_oracle_leakage_is_rejected() {
        let mut changed = FROZEN_CORPUS.to_vec();
        changed[14].expectation = Some(OracleExpectation::WithinBudget);
        assert_eq!(
            validate_corpus(&changed),
            Err(CorpusError::HeldOutOracleLeakage("held.exact.boundary"))
        );
    }
}
