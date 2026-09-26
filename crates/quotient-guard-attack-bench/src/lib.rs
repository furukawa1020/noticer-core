#![forbid(unsafe_code)]

use std::fmt::Write as _;

pub const DEFAULT_SEED: u64 = 0x5147_0006_C0DE_2026;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum AttackKind {
    ConfigSubstitution,
    EpochRollback,
    TimingProbe,
    FaultAmplification,
    ColludingObserver,
    ReplaySplice,
}

impl AttackKind {
    pub const ALL: [Self; 6] = [
        Self::ConfigSubstitution,
        Self::EpochRollback,
        Self::TimingProbe,
        Self::FaultAmplification,
        Self::ColludingObserver,
        Self::ReplaySplice,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConfigSubstitution => "config_substitution",
            Self::EpochRollback => "epoch_rollback",
            Self::TimingProbe => "timing_probe",
            Self::FaultAmplification => "fault_amplification",
            Self::ColludingObserver => "colluding_observer",
            Self::ReplaySplice => "replay_splice",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixtureClass {
    Attack,
    NegativeControl,
}

impl FixtureClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Attack => "attack",
            Self::NegativeControl => "negative_control",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetectionReason {
    ConfigDigestMismatch,
    EpochRollback,
    TimingRelationViolation,
    FaultBudgetExceeded,
    CrossServiceLinkage,
    SlotDiscontinuity,
}

impl DetectionReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConfigDigestMismatch => "config_digest_mismatch",
            Self::EpochRollback => "epoch_rollback",
            Self::TimingRelationViolation => "timing_relation_violation",
            Self::FaultBudgetExceeded => "fault_budget_exceeded",
            Self::CrossServiceLinkage => "cross_service_linkage",
            Self::SlotDiscontinuity => "slot_discontinuity",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verdict {
    Accepted,
    Detected(DetectionReason),
}

impl Verdict {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Detected(_) => "detected",
        }
    }

    pub const fn reason(self) -> &'static str {
        match self {
            Self::Accepted => "none",
            Self::Detected(reason) => reason.as_str(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fixture {
    pub fixture_id: u64,
    pub kind: AttackKind,
    pub class: FixtureClass,
    approved_digest: u64,
    observed_digest: u64,
    current_epoch: u64,
    observed_epoch: u64,
    expected_slot: u64,
    observed_slot: u64,
    reference_delay: u16,
    observed_delay: u16,
    fault_budget: u8,
    injected_faults: u8,
    service_a_tag: u64,
    service_b_tag: u64,
}

impl Fixture {
    pub const fn expected_verdict(self) -> Verdict {
        match self.class {
            FixtureClass::Attack => Verdict::Detected(reason_for(self.kind)),
            FixtureClass::NegativeControl => Verdict::Accepted,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Observation {
    pub fixture_id: u64,
    pub kind: AttackKind,
    pub class: FixtureClass,
    pub verdict: Verdict,
    pub expected: Verdict,
}

impl Observation {
    pub const fn passed(self) -> bool {
        matches!(
            (self.class, self.verdict),
            (FixtureClass::Attack, Verdict::Detected(_))
                | (FixtureClass::NegativeControl, Verdict::Accepted)
        ) && same_verdict(self.verdict, self.expected)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchmarkReport {
    pub seed: u64,
    pub observations: Vec<Observation>,
}

impl BenchmarkReport {
    pub fn all_passed(&self) -> bool {
        self.observations.iter().all(|item| item.passed())
    }

    pub fn attack_detection_count(&self) -> usize {
        self.observations
            .iter()
            .filter(|item| {
                item.class == FixtureClass::Attack && matches!(item.verdict, Verdict::Detected(_))
            })
            .count()
    }

    pub fn negative_control_acceptance_count(&self) -> usize {
        self.observations
            .iter()
            .filter(|item| {
                item.class == FixtureClass::NegativeControl && item.verdict == Verdict::Accepted
            })
            .count()
    }

    pub fn to_csv(&self) -> String {
        let mut output = String::from("seed,fixture_id,kind,class,verdict,reason,passed\n");
        for item in &self.observations {
            writeln!(
                output,
                "{},{},{},{},{},{},{}",
                self.seed,
                item.fixture_id,
                item.kind.as_str(),
                item.class.as_str(),
                item.verdict.as_str(),
                item.verdict.reason(),
                item.passed()
            )
            .expect("writing to String cannot fail");
        }
        output
    }
}

pub fn run_benchmark(seed: u64) -> BenchmarkReport {
    let observations = fixtures(seed)
        .into_iter()
        .map(|fixture| Observation {
            fixture_id: fixture.fixture_id,
            kind: fixture.kind,
            class: fixture.class,
            verdict: evaluate(fixture),
            expected: fixture.expected_verdict(),
        })
        .collect();
    BenchmarkReport { seed, observations }
}

pub fn fixtures(seed: u64) -> Vec<Fixture> {
    let mut rng = SplitMix64::new(seed);
    let mut result = Vec::with_capacity(AttackKind::ALL.len() * 2);
    for kind in AttackKind::ALL {
        let fixture_id = rng.next();
        let nonce = rng.next() | 1;
        result.push(build_fixture(fixture_id, nonce, kind, FixtureClass::Attack));
        result.push(build_fixture(
            fixture_id ^ 1,
            nonce,
            kind,
            FixtureClass::NegativeControl,
        ));
    }
    result
}

pub const fn evaluate(fixture: Fixture) -> Verdict {
    if fixture.observed_digest != fixture.approved_digest {
        return Verdict::Detected(DetectionReason::ConfigDigestMismatch);
    }
    if fixture.observed_epoch < fixture.current_epoch {
        return Verdict::Detected(DetectionReason::EpochRollback);
    }
    if fixture.observed_delay != fixture.reference_delay {
        return Verdict::Detected(DetectionReason::TimingRelationViolation);
    }
    if fixture.injected_faults > fixture.fault_budget {
        return Verdict::Detected(DetectionReason::FaultBudgetExceeded);
    }
    if fixture.service_a_tag == fixture.service_b_tag {
        return Verdict::Detected(DetectionReason::CrossServiceLinkage);
    }
    if fixture.observed_slot != fixture.expected_slot {
        return Verdict::Detected(DetectionReason::SlotDiscontinuity);
    }
    Verdict::Accepted
}

const fn reason_for(kind: AttackKind) -> DetectionReason {
    match kind {
        AttackKind::ConfigSubstitution => DetectionReason::ConfigDigestMismatch,
        AttackKind::EpochRollback => DetectionReason::EpochRollback,
        AttackKind::TimingProbe => DetectionReason::TimingRelationViolation,
        AttackKind::FaultAmplification => DetectionReason::FaultBudgetExceeded,
        AttackKind::ColludingObserver => DetectionReason::CrossServiceLinkage,
        AttackKind::ReplaySplice => DetectionReason::SlotDiscontinuity,
    }
}

const fn same_verdict(left: Verdict, right: Verdict) -> bool {
    match (left, right) {
        (Verdict::Accepted, Verdict::Accepted) => true,
        (Verdict::Detected(left_reason), Verdict::Detected(right_reason)) => {
            left_reason as u8 == right_reason as u8
        }
        _ => false,
    }
}

fn build_fixture(fixture_id: u64, nonce: u64, kind: AttackKind, class: FixtureClass) -> Fixture {
    let approved_digest = mix(nonce, 0xC011_F1C0);
    let current_epoch = 11;
    let expected_slot = 64;
    let reference_delay = 4;
    let fault_budget = 2;
    let service_a_tag = mix(nonce, 0xA);
    let service_b_tag = mix(nonce, 0xB);
    let mut fixture = Fixture {
        fixture_id,
        kind,
        class,
        approved_digest,
        observed_digest: approved_digest,
        current_epoch,
        observed_epoch: current_epoch,
        expected_slot,
        observed_slot: expected_slot,
        reference_delay,
        observed_delay: reference_delay,
        fault_budget,
        injected_faults: fault_budget,
        service_a_tag,
        service_b_tag,
    };
    if class == FixtureClass::Attack {
        match kind {
            AttackKind::ConfigSubstitution => fixture.observed_digest ^= 1,
            AttackKind::EpochRollback => fixture.observed_epoch -= 1,
            AttackKind::TimingProbe => fixture.observed_delay += 1,
            AttackKind::FaultAmplification => fixture.injected_faults += 1,
            AttackKind::ColludingObserver => fixture.service_b_tag = service_a_tag,
            AttackKind::ReplaySplice => fixture.observed_slot -= 1,
        }
    }
    fixture
}

const fn mix(value: u64, domain: u64) -> u64 {
    value.rotate_left(17) ^ domain.wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        value ^ (value >> 31)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_attack_is_detected_for_its_registered_reason() {
        let report = run_benchmark(DEFAULT_SEED);
        assert_eq!(report.attack_detection_count(), AttackKind::ALL.len());
        for observation in report
            .observations
            .iter()
            .filter(|item| item.class == FixtureClass::Attack)
        {
            assert_eq!(
                observation.verdict,
                Verdict::Detected(reason_for(observation.kind))
            );
        }
    }

    #[test]
    fn every_negative_control_is_accepted() {
        let report = run_benchmark(DEFAULT_SEED);
        assert_eq!(
            report.negative_control_acceptance_count(),
            AttackKind::ALL.len()
        );
        assert!(report.all_passed());
    }

    #[test]
    fn seed_reproduces_fixture_order_ids_and_verdicts() {
        assert_eq!(run_benchmark(DEFAULT_SEED), run_benchmark(DEFAULT_SEED));
        assert_ne!(run_benchmark(DEFAULT_SEED), run_benchmark(DEFAULT_SEED + 1));
    }

    #[test]
    fn fixture_ids_are_unique_and_pairs_are_complete() {
        let fixtures = fixtures(DEFAULT_SEED);
        assert_eq!(fixtures.len(), 12);
        for (index, left) in fixtures.iter().enumerate() {
            assert!(!fixtures[..index]
                .iter()
                .any(|right| right.fixture_id == left.fixture_id));
        }
        for kind in AttackKind::ALL {
            assert!(fixtures
                .iter()
                .any(|item| item.kind == kind && item.class == FixtureClass::Attack));
            assert!(fixtures
                .iter()
                .any(|item| item.kind == kind && item.class == FixtureClass::NegativeControl));
        }
    }

    #[test]
    fn csv_contains_only_public_benchmark_observations() {
        let csv = run_benchmark(DEFAULT_SEED).to_csv();
        assert_eq!(csv.lines().count(), 13);
        assert!(csv.contains("config_substitution,attack,detected"));
        assert!(csv.contains("replay_splice,negative_control,accepted"));
        assert!(!csv.contains("approved_digest"));
        assert!(!csv.contains("service_a_tag"));
    }
}
