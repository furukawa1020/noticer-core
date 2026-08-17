use std::cell::RefCell;
use std::collections::BTreeSet;

use quotient_forge_caqt::{Digest, RelationPair};
use quotient_seal_context::{
    EventKind, ProductCheckReport, ProductInconclusive, ProductVerdict, RelationBinding,
    TargetEvent,
};
use quotient_seal_relation::{RelationResourceBound, RelationValidationReport, RelationVerdict};
use quotient_seal_resource::{
    check_resource_strict, check_resource_with_normalization, project_resource_trace,
    NormalizationKind, QuotientPadCandidate, QuotientPadRevalidator, ResourceAxis, ResourceCase,
    ResourceDivergence, ResourceInconclusive, ResourceLimits, ResourceVerdict,
    RevalidationEvidence,
};

struct CapturingRevalidator {
    evidence: RevalidationEvidence,
    candidate: RefCell<Option<QuotientPadCandidate>>,
}

impl CapturingRevalidator {
    fn new(evidence: RevalidationEvidence) -> Self {
        Self {
            evidence,
            candidate: RefCell::new(None),
        }
    }
}

impl QuotientPadRevalidator for CapturingRevalidator {
    fn revalidate(&self, candidate: &QuotientPadCandidate) -> RevalidationEvidence {
        self.candidate.replace(Some(candidate.clone()));
        self.evidence.clone()
    }
}

#[test]
fn projects_exactly_the_six_resource_axes() {
    let mut trace = vec![public_action(7)];
    for (index, axis) in axes().into_iter().enumerate() {
        trace.push(resource_event(
            axis,
            u64::try_from(index).unwrap_or(u64::MAX),
        ));
    }

    let projected = project_resource_trace(&trace);

    assert_eq!(projected.len(), 6);
    assert_eq!(
        projected
            .events()
            .iter()
            .map(|event| event.axis)
            .collect::<Vec<_>>(),
        axes()
    );
}

#[test]
fn exact_resource_profile_is_strict() {
    let relation = valid_relation(1);
    let context = accepted_context(binding(&relation));
    let case = resource_case(
        vec![resource_event(ResourceAxis::Opcode, 4)],
        vec![resource_event(ResourceAxis::Opcode, 4)],
    );

    let verdict = check_resource_strict(&relation, &context, &[case], ResourceLimits::default());

    assert!(matches!(verdict, ResourceVerdict::Strict(_)));
}

#[test]
fn api_equal_resource_difference_is_counterexample() {
    let relation = valid_relation(2);
    let context = accepted_context(binding(&relation));
    let case = divergent_case();

    let first = check_resource_strict(
        &relation,
        &context,
        std::slice::from_ref(&case),
        ResourceLimits::default(),
    );
    let second = check_resource_strict(&relation, &context, &[case], ResourceLimits::default());

    let ResourceVerdict::Counterexample(first) = first else {
        panic!("resource-only difference must be rejected");
    };
    let ResourceVerdict::Counterexample(second) = second else {
        panic!("resource-only difference must be reproducible");
    };
    assert_eq!(first.divergence, ResourceDivergence::ResourceOnly);
    assert_eq!(first.digest(), second.digest());
}

#[test]
fn bounded_candidate_can_be_normalized_after_all_post_gates() {
    let relation = valid_relation(3);
    let context = accepted_context(binding(&relation));
    let original = resource_case(
        axes()
            .into_iter()
            .map(|axis| resource_event(axis, 1))
            .collect(),
        axes()
            .into_iter()
            .map(|axis| resource_event(axis, 2))
            .collect(),
    );
    let normalized = resource_case(
        axes()
            .into_iter()
            .map(|axis| resource_event(axis, 2))
            .collect(),
        axes()
            .into_iter()
            .map(|axis| resource_event(axis, 2))
            .collect(),
    );
    let revalidator = CapturingRevalidator::new(valid_evidence(vec![normalized]));

    let verdict = check_resource_with_normalization(
        &relation,
        &context,
        &[original],
        ResourceLimits::default(),
        &revalidator,
    );

    let ResourceVerdict::Normalized(report) = verdict else {
        panic!("bounded candidate with successful post gates must normalize");
    };
    assert_eq!(report.overhead.operation_count, 6);
    assert!(report.candidate_digest.is_some());
    let candidate = revalidator.candidate.borrow();
    let candidate = candidate.as_ref().expect("candidate must be captured");
    let kinds = candidate
        .operations
        .iter()
        .map(|operation| operation.kind)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        kinds,
        BTreeSet::from([
            NormalizationKind::PublicNoOp,
            NormalizationKind::BoundedLoop,
            NormalizationKind::BranchFuel,
            NormalizationKind::FixedScratch,
            NormalizationKind::FailureReturnPath,
        ])
    );
}

#[test]
fn post_relation_resource_bound_is_never_normalized() {
    let relation = valid_relation(4);
    let context = accepted_context(binding(&relation));
    let mut evidence = valid_evidence(vec![equalized_case()]);
    evidence.relation = RelationVerdict::ResourceBound(RelationResourceBound::SourceCases {
        actual: 2,
        limit: 1,
    });
    let revalidator = CapturingRevalidator::new(evidence);

    let verdict = check_resource_with_normalization(
        &relation,
        &context,
        &[divergent_case()],
        ResourceLimits::default(),
        &revalidator,
    );

    assert_eq!(
        verdict,
        ResourceVerdict::Inconclusive(ResourceInconclusive::RevalidationRelation)
    );
}

#[test]
fn post_context_inconclusive_is_never_normalized() {
    let relation = valid_relation(5);
    let context = accepted_context(binding(&relation));
    let mut evidence = valid_evidence(vec![equalized_case()]);
    evidence.context = ProductVerdict::Inconclusive(ProductInconclusive::InvalidLimits);
    let revalidator = CapturingRevalidator::new(evidence);

    let verdict = check_resource_with_normalization(
        &relation,
        &context,
        &[divergent_case()],
        ResourceLimits::default(),
        &revalidator,
    );

    assert_eq!(
        verdict,
        ResourceVerdict::Inconclusive(ResourceInconclusive::RevalidationContext)
    );
}

#[test]
fn normalization_cannot_change_public_projection() {
    let relation = valid_relation(6);
    let context = accepted_context(binding(&relation));
    let mut normalized = equalized_case();
    normalized.left_trace[0].value = 99;
    normalized.right_trace[0].value = 99;
    let revalidator = CapturingRevalidator::new(valid_evidence(vec![normalized]));

    let verdict = check_resource_with_normalization(
        &relation,
        &context,
        &[divergent_case()],
        ResourceLimits::default(),
        &revalidator,
    );

    assert!(matches!(
        verdict,
        ResourceVerdict::Counterexample(counterexample)
            if counterexample.divergence == ResourceDivergence::NormalizationChangedPublic
    ));
}

#[test]
fn normalization_cannot_change_utility_or_deadline() {
    let relation = valid_relation(7);
    let context = accepted_context(binding(&relation));
    let mut utility_evidence = valid_evidence(vec![equalized_case()]);
    utility_evidence.utility_preserved = false;
    let utility_revalidator = CapturingRevalidator::new(utility_evidence);
    let mut deadline_evidence = valid_evidence(vec![equalized_case()]);
    deadline_evidence.deadlines_preserved = false;
    let deadline_revalidator = CapturingRevalidator::new(deadline_evidence);

    let utility = check_resource_with_normalization(
        &relation,
        &context,
        &[divergent_case()],
        ResourceLimits::default(),
        &utility_revalidator,
    );
    let deadline = check_resource_with_normalization(
        &relation,
        &context,
        &[divergent_case()],
        ResourceLimits::default(),
        &deadline_revalidator,
    );

    assert!(matches!(
        utility,
        ResourceVerdict::Counterexample(counterexample)
            if counterexample.divergence == ResourceDivergence::NormalizationChangedUtility
    ));
    assert!(matches!(
        deadline,
        ResourceVerdict::Counterexample(counterexample)
            if counterexample.divergence == ResourceDivergence::NormalizationChangedDeadline
    ));
}

#[test]
fn unequal_post_resource_trace_is_counterexample() {
    let relation = valid_relation(8);
    let context = accepted_context(binding(&relation));
    let revalidator = CapturingRevalidator::new(valid_evidence(vec![divergent_case()]));

    let verdict = check_resource_with_normalization(
        &relation,
        &context,
        &[divergent_case()],
        ResourceLimits::default(),
        &revalidator,
    );

    assert!(matches!(
        verdict,
        ResourceVerdict::Counterexample(counterexample)
            if counterexample.divergence == ResourceDivergence::NormalizationFailed
    ));
}

#[test]
fn candidate_limit_is_inconclusive_not_success() {
    let relation = valid_relation(9);
    let context = accepted_context(binding(&relation));
    let revalidator = CapturingRevalidator::new(valid_evidence(vec![equalized_case()]));
    let limits = ResourceLimits {
        max_added_fuel: 1,
        ..ResourceLimits::default()
    };

    let verdict = check_resource_with_normalization(
        &relation,
        &context,
        &[divergent_case()],
        limits,
        &revalidator,
    );

    assert_eq!(
        verdict,
        ResourceVerdict::Inconclusive(ResourceInconclusive::CandidateBound)
    );
    assert!(revalidator.candidate.borrow().is_none());
}

#[test]
fn quotient_pad_candidate_is_reproducible() {
    let relation = valid_relation(10);
    let context = accepted_context(binding(&relation));
    let first = CapturingRevalidator::new(valid_evidence(vec![equalized_case()]));
    let second = CapturingRevalidator::new(valid_evidence(vec![equalized_case()]));

    let first_verdict = check_resource_with_normalization(
        &relation,
        &context,
        &[divergent_case()],
        ResourceLimits::default(),
        &first,
    );
    let second_verdict = check_resource_with_normalization(
        &relation,
        &context,
        &[divergent_case()],
        ResourceLimits::default(),
        &second,
    );

    assert_eq!(first_verdict, second_verdict);
    assert_eq!(
        first
            .candidate
            .borrow()
            .as_ref()
            .map(QuotientPadCandidate::digest),
        second
            .candidate
            .borrow()
            .as_ref()
            .map(QuotientPadCandidate::digest)
    );
}

#[test]
fn noncanonical_private_pairs_are_inconclusive() {
    let relation = valid_relation(11);
    let context = accepted_context(binding(&relation));
    let mut case = divergent_case();
    case.pair = RelationPair { left: 2, right: 1 };

    let verdict = check_resource_strict(&relation, &context, &[case], ResourceLimits::default());

    assert_eq!(
        verdict,
        ResourceVerdict::Inconclusive(ResourceInconclusive::NonCanonicalCases)
    );
}

#[test]
fn contract_freezes_strict_default_and_hardware_nonclaim() {
    let config = include_str!("../../../configs/quotient_seal/resource_trace_v1.yaml");
    let schema = include_str!("../../../schemas/quotient_seal_resource_v1.schema.json");
    let document = include_str!("../../../docs/quotient_seal_resource.md");

    assert!(config.contains("default_mode: strict"));
    assert!(config.contains("hardware_status: NOT_VERIFIED"));
    assert!(schema.contains("QUOTIENT_SEAL_RESOURCE_V1"));
    assert!(schema.contains("NOT_VERIFIED"));
    assert!(document.contains("candidate new primitive"));
    assert!(document.contains("NOT_VERIFIED"));
    assert!(!document.contains("世界初"));
}

fn valid_relation(seed: u8) -> RelationVerdict {
    RelationVerdict::Valid(Box::new(RelationValidationReport {
        relation_digest: digest(seed),
        inductive_digest: digest(seed.wrapping_add(1)),
        target_ir_digest: digest(seed.wrapping_add(2)),
        reachable_states: 2,
        checked_source_steps: 2,
        checked_lifecycle_calls: 1,
        checked_two_run_cases: 1,
        checked_observer_events: 2,
    }))
}

fn binding(verdict: &RelationVerdict) -> RelationBinding {
    let RelationVerdict::Valid(report) = verdict else {
        panic!("test fixture must be valid");
    };
    RelationBinding::from_report(report)
}

fn accepted_context(binding: RelationBinding) -> ProductVerdict {
    ProductVerdict::Accept(Box::new(ProductCheckReport {
        binding,
        observer_profiles: 7,
        context_families: 12,
        private_pairs: 1,
        visited_product_states: 4,
        checked_edges: 8,
        maximum_shortest_prefix: 2,
        declared_product_bound: 64,
        induction_closed: true,
    }))
}

fn valid_evidence(normalized_cases: Vec<ResourceCase>) -> RevalidationEvidence {
    let relation = valid_relation(200);
    let context = accepted_context(binding(&relation));
    RevalidationEvidence {
        relation,
        context,
        normalized_cases,
        utility_preserved: true,
        deadlines_preserved: true,
    }
}

fn divergent_case() -> ResourceCase {
    resource_case(
        vec![resource_event(ResourceAxis::Opcode, 1)],
        vec![resource_event(ResourceAxis::Opcode, 3)],
    )
}

fn equalized_case() -> ResourceCase {
    resource_case(
        vec![resource_event(ResourceAxis::Opcode, 3)],
        vec![resource_event(ResourceAxis::Opcode, 3)],
    )
}

fn resource_case(left: Vec<TargetEvent>, right: Vec<TargetEvent>) -> ResourceCase {
    let mut left_trace = vec![public_action(7)];
    left_trace.extend(left);
    let mut right_trace = vec![public_action(7)];
    right_trace.extend(right);
    ResourceCase {
        pair: RelationPair { left: 1, right: 2 },
        left_trace,
        right_trace,
    }
}

fn public_action(value: u64) -> TargetEvent {
    TargetEvent {
        kind: EventKind::Action,
        label: 10,
        slot: 0,
        value,
    }
}

fn resource_event(axis: ResourceAxis, value: u64) -> TargetEvent {
    let kind = match axis {
        ResourceAxis::Opcode => EventKind::Instruction,
        ResourceAxis::Branch => EventKind::Control,
        ResourceAxis::MemoryAddress => EventKind::MemoryAccess,
        ResourceAxis::Import => EventKind::HostCall,
        ResourceAxis::Fuel => EventKind::Resource,
        ResourceAxis::MemoryPages => EventKind::MemoryGrow,
    };
    TargetEvent {
        kind,
        label: u32::from(axis as u8) + 1,
        slot: u64::from(axis as u8),
        value,
    }
}

const fn axes() -> [ResourceAxis; 6] {
    [
        ResourceAxis::Opcode,
        ResourceAxis::Branch,
        ResourceAxis::MemoryAddress,
        ResourceAxis::Import,
        ResourceAxis::Fuel,
        ResourceAxis::MemoryPages,
    ]
}

const fn digest(seed: u8) -> Digest {
    Digest::new([seed; 32])
}
