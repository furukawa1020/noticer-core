use quotient_forge_caqt::{Digest, RelationPair};
use quotient_seal_context::{project_trace, ObserverProfile, ProductVerdict, RelationBinding};
use quotient_seal_relation::RelationVerdict;

use crate::model::{
    project_resource_trace, NormalizationKind, NormalizationOverhead, PadSide,
    QuotientPadCandidate, QuotientPadOperation, QuotientPadRevalidator, ResourceAxis, ResourceCase,
    ResourceCounterexample, ResourceDivergence, ResourceEvent, ResourceInconclusive,
    ResourceLimits, ResourceReport, ResourceTrace, ResourceVerdict, QUOTIENT_PAD_FORMAT_VERSION,
};

#[must_use]
pub fn check_resource_strict(
    relation: &RelationVerdict,
    context: &ProductVerdict,
    cases: &[ResourceCase],
    limits: ResourceLimits,
) -> ResourceVerdict {
    let binding = match preflight(relation, context, cases, limits) {
        Ok(binding) => binding,
        Err(verdict) => return verdict,
    };

    let mut checked_resource_events = 0_usize;
    for case in cases {
        let left_public = project_trace(&case.left_trace, ObserverProfile::O0Api);
        let right_public = project_trace(&case.right_trace, ObserverProfile::O0Api);
        if left_public != right_public {
            return counterexample(ResourceDivergence::PublicSurface, case, 0, None);
        }

        let left = project_resource_trace(&case.left_trace);
        let right = project_resource_trace(&case.right_trace);
        checked_resource_events = match checked_resource_events
            .checked_add(left.len())
            .and_then(|count| count.checked_add(right.len()))
        {
            Some(count) => count,
            None => return ResourceVerdict::Inconclusive(ResourceInconclusive::ArithmeticOverflow),
        };
        if left != right {
            return counterexample(
                ResourceDivergence::ResourceOnly,
                case,
                first_difference(&left, &right),
                None,
            );
        }
    }

    ResourceVerdict::Strict(Box::new(ResourceReport {
        pre_binding: binding,
        post_binding: binding,
        checked_cases: cases.len(),
        checked_resource_events,
        candidate_digest: None,
        overhead: NormalizationOverhead::default(),
    }))
}

#[must_use]
pub fn check_resource_with_normalization<R: QuotientPadRevalidator + ?Sized>(
    relation: &RelationVerdict,
    context: &ProductVerdict,
    cases: &[ResourceCase],
    limits: ResourceLimits,
    revalidator: &R,
) -> ResourceVerdict {
    let pre_binding = match preflight(relation, context, cases, limits) {
        Ok(binding) => binding,
        Err(verdict) => return verdict,
    };

    let mut checked_resource_events = 0_usize;
    let mut operations = Vec::new();
    for case in cases {
        let left_public = project_trace(&case.left_trace, ObserverProfile::O0Api);
        let right_public = project_trace(&case.right_trace, ObserverProfile::O0Api);
        if left_public != right_public {
            return counterexample(ResourceDivergence::PublicSurface, case, 0, None);
        }

        let left = project_resource_trace(&case.left_trace);
        let right = project_resource_trace(&case.right_trace);
        checked_resource_events = match checked_resource_events
            .checked_add(left.len())
            .and_then(|count| count.checked_add(right.len()))
        {
            Some(count) => count,
            None => return ResourceVerdict::Inconclusive(ResourceInconclusive::ArithmeticOverflow),
        };
        if let Err(reason) = append_operations(case.pair, &left, &right, &mut operations, limits) {
            return ResourceVerdict::Inconclusive(reason);
        }
    }

    if operations.is_empty() {
        return ResourceVerdict::Strict(Box::new(ResourceReport {
            pre_binding,
            post_binding: pre_binding,
            checked_cases: cases.len(),
            checked_resource_events,
            candidate_digest: None,
            overhead: NormalizationOverhead::default(),
        }));
    }

    let overhead = match calculate_overhead(&operations) {
        Some(overhead) => overhead,
        None => return ResourceVerdict::Inconclusive(ResourceInconclusive::ArithmeticOverflow),
    };
    if !within_limits(overhead, limits) {
        return ResourceVerdict::Inconclusive(ResourceInconclusive::CandidateBound);
    }

    let candidate = QuotientPadCandidate {
        version: QUOTIENT_PAD_FORMAT_VERSION,
        operations,
        overhead,
    };
    let candidate_digest = candidate.digest();
    let evidence = revalidator.revalidate(&candidate);
    let post_binding = match &evidence.relation {
        RelationVerdict::Valid(report) => RelationBinding::from_report(report),
        RelationVerdict::Invalid(_) => {
            return counterexample(
                ResourceDivergence::PostRelation,
                &cases[0],
                0,
                Some(candidate_digest),
            );
        }
        RelationVerdict::Incompatible(_)
        | RelationVerdict::ResourceBound(_)
        | RelationVerdict::Unresolved(_) => {
            return ResourceVerdict::Inconclusive(ResourceInconclusive::RevalidationRelation);
        }
    };
    match &evidence.context {
        ProductVerdict::Accept(report) if report.binding == post_binding => {}
        ProductVerdict::Accept(_) => {
            return ResourceVerdict::Inconclusive(ResourceInconclusive::RevalidationContext);
        }
        ProductVerdict::Counterexample(_) => {
            return counterexample(
                ResourceDivergence::PostContext,
                &cases[0],
                0,
                Some(candidate_digest),
            );
        }
        ProductVerdict::Inconclusive(_) => {
            return ResourceVerdict::Inconclusive(ResourceInconclusive::RevalidationContext);
        }
    }
    if !evidence.utility_preserved {
        return counterexample(
            ResourceDivergence::NormalizationChangedUtility,
            &cases[0],
            0,
            Some(candidate_digest),
        );
    }
    if !evidence.deadlines_preserved {
        return counterexample(
            ResourceDivergence::NormalizationChangedDeadline,
            &cases[0],
            0,
            Some(candidate_digest),
        );
    }
    if evidence.normalized_cases.len() != cases.len() {
        return ResourceVerdict::Inconclusive(ResourceInconclusive::RevalidationCaseMismatch);
    }

    let mut post_events = 0_usize;
    for (original, normalized) in cases.iter().zip(&evidence.normalized_cases) {
        if normalized.pair != original.pair {
            return ResourceVerdict::Inconclusive(ResourceInconclusive::RevalidationCaseMismatch);
        }
        if normalized.left_trace.len() > limits.max_events_per_trace
            || normalized.right_trace.len() > limits.max_events_per_trace
        {
            return ResourceVerdict::Inconclusive(ResourceInconclusive::TraceBound {
                actual: normalized
                    .left_trace
                    .len()
                    .max(normalized.right_trace.len()),
                limit: limits.max_events_per_trace,
            });
        }

        let original_public = project_trace(&original.left_trace, ObserverProfile::O0Api);
        let left_public = project_trace(&normalized.left_trace, ObserverProfile::O0Api);
        let right_public = project_trace(&normalized.right_trace, ObserverProfile::O0Api);
        if left_public != right_public || left_public != original_public {
            return counterexample(
                ResourceDivergence::NormalizationChangedPublic,
                normalized,
                0,
                Some(candidate_digest),
            );
        }

        let left = project_resource_trace(&normalized.left_trace);
        let right = project_resource_trace(&normalized.right_trace);
        post_events = match post_events
            .checked_add(left.len())
            .and_then(|count| count.checked_add(right.len()))
        {
            Some(count) => count,
            None => return ResourceVerdict::Inconclusive(ResourceInconclusive::ArithmeticOverflow),
        };
        if left != right {
            return counterexample(
                ResourceDivergence::NormalizationFailed,
                normalized,
                first_difference(&left, &right),
                Some(candidate_digest),
            );
        }
    }

    checked_resource_events = match checked_resource_events.checked_add(post_events) {
        Some(count) => count,
        None => return ResourceVerdict::Inconclusive(ResourceInconclusive::ArithmeticOverflow),
    };
    ResourceVerdict::Normalized(Box::new(ResourceReport {
        pre_binding,
        post_binding,
        checked_cases: cases.len(),
        checked_resource_events,
        candidate_digest: Some(candidate_digest),
        overhead,
    }))
}

fn preflight(
    relation: &RelationVerdict,
    context: &ProductVerdict,
    cases: &[ResourceCase],
    limits: ResourceLimits,
) -> Result<RelationBinding, ResourceVerdict> {
    if !limits.is_valid() {
        return Err(ResourceVerdict::Inconclusive(
            ResourceInconclusive::InvalidLimits,
        ));
    }
    if cases.is_empty() {
        return Err(ResourceVerdict::Inconclusive(
            ResourceInconclusive::EmptyCases,
        ));
    }
    if cases.len() > limits.max_cases {
        return Err(ResourceVerdict::Inconclusive(
            ResourceInconclusive::CaseBound {
                actual: cases.len(),
                limit: limits.max_cases,
            },
        ));
    }
    if !canonical_cases(cases) {
        return Err(ResourceVerdict::Inconclusive(
            ResourceInconclusive::NonCanonicalCases,
        ));
    }
    for case in cases {
        if case.left_trace.len() > limits.max_events_per_trace
            || case.right_trace.len() > limits.max_events_per_trace
        {
            return Err(ResourceVerdict::Inconclusive(
                ResourceInconclusive::TraceBound {
                    actual: case.left_trace.len().max(case.right_trace.len()),
                    limit: limits.max_events_per_trace,
                },
            ));
        }
    }

    let binding = match relation {
        RelationVerdict::Valid(report) => RelationBinding::from_report(report),
        RelationVerdict::Invalid(_) => {
            return Err(counterexample(
                ResourceDivergence::UpstreamRelation,
                &cases[0],
                0,
                None,
            ));
        }
        RelationVerdict::Incompatible(_)
        | RelationVerdict::ResourceBound(_)
        | RelationVerdict::Unresolved(_) => {
            return Err(ResourceVerdict::Inconclusive(
                ResourceInconclusive::UpstreamRelation,
            ));
        }
    };
    match context {
        ProductVerdict::Accept(report) if report.binding == binding => Ok(binding),
        ProductVerdict::Accept(_) | ProductVerdict::Inconclusive(_) => Err(
            ResourceVerdict::Inconclusive(ResourceInconclusive::UpstreamContext),
        ),
        ProductVerdict::Counterexample(_) => Err(counterexample(
            ResourceDivergence::UpstreamContext,
            &cases[0],
            0,
            None,
        )),
    }
}

fn canonical_cases(cases: &[ResourceCase]) -> bool {
    let mut previous: Option<RelationPair> = None;
    for case in cases {
        if case.pair.left >= case.pair.right || previous.is_some_and(|pair| pair >= case.pair) {
            return false;
        }
        previous = Some(case.pair);
    }
    true
}

fn append_operations(
    pair: RelationPair,
    left: &ResourceTrace,
    right: &ResourceTrace,
    operations: &mut Vec<QuotientPadOperation>,
    limits: ResourceLimits,
) -> Result<(), ResourceInconclusive> {
    let event_count = left.len().max(right.len());
    for index in 0..event_count {
        let left_event = left.events().get(index);
        let right_event = right.events().get(index);
        if left_event == right_event {
            continue;
        }
        if operations.len() >= limits.max_operations {
            return Err(ResourceInconclusive::CandidateBound);
        }
        let (axis, side, amount) = operation_shape(left_event, right_event);
        operations.push(QuotientPadOperation {
            pair,
            event_index: u32::try_from(index)
                .map_err(|_| ResourceInconclusive::ArithmeticOverflow)?,
            axis,
            kind: normalization_kind(axis),
            side,
            amount,
        });
    }
    Ok(())
}

fn operation_shape(
    left: Option<&ResourceEvent>,
    right: Option<&ResourceEvent>,
) -> (ResourceAxis, PadSide, u64) {
    match (left, right) {
        (Some(left), Some(right)) => {
            let axis = left.axis.min(right.axis);
            if left.axis != right.axis || left.label != right.label || left.slot != right.slot {
                (axis, PadSide::Both, 1)
            } else if left.value < right.value {
                (
                    axis,
                    PadSide::Left,
                    right.value.saturating_sub(left.value).max(1),
                )
            } else if left.value > right.value {
                (
                    axis,
                    PadSide::Right,
                    left.value.saturating_sub(right.value).max(1),
                )
            } else {
                (axis, PadSide::Both, 1)
            }
        }
        (Some(left), None) => (left.axis, PadSide::Right, left.value.max(1)),
        (None, Some(right)) => (right.axis, PadSide::Left, right.value.max(1)),
        (None, None) => (ResourceAxis::Opcode, PadSide::Both, 1),
    }
}

const fn normalization_kind(axis: ResourceAxis) -> NormalizationKind {
    match axis {
        ResourceAxis::Opcode => NormalizationKind::PublicNoOp,
        ResourceAxis::Branch => NormalizationKind::BranchFuel,
        ResourceAxis::MemoryAddress | ResourceAxis::MemoryPages => NormalizationKind::FixedScratch,
        ResourceAxis::Import => NormalizationKind::FailureReturnPath,
        ResourceAxis::Fuel => NormalizationKind::BoundedLoop,
    }
}

fn calculate_overhead(operations: &[QuotientPadOperation]) -> Option<NormalizationOverhead> {
    let mut overhead = NormalizationOverhead {
        operation_count: operations.len(),
        ..NormalizationOverhead::default()
    };
    for operation in operations {
        let amount = operation.amount.max(1);
        overhead.added_instructions = overhead.added_instructions.checked_add(amount)?;
        overhead.added_fuel = overhead.added_fuel.checked_add(amount)?;
        match operation.kind {
            NormalizationKind::BoundedLoop => {
                overhead.bounded_loop_iterations =
                    overhead.bounded_loop_iterations.checked_add(amount)?;
            }
            NormalizationKind::FixedScratch => {
                overhead.fixed_scratch_bytes = overhead.fixed_scratch_bytes.checked_add(amount)?;
            }
            NormalizationKind::PublicNoOp
            | NormalizationKind::BranchFuel
            | NormalizationKind::FailureReturnPath => {}
        }
    }
    Some(overhead)
}

const fn within_limits(overhead: NormalizationOverhead, limits: ResourceLimits) -> bool {
    overhead.operation_count <= limits.max_operations
        && overhead.added_instructions <= limits.max_added_instructions
        && overhead.added_fuel <= limits.max_added_fuel
        && overhead.bounded_loop_iterations <= limits.max_loop_iterations
        && overhead.fixed_scratch_bytes <= limits.max_scratch_bytes
}

fn first_difference(left: &ResourceTrace, right: &ResourceTrace) -> usize {
    let count = left.len().max(right.len());
    (0..count)
        .find(|index| left.events().get(*index) != right.events().get(*index))
        .unwrap_or(0)
}

fn counterexample(
    divergence: ResourceDivergence,
    case: &ResourceCase,
    event_index: usize,
    candidate_digest: Option<Digest>,
) -> ResourceVerdict {
    let left = project_resource_trace(&case.left_trace);
    let right = project_resource_trace(&case.right_trace);
    ResourceVerdict::Counterexample(Box::new(ResourceCounterexample {
        version: QUOTIENT_PAD_FORMAT_VERSION,
        divergence,
        pair: case.pair,
        event_index: u32::try_from(event_index).unwrap_or(u32::MAX),
        left_public: project_trace(&case.left_trace, ObserverProfile::O0Api),
        right_public: project_trace(&case.right_trace, ObserverProfile::O0Api),
        left_resource: left.events().get(event_index).cloned(),
        right_resource: right.events().get(event_index).cloned(),
        candidate_digest,
    }))
}
