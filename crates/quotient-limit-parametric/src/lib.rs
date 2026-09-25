#![no_std]
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Parameter {
    ReadySpan,
    Deadline,
    ObserverResolution,
    CoverBudget,
    FaultCount,
    Services,
}

pub const SYMBOLIC_PARAMETERS: [Parameter; 6] = [
    Parameter::ReadySpan,
    Parameter::Deadline,
    Parameter::ObserverResolution,
    Parameter::CoverBudget,
    Parameter::FaultCount,
    Parameter::Services,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParameterPoint {
    pub ready_span: u64,
    pub deadline: u64,
    pub observer_resolution: u64,
    pub cover_budget: u64,
    pub fault_count: u64,
    pub services: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadinessGuard {
    DeadlineBeforeReadySpan,
    DeadlineAtOrAfterReadySpan,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SymbolicBound {
    Infeasible,
    ReadySpan,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PiecewiseRegion {
    pub guard: ReadinessGuard,
    pub minimum_worst_case_latency: SymbolicBound,
}

pub const READINESS_FRONTIER: [PiecewiseRegion; 2] = [
    PiecewiseRegion {
        guard: ReadinessGuard::DeadlineBeforeReadySpan,
        minimum_worst_case_latency: SymbolicBound::Infeasible,
    },
    PiecewiseRegion {
        guard: ReadinessGuard::DeadlineAtOrAfterReadySpan,
        minimum_worst_case_latency: SymbolicBound::ReadySpan,
    },
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeasibilityRegion {
    InfeasibleDeadline,
    Feasible,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParametricLowerBound {
    pub region: FeasibilityRegion,
    pub minimum_worst_case_latency: Option<u64>,
    pub critical_deadline: u64,
    pub active_parameters: [Parameter; 2],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParametricError {
    ZeroObserverResolution,
    ZeroServices,
}

pub fn evaluate_readiness_frontier(
    point: ParameterPoint,
) -> Result<ParametricLowerBound, ParametricError> {
    if point.observer_resolution == 0 {
        return Err(ParametricError::ZeroObserverResolution);
    }
    if point.services == 0 {
        return Err(ParametricError::ZeroServices);
    }
    let active_parameters = [Parameter::ReadySpan, Parameter::Deadline];
    if point.deadline < point.ready_span {
        return Ok(ParametricLowerBound {
            region: FeasibilityRegion::InfeasibleDeadline,
            minimum_worst_case_latency: None,
            critical_deadline: point.ready_span,
            active_parameters,
        });
    }
    Ok(ParametricLowerBound {
        region: FeasibilityRegion::Feasible,
        minimum_worst_case_latency: Some(point.ready_span),
        critical_deadline: point.ready_span,
        active_parameters,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point(ready_span: u64, deadline: u64) -> ParameterPoint {
        ParameterPoint {
            ready_span,
            deadline,
            observer_resolution: 1,
            cover_budget: 0,
            fault_count: 0,
            services: 1,
        }
    }

    #[test]
    fn deadline_before_ready_span_is_infeasible() {
        let result = evaluate_readiness_frontier(point(5, 4)).unwrap();
        assert_eq!(result.region, FeasibilityRegion::InfeasibleDeadline);
        assert_eq!(result.minimum_worst_case_latency, None);
        assert_eq!(result.critical_deadline, 5);
    }

    #[test]
    fn boundary_is_feasible_with_ready_span_lower_bound() {
        let result = evaluate_readiness_frontier(point(5, 5)).unwrap();
        assert_eq!(result.region, FeasibilityRegion::Feasible);
        assert_eq!(result.minimum_worst_case_latency, Some(5));
        assert_eq!(
            result.active_parameters,
            [Parameter::ReadySpan, Parameter::Deadline]
        );
    }

    #[test]
    fn rejects_undefined_public_dimensions() {
        let mut invalid_resolution = point(1, 1);
        invalid_resolution.observer_resolution = 0;
        assert_eq!(
            evaluate_readiness_frontier(invalid_resolution),
            Err(ParametricError::ZeroObserverResolution)
        );
        let mut invalid_services = point(1, 1);
        invalid_services.services = 0;
        assert_eq!(
            evaluate_readiness_frontier(invalid_services),
            Err(ParametricError::ZeroServices)
        );
    }

    #[test]
    fn exposes_all_frozen_symbolic_dimensions() {
        assert_eq!(SYMBOLIC_PARAMETERS.len(), 6);
        assert_eq!(READINESS_FRONTIER.len(), 2);
    }
}
