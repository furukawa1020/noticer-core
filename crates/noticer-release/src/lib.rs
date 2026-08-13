#![forbid(unsafe_code)]

//! Low-side public token planning. No private evidence timing is representable.

use noticer_aetp::{
    required_claim, validate_obligation, ActionObligation, ActionSemantics, ClaimBound,
    ServiceBinding,
};
use noticer_claim::AdmittedAction;
use std::collections::BTreeSet;
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedAction {
    obligation: ActionObligation,
    claim_bound: ClaimBound,
}

impl PlannedAction {
    pub const fn obligation(&self) -> &ActionObligation {
        &self.obligation
    }

    pub const fn claim_bound(&self) -> ClaimBound {
        self.claim_bound
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenPlan {
    actions: Vec<PlannedAction>,
    services: Vec<ServiceBinding>,
}

impl TokenPlan {
    pub fn from_admitted(
        admitted: impl IntoIterator<Item = AdmittedAction>,
        services: Vec<ServiceBinding>,
    ) -> Result<Self, PlanError> {
        let actions = admitted
            .into_iter()
            .map(|item| {
                let (obligation, claim_bound) = item.into_public_parts();
                PlannedAction {
                    obligation,
                    claim_bound,
                }
            })
            .collect();
        Self::new(actions, services)
    }

    pub fn from_action_semantics(
        semantics: &ActionSemantics,
        services: Vec<ServiceBinding>,
    ) -> Result<Self, PlanError> {
        let actions = semantics
            .obligations
            .iter()
            .cloned()
            .map(|obligation| PlannedAction {
                claim_bound: required_claim(obligation.action),
                obligation,
            })
            .collect();
        Self::new(actions, services)
    }

    fn new(mut actions: Vec<PlannedAction>, mut services: Vec<ServiceBinding>) -> Result<Self, PlanError> {
        services.sort_unstable();
        services.dedup();
        if services.is_empty() {
            return Err(PlanError::InvalidPlan);
        }
        let service_set: BTreeSet<_> = services.iter().copied().collect();
        for action in &actions {
            validate_obligation(&action.obligation).map_err(|_| PlanError::InvalidPlan)?;
            if !service_set.contains(&action.obligation.service)
                || !action
                    .claim_bound
                    .permits(required_claim(action.obligation.action))
            {
                return Err(PlanError::InvalidPlan);
            }
        }
        actions.sort_by_key(|item| (item.obligation.public_bucket, item.obligation.service));
        for pair in actions.windows(2) {
            if pair[0].obligation.service == pair[1].obligation.service
                && pair[0].obligation.public_bucket == pair[1].obligation.public_bucket
            {
                return Err(PlanError::InvalidPlan);
            }
        }
        Ok(Self { actions, services })
    }

    pub fn actions(&self) -> &[PlannedAction] {
        &self.actions
    }

    pub fn services(&self) -> &[ServiceBinding] {
        &self.services
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PlanError {
    #[error("invalid public token plan")]
    InvalidPlan,
}
