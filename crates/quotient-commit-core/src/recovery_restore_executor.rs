use crate::recovery_restore_plan::RestorePlan;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestoreState {
    Ready,
    Running,
    Complete,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionError {
    EmptyPlan,
    UnexpectedComponent,
    AlreadyComplete,
    PermanentlyFailed,
}

pub struct RestoreExecutor {
    ordered: Vec<u16>,
    next: usize,
    state: RestoreState,
}

impl RestoreExecutor {
    pub fn new(plan: &RestorePlan) -> Result<Self, ExecutionError> {
        if plan.ordered_components.is_empty() {
            return Err(ExecutionError::EmptyPlan);
        }
        Ok(Self {
            ordered: plan.ordered_components.clone(),
            next: 0,
            state: RestoreState::Ready,
        })
    }

    pub fn state(&self) -> RestoreState {
        self.state
    }
    pub fn expected_component(&self) -> Option<u16> {
        self.ordered.get(self.next).copied()
    }

    pub fn record(
        &mut self,
        component: u16,
        succeeded: bool,
    ) -> Result<RestoreState, ExecutionError> {
        match self.state {
            RestoreState::Failed => return Err(ExecutionError::PermanentlyFailed),
            RestoreState::Complete => return Err(ExecutionError::AlreadyComplete),
            RestoreState::Ready | RestoreState::Running => {}
        }
        if self.expected_component() != Some(component) {
            return Err(ExecutionError::UnexpectedComponent);
        }
        if !succeeded {
            self.state = RestoreState::Failed;
            return Ok(self.state);
        }
        self.next += 1;
        self.state = if self.next == self.ordered.len() {
            RestoreState::Complete
        } else {
            RestoreState::Running
        };
        Ok(self.state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn plan() -> RestorePlan {
        RestorePlan {
            ordered_components: vec![1, 2],
            digest: [8; 32],
        }
    }
    #[test]
    fn executes_only_the_compiled_order() {
        let mut executor = RestoreExecutor::new(&plan()).unwrap();
        assert_eq!(
            executor.record(2, true),
            Err(ExecutionError::UnexpectedComponent)
        );
        assert_eq!(executor.record(1, true), Ok(RestoreState::Running));
        assert_eq!(executor.record(2, true), Ok(RestoreState::Complete));
    }
    #[test]
    fn failure_is_irreversible() {
        let mut executor = RestoreExecutor::new(&plan()).unwrap();
        assert_eq!(executor.record(1, false), Ok(RestoreState::Failed));
        assert_eq!(
            executor.record(1, true),
            Err(ExecutionError::PermanentlyFailed)
        );
    }
}
