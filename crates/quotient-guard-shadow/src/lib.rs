#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;

pub const MINIMUM_SHADOWS: usize = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivateShadowInput {
    readiness_class: u16,
    private_branch: u16,
}

impl PrivateShadowInput {
    pub const fn new(readiness_class: u16, private_branch: u16) -> Self {
        Self {
            readiness_class,
            private_branch,
        }
    }

    pub const fn readiness_class(self) -> u16 {
        self.readiness_class
    }

    pub const fn private_branch(self) -> u16 {
        self.private_branch
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicStepInput {
    pub action_quotient: u16,
    pub public_input: u16,
    pub fault_input: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicProjection {
    pub release_symbol: Option<u16>,
    pub public_state: u32,
    pub public_error: u16,
}

pub trait ShadowMachine: Clone {
    fn step(&mut self, private: PrivateShadowInput, public: PublicStepInput) -> PublicProjection;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShadowLimits {
    pub maximum_shadows: usize,
    pub maximum_steps: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DivergenceClass {
    ReleasePresence,
    ReleaseSymbol,
    PublicState,
    PublicError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShadowStepOutcome {
    Equivalent {
        slot: u64,
        projection: PublicProjection,
        compared_shadows: usize,
    },
    Diverged {
        slot: u64,
        class: DivergenceClass,
        compared_shadows: usize,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShadowError {
    TooFewShadows,
    ShadowLimit,
    InputCountMismatch,
    StepLimit,
    Terminal,
}

#[derive(Clone, Debug)]
pub struct ShadowExecutor<M: ShadowMachine> {
    machines: Vec<M>,
    limits: ShadowLimits,
    completed_steps: u64,
    terminal: bool,
}

impl<M: ShadowMachine> ShadowExecutor<M> {
    pub fn new(
        template: M,
        shadow_count: usize,
        limits: ShadowLimits,
    ) -> Result<Self, ShadowError> {
        if shadow_count < MINIMUM_SHADOWS {
            return Err(ShadowError::TooFewShadows);
        }
        if shadow_count > limits.maximum_shadows {
            return Err(ShadowError::ShadowLimit);
        }
        Ok(Self {
            machines: alloc::vec![template; shadow_count],
            limits,
            completed_steps: 0,
            terminal: false,
        })
    }

    pub fn compared_shadows(&self) -> usize {
        self.machines.len()
    }

    pub fn completed_steps(&self) -> u64 {
        self.completed_steps
    }

    pub fn is_terminal(&self) -> bool {
        self.terminal
    }

    pub fn step(
        &mut self,
        private_inputs: &[PrivateShadowInput],
        public: PublicStepInput,
    ) -> Result<ShadowStepOutcome, ShadowError> {
        if self.terminal {
            return Err(ShadowError::Terminal);
        }
        if private_inputs.len() != self.machines.len() {
            self.terminal = true;
            return Err(ShadowError::InputCountMismatch);
        }
        if self.completed_steps >= self.limits.maximum_steps {
            self.terminal = true;
            return Err(ShadowError::StepLimit);
        }
        let slot = self.completed_steps;
        self.completed_steps += 1;
        let mut reference = None;
        for (machine, private) in self.machines.iter_mut().zip(private_inputs.iter().copied()) {
            let projection = machine.step(private, public);
            if let Some(first) = reference {
                if let Some(class) = classify_divergence(first, projection) {
                    self.terminal = true;
                    return Ok(ShadowStepOutcome::Diverged {
                        slot,
                        class,
                        compared_shadows: self.machines.len(),
                    });
                }
            } else {
                reference = Some(projection);
            }
        }
        Ok(ShadowStepOutcome::Equivalent {
            slot,
            projection: reference.expect("minimum shadow count is enforced"),
            compared_shadows: self.machines.len(),
        })
    }
}

fn classify_divergence(left: PublicProjection, right: PublicProjection) -> Option<DivergenceClass> {
    if left.release_symbol.is_some() != right.release_symbol.is_some() {
        Some(DivergenceClass::ReleasePresence)
    } else if left.release_symbol != right.release_symbol {
        Some(DivergenceClass::ReleaseSymbol)
    } else if left.public_state != right.public_state {
        Some(DivergenceClass::PublicState)
    } else if left.public_error != right.public_error {
        Some(DivergenceClass::PublicError)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug)]
    struct FixtureMachine {
        leak_readiness: bool,
        state: u32,
    }

    impl ShadowMachine for FixtureMachine {
        fn step(
            &mut self,
            private: PrivateShadowInput,
            public: PublicStepInput,
        ) -> PublicProjection {
            self.state += 1;
            PublicProjection {
                release_symbol: Some(if self.leak_readiness {
                    private.readiness_class()
                } else {
                    public.action_quotient
                }),
                public_state: self.state,
                public_error: 0,
            }
        }
    }

    fn limits() -> ShadowLimits {
        ShadowLimits {
            maximum_shadows: 16,
            maximum_steps: 4,
        }
    }

    fn private_pair() -> [PrivateShadowInput; 2] {
        [PrivateShadowInput::new(3, 1), PrivateShadowInput::new(9, 2)]
    }

    #[test]
    fn action_equivalent_private_histories_produce_one_projection() {
        let mut executor = ShadowExecutor::new(
            FixtureMachine {
                leak_readiness: false,
                state: 0,
            },
            2,
            limits(),
        )
        .unwrap();
        let outcome = executor
            .step(
                &private_pair(),
                PublicStepInput {
                    action_quotient: 7,
                    public_input: 0,
                    fault_input: 0,
                },
            )
            .unwrap();
        assert_eq!(
            outcome,
            ShadowStepOutcome::Equivalent {
                slot: 0,
                projection: PublicProjection {
                    release_symbol: Some(7),
                    public_state: 1,
                    public_error: 0,
                },
                compared_shadows: 2,
            }
        );
    }

    #[test]
    fn private_readiness_leak_is_reduced_to_relation_class() {
        let mut executor = ShadowExecutor::new(
            FixtureMachine {
                leak_readiness: true,
                state: 0,
            },
            2,
            limits(),
        )
        .unwrap();
        let outcome = executor
            .step(
                &private_pair(),
                PublicStepInput {
                    action_quotient: 7,
                    public_input: 0,
                    fault_input: 0,
                },
            )
            .unwrap();
        assert_eq!(
            outcome,
            ShadowStepOutcome::Diverged {
                slot: 0,
                class: DivergenceClass::ReleaseSymbol,
                compared_shadows: 2,
            }
        );
        assert!(executor.is_terminal());
    }

    #[test]
    fn divergence_is_terminal_and_cannot_be_sampled_again() {
        let mut executor = ShadowExecutor::new(
            FixtureMachine {
                leak_readiness: true,
                state: 0,
            },
            2,
            limits(),
        )
        .unwrap();
        let public = PublicStepInput {
            action_quotient: 1,
            public_input: 0,
            fault_input: 0,
        };
        executor.step(&private_pair(), public).unwrap();
        assert_eq!(
            executor.step(&private_pair(), public),
            Err(ShadowError::Terminal)
        );
    }

    #[test]
    fn count_mismatch_and_step_exhaustion_fail_closed() {
        let machine = FixtureMachine {
            leak_readiness: false,
            state: 0,
        };
        let mut mismatch = ShadowExecutor::new(machine.clone(), 2, limits()).unwrap();
        let public = PublicStepInput {
            action_quotient: 1,
            public_input: 0,
            fault_input: 0,
        };
        assert_eq!(
            mismatch.step(&private_pair()[..1], public),
            Err(ShadowError::InputCountMismatch)
        );
        let mut bounded = ShadowExecutor::new(
            machine,
            2,
            ShadowLimits {
                maximum_shadows: 2,
                maximum_steps: 1,
            },
        )
        .unwrap();
        bounded.step(&private_pair(), public).unwrap();
        assert_eq!(
            bounded.step(&private_pair(), public),
            Err(ShadowError::StepLimit)
        );
    }

    #[test]
    fn executor_requires_at_least_two_bounded_shadows() {
        let machine = FixtureMachine {
            leak_readiness: false,
            state: 0,
        };
        assert_eq!(
            ShadowExecutor::new(machine.clone(), 1, limits()).unwrap_err(),
            ShadowError::TooFewShadows
        );
        assert_eq!(
            ShadowExecutor::new(
                machine,
                17,
                ShadowLimits {
                    maximum_shadows: 16,
                    maximum_steps: 1,
                },
            )
            .unwrap_err(),
            ShadowError::ShadowLimit
        );
    }
}
