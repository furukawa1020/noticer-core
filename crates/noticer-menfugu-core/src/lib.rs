#![no_std]
#![forbid(unsafe_code)]

//! Fail-closed physical actuation state machine for Menfugu.

use noticer_protocol::TokenId;
use noticer_types::ActionCode;
use noticer_verifier_core::AuthorizedAction;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionPolicy {
    pub pump_ticks: u32,
    pub maximum_pump_ticks: u32,
    pub cooldown_slots: u32,
    pub execution_period_slots: u32,
    pub execution_offset_slots: u32,
}

impl ExecutionPolicy {
    pub const fn validate(self) -> Result<Self, ExecutionError> {
        if self.pump_ticks == 0
            || self.pump_ticks > self.maximum_pump_ticks
            || self.execution_period_slots == 0
            || self.execution_offset_slots >= self.execution_period_slots
        {
            return Err(ExecutionError::InvalidConfiguration);
        }
        Ok(self)
    }

    pub const fn slot_is_publicly_allowed(self, slot: u32) -> bool {
        slot % self.execution_period_slots == self.execution_offset_slots
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActuationCommand {
    PumpOn { duration_ticks: u32 },
    PumpOff,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionState {
    Idle,
    Pumping {
        stop_tick: u64,
        cooldown_until_slot: u32,
    },
    Cooldown {
        until_slot: u32,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionError {
    InvalidConfiguration,
    UnsupportedAction,
    OutsidePublicExecutionSlot,
    Busy,
    Cooldown,
    AlreadyConsumed,
    ClockOverflow,
    ConsumptionCapacity,
}

struct ConsumedTokens<const CAPACITY: usize> {
    ids: [TokenId; CAPACITY],
    occupied: [bool; CAPACITY],
    cursor: usize,
}

impl<const CAPACITY: usize> ConsumedTokens<CAPACITY> {
    const fn new() -> Self {
        Self {
            ids: [TokenId([0; 16]); CAPACITY],
            occupied: [false; CAPACITY],
            cursor: 0,
        }
    }

    fn contains(&self, token_id: TokenId) -> bool {
        self.ids
            .iter()
            .zip(self.occupied)
            .any(|(known, occupied)| occupied && *known == token_id)
    }

    fn insert(&mut self, token_id: TokenId) -> Result<(), ExecutionError> {
        if CAPACITY == 0 {
            return Err(ExecutionError::ConsumptionCapacity);
        }
        self.ids[self.cursor] = token_id;
        self.occupied[self.cursor] = true;
        self.cursor = (self.cursor + 1) % CAPACITY;
        Ok(())
    }
}

pub struct MenfuguExecutor<const CONSUMED_CAPACITY: usize> {
    policy: ExecutionPolicy,
    state: ExecutionState,
    consumed: ConsumedTokens<CONSUMED_CAPACITY>,
}

impl<const CONSUMED_CAPACITY: usize> MenfuguExecutor<CONSUMED_CAPACITY> {
    pub fn new(policy: ExecutionPolicy) -> Result<Self, ExecutionError> {
        Ok(Self {
            policy: policy.validate()?,
            state: ExecutionState::Idle,
            consumed: ConsumedTokens::new(),
        })
    }

    pub const fn state(&self) -> ExecutionState {
        self.state
    }

    /// Only the sealed output of the shared verifier core reaches this boundary.
    pub fn request(
        &mut self,
        authorization: AuthorizedAction,
        now_slot: u32,
        now_tick: u64,
    ) -> Result<ActuationCommand, ExecutionError> {
        self.request_verified(
            authorization.action,
            authorization.token_id,
            now_slot,
            now_tick,
        )
    }

    pub fn advance(&mut self, now_slot: u32, now_tick: u64) -> Option<ActuationCommand> {
        match self.state {
            ExecutionState::Pumping {
                stop_tick,
                cooldown_until_slot,
            } if now_tick >= stop_tick => {
                self.state = ExecutionState::Cooldown {
                    until_slot: cooldown_until_slot,
                };
                Some(ActuationCommand::PumpOff)
            }
            ExecutionState::Cooldown { until_slot } if now_slot >= until_slot => {
                self.state = ExecutionState::Idle;
                None
            }
            _ => None,
        }
    }

    fn request_verified(
        &mut self,
        action: ActionCode,
        token_id: TokenId,
        now_slot: u32,
        now_tick: u64,
    ) -> Result<ActuationCommand, ExecutionError> {
        self.settle_cooldown(now_slot);
        if action != ActionCode::MenfuguInflateSoft {
            return Err(ExecutionError::UnsupportedAction);
        }
        if !self.policy.slot_is_publicly_allowed(now_slot) {
            return Err(ExecutionError::OutsidePublicExecutionSlot);
        }
        match self.state {
            ExecutionState::Pumping { .. } => return Err(ExecutionError::Busy),
            ExecutionState::Cooldown { .. } => return Err(ExecutionError::Cooldown),
            ExecutionState::Idle => {}
        }
        if self.consumed.contains(token_id) {
            return Err(ExecutionError::AlreadyConsumed);
        }
        let stop_tick = now_tick
            .checked_add(u64::from(self.policy.pump_ticks))
            .ok_or(ExecutionError::ClockOverflow)?;
        let cooldown_until_slot = now_slot
            .checked_add(self.policy.cooldown_slots)
            .ok_or(ExecutionError::ClockOverflow)?;
        self.consumed.insert(token_id)?;
        self.state = ExecutionState::Pumping {
            stop_tick,
            cooldown_until_slot,
        };
        Ok(ActuationCommand::PumpOn {
            duration_ticks: self.policy.pump_ticks,
        })
    }

    fn settle_cooldown(&mut self, now_slot: u32) {
        if matches!(
            self.state,
            ExecutionState::Cooldown { until_slot } if now_slot >= until_slot
        ) {
            self.state = ExecutionState::Idle;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> ExecutionPolicy {
        ExecutionPolicy {
            pump_ticks: 20,
            maximum_pump_ticks: 30,
            cooldown_slots: 4,
            execution_period_slots: 4,
            execution_offset_slots: 2,
        }
    }

    #[test]
    fn only_soft_inflate_in_public_slot_runs_once() {
        let mut executor = MenfuguExecutor::<4>::new(policy()).unwrap();
        let token = TokenId([1; 16]);
        assert_eq!(
            executor.request_verified(ActionCode::RenderAmbientPulse, token, 10, 100),
            Err(ExecutionError::UnsupportedAction)
        );
        assert_eq!(
            executor.request_verified(ActionCode::MenfuguInflateSoft, token, 11, 100),
            Err(ExecutionError::OutsidePublicExecutionSlot)
        );
        assert_eq!(
            executor.request_verified(ActionCode::MenfuguInflateSoft, token, 10, 100),
            Ok(ActuationCommand::PumpOn { duration_ticks: 20 })
        );
        assert_eq!(executor.advance(10, 120), Some(ActuationCommand::PumpOff));
        assert_eq!(
            executor.request_verified(ActionCode::MenfuguInflateSoft, TokenId([2; 16]), 10, 121),
            Err(ExecutionError::Cooldown)
        );
        assert_eq!(
            executor.request_verified(ActionCode::MenfuguInflateSoft, token, 14, 122),
            Err(ExecutionError::AlreadyConsumed)
        );
    }

    #[test]
    fn invalid_bounds_and_clock_overflow_fail_closed() {
        let mut invalid = policy();
        invalid.pump_ticks = 31;
        assert!(matches!(
            MenfuguExecutor::<4>::new(invalid),
            Err(ExecutionError::InvalidConfiguration)
        ));
        let mut executor = MenfuguExecutor::<4>::new(policy()).unwrap();
        assert_eq!(
            executor.request_verified(
                ActionCode::MenfuguInflateSoft,
                TokenId([3; 16]),
                10,
                u64::MAX
            ),
            Err(ExecutionError::ClockOverflow)
        );
    }
}
