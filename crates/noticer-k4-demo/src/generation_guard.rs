use crate::{
    authenticated_public_clock::PublicClockAuthKey,
    durable_recovery_ledger::FileRecoveryLedger,
    monotonic_anchor::{
        AnchorBinding, AnchoredAuthenticatedClock, AnchoredClockError, MonotonicAnchor,
    },
    state_generation::{
        advance_generation, verify_generation, GenerationAnchor, StateGenerationError,
        StateSnapshot,
    },
};
use noticer_crypto::StateAuthenticationKey;
use std::path::Path;
#[derive(Debug)]
pub enum GenerationGuardError {
    Clock(AnchoredClockError),
    Ledger,
    Generation(StateGenerationError),
    Poisoned,
    SlotOverflow,
}
pub struct GenerationGuardedClock {
    clock: AnchoredAuthenticatedClock<Box<dyn MonotonicAnchor>>,
    _ledger: FileRecoveryLedger,
    generation_anchor: Box<dyn GenerationAnchor>,
    generation_key: StateAuthenticationKey,
    snapshot: StateSnapshot,
    poisoned: bool,
}
impl GenerationGuardedClock {
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        clock_path: impl AsRef<Path>,
        clock_key: PublicClockAuthKey,
        ledger_path: impl AsRef<Path>,
        ledger_key: StateAuthenticationKey,
        generation_key: StateAuthenticationKey,
        binding: AnchorBinding,
        monotonic_anchor: Box<dyn MonotonicAnchor>,
        mut generation_anchor: Box<dyn GenerationAnchor>,
    ) -> Result<Self, GenerationGuardError> {
        let ledger =
            FileRecoveryLedger::open(ledger_path, binding.epoch, binding.generation, ledger_key)
                .map_err(|_| GenerationGuardError::Ledger)?;
        let clock =
            AnchoredAuthenticatedClock::open(clock_path, binding, clock_key, monotonic_anchor)
                .map_err(GenerationGuardError::Clock)?;
        let snapshot = StateSnapshot {
            binding,
            clock_slot: clock.slot(),
            anchor_slot: clock.slot(),
            recovery_ledger: ledger.head(),
        };
        verify_generation(&snapshot, &generation_key, &mut generation_anchor)
            .map_err(GenerationGuardError::Generation)?;
        Ok(Self {
            clock,
            _ledger: ledger,
            generation_anchor,
            generation_key,
            snapshot,
            poisoned: false,
        })
    }
    pub const fn slot(&self) -> u64 {
        self.snapshot.clock_slot
    }
    pub fn advance(&mut self, slot: u64) -> Result<(), GenerationGuardError> {
        if self.poisoned {
            return Err(GenerationGuardError::Poisoned);
        }
        if let Err(e) = self.clock.advance(slot) {
            self.poisoned = true;
            return Err(GenerationGuardError::Clock(e));
        }
        let next = StateSnapshot {
            clock_slot: slot,
            anchor_slot: slot,
            ..self.snapshot
        };
        if let Err(e) = advance_generation(
            &self.snapshot,
            &next,
            &self.generation_key,
            &mut self.generation_anchor,
        ) {
            self.poisoned = true;
            return Err(GenerationGuardError::Generation(e));
        }
        self.snapshot = next;
        Ok(())
    }
}
