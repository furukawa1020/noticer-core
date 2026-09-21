use noticer_crypto::StateAuthenticationKey;
use noticer_k4_demo::{
    durable_recovery_ledger::FileRecoveryLedger, monotonic_anchor::AnchorBinding,
    recovery::RecoveryLedger, state_generation::*,
};
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
struct TestAnchor {
    binding: AnchorBinding,
    state: GenerationAnchorState,
    available: bool,
}
impl GenerationAnchor for TestAnchor {
    fn current(
        &mut self,
        b: AnchorBinding,
    ) -> Result<GenerationAnchorState, GenerationAnchorError> {
        if !self.available {
            return Err(GenerationAnchorError::Unavailable);
        }
        if b != self.binding {
            return Err(GenerationAnchorError::BindingMismatch);
        }
        Ok(self.state)
    }
    fn advance(
        &mut self,
        b: AnchorBinding,
        e: u64,
        n: GenerationAnchorState,
    ) -> Result<(), GenerationAnchorError> {
        if b != self.binding || self.state.revision != e {
            return Err(GenerationAnchorError::BindingMismatch);
        }
        self.state = n;
        Ok(())
    }
}
fn path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "noticer-generation-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}
fn ledger_key() -> StateAuthenticationKey {
    StateAuthenticationKey::new([61; 32])
}
fn generation_key() -> StateAuthenticationKey {
    StateAuthenticationKey::new([62; 32])
}
#[test]
fn coordinated_and_individual_rollbacks_mismatch_external_commitment() {
    let p = path();
    let binding = AnchorBinding {
        epoch: 5,
        generation: 7,
    };
    let mut ledger = FileRecoveryLedger::open(&p, 5, 7, ledger_key()).unwrap();
    let old = StateSnapshot {
        binding,
        clock_slot: 10,
        anchor_slot: 10,
        recovery_ledger: ledger.head(),
    };
    let mut external = TestAnchor {
        binding,
        state: initial_generation_state(&old, &generation_key()),
        available: true,
    };
    ledger.consume([1; 16]).unwrap();
    let new = StateSnapshot {
        binding,
        clock_slot: 11,
        anchor_slot: 11,
        recovery_ledger: ledger.head(),
    };
    advance_generation(&old, &new, &generation_key(), &mut external).unwrap();
    verify_generation(&new, &generation_key(), &mut external).unwrap();
    assert_eq!(
        verify_generation(&old, &generation_key(), &mut external),
        Err(StateGenerationError::CommitmentMismatch)
    );
    let clock_only = StateSnapshot {
        clock_slot: 10,
        ..new
    };
    assert_eq!(
        verify_generation(&clock_only, &generation_key(), &mut external),
        Err(StateGenerationError::CommitmentMismatch)
    );
    let ledger_only = StateSnapshot {
        recovery_ledger: old.recovery_ledger,
        ..new
    };
    assert_eq!(
        verify_generation(&ledger_only, &generation_key(), &mut external),
        Err(StateGenerationError::CommitmentMismatch)
    );
    drop(ledger);
    fs::remove_file(p).unwrap();
}
#[test]
fn unavailable_anchor_and_regression_fail_closed() {
    let binding = AnchorBinding {
        epoch: 5,
        generation: 7,
    };
    let snapshot = StateSnapshot {
        binding,
        clock_slot: 3,
        anchor_slot: 3,
        recovery_ledger: noticer_k4_demo::durable_recovery_ledger::RecoveryLedgerHead {
            sequence: 0,
            tag: [0; 32],
        },
    };
    let mut down = TestAnchor {
        binding,
        state: initial_generation_state(&snapshot, &generation_key()),
        available: false,
    };
    assert_eq!(
        verify_generation(&snapshot, &generation_key(), &mut down),
        Err(StateGenerationError::Anchor(
            GenerationAnchorError::Unavailable
        ))
    );
    let mut up = TestAnchor {
        binding,
        state: initial_generation_state(&snapshot, &generation_key()),
        available: true,
    };
    let regressed = StateSnapshot {
        clock_slot: 2,
        ..snapshot
    };
    assert_eq!(
        advance_generation(&snapshot, &regressed, &generation_key(), &mut up),
        Err(StateGenerationError::Regression)
    );
}
