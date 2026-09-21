use crate::{
    authenticated_public_clock::PublicClockAuthKey,
    durable_recovery_ledger::{FileRecoveryLedger, FileRecoveryLedgerError},
    monotonic_anchor::{AnchorBinding, MonotonicAnchor},
    recovery::{recover_clock, RecoveryError, RecoveryPermit},
};
use noticer_aetp::ServiceBinding;
use noticer_crypto::{StateAuthenticationKey, VerifierKeyMaterial};
use std::path::Path;
#[derive(Debug)]
pub enum DurableRecoveryError {
    Ledger(FileRecoveryLedgerError),
    Recovery(RecoveryError),
}
#[allow(clippy::too_many_arguments)]
pub fn recover_clock_with_durable_ledger<A: MonotonicAnchor>(
    clock_path: impl AsRef<Path>,
    clock_key: PublicClockAuthKey,
    ledger_path: impl AsRef<Path>,
    ledger_key: StateAuthenticationKey,
    verifier: &VerifierKeyMaterial,
    operator_domain: ServiceBinding,
    binding: AnchorBinding,
    now: u64,
    permit: &RecoveryPermit,
    anchor: &mut A,
) -> Result<u64, DurableRecoveryError> {
    let mut ledger =
        FileRecoveryLedger::open(ledger_path, binding.epoch, binding.generation, ledger_key)
            .map_err(DurableRecoveryError::Ledger)?;
    recover_clock(
        clock_path,
        clock_key,
        verifier,
        operator_domain,
        binding,
        now,
        permit,
        anchor,
        &mut ledger,
    )
    .map_err(DurableRecoveryError::Recovery)
}
