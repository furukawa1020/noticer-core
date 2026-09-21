use noticer_aetp::ServiceBinding;
use noticer_crypto::{derive_issuer_keys, CryptographicRootSecret, StateAuthenticationKey};
use noticer_k4_demo::{
    authenticated_public_clock::{AuthenticatedDurablePublicClock, PublicClockAuthKey},
    durable_recovery::{recover_clock_with_durable_ledger, DurableRecoveryError},
    monotonic_anchor::{AnchorBinding, MonotonicAnchor, MonotonicAnchorError},
    recovery::{issue_recovery_permit, RecoveryError},
};
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
struct Anchor {
    binding: AnchorBinding,
    slot: u64,
}
impl MonotonicAnchor for Anchor {
    fn current(&mut self, b: AnchorBinding) -> Result<u64, MonotonicAnchorError> {
        if b != self.binding {
            return Err(MonotonicAnchorError::BindingMismatch);
        }
        Ok(self.slot)
    }
    fn advance(&mut self, b: AnchorBinding, s: u64) -> Result<(), MonotonicAnchorError> {
        if b != self.binding {
            return Err(MonotonicAnchorError::BindingMismatch);
        }
        self.slot = s;
        Ok(())
    }
}
fn path(l: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "noticer-durable-recovery-{l}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}
fn ck() -> PublicClockAuthKey {
    PublicClockAuthKey::new([22; 32])
}
fn lk() -> StateAuthenticationKey {
    StateAuthenticationKey::new([23; 32])
}
#[test]
fn consumed_permit_survives_clock_and_anchor_rollback() {
    let clock = path("clock");
    let ledger = path("ledger");
    let binding = AnchorBinding {
        epoch: 5,
        generation: 9,
    };
    let domain = ServiceBinding([4; 16]);
    let issuer = derive_issuer_keys(&CryptographicRootSecret::new([5; 32]), domain, 5).unwrap();
    let verifier = issuer.verifier_material();
    let c = AuthenticatedDurablePublicClock::open(&clock, 5, 9, 10, ck()).unwrap();
    drop(c);
    let old = fs::read(&clock).unwrap();
    let permit = issue_recovery_permit(&issuer, domain, 9, 10, 11, 12, 100, [8; 16]);
    let mut anchor = Anchor { binding, slot: 11 };
    assert_eq!(
        recover_clock_with_durable_ledger(
            &clock,
            ck(),
            &ledger,
            lk(),
            &verifier,
            domain,
            binding,
            50,
            &permit,
            &mut anchor
        )
        .unwrap(),
        12
    );
    fs::write(&clock, old).unwrap();
    anchor.slot = 11;
    assert!(matches!(
        recover_clock_with_durable_ledger(
            &clock,
            ck(),
            &ledger,
            lk(),
            &verifier,
            domain,
            binding,
            50,
            &permit,
            &mut anchor
        ),
        Err(DurableRecoveryError::Recovery(RecoveryError::Replay))
    ));
    fs::remove_file(clock).unwrap();
    fs::remove_file(ledger).unwrap();
}
