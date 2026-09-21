use noticer_aetp::ServiceBinding;
use noticer_crypto::{derive_issuer_keys, CryptographicRootSecret};
use noticer_k4_demo::{
    authenticated_public_clock::{AuthenticatedDurablePublicClock, PublicClockAuthKey},
    monotonic_anchor::{
        AnchorBinding, AnchoredAuthenticatedClock, MonotonicAnchor, MonotonicAnchorError,
    },
    recovery::*,
};
use std::{
    collections::HashSet,
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
#[derive(Default)]
struct Ledger(HashSet<[u8; 16]>);
impl RecoveryLedger for Ledger {
    fn consume(&mut self, id: [u8; 16]) -> Result<bool, ()> {
        Ok(self.0.insert(id))
    }
}
fn path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "noticer-recovery-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}
fn key() -> PublicClockAuthKey {
    PublicClockAuthKey::new([33; 32])
}
#[test]
fn signed_one_time_permit_recovers_exact_mismatch() {
    let p = path();
    let binding = AnchorBinding {
        epoch: 5,
        generation: 7,
    };
    let domain = ServiceBinding([8; 16]);
    let issuer = derive_issuer_keys(&CryptographicRootSecret::new([9; 32]), domain, 5).unwrap();
    let verifier = issuer.verifier_material();
    let c = AuthenticatedDurablePublicClock::open(&p, 5, 7, 10, key()).unwrap();
    drop(c);
    let mut anchor = Anchor { binding, slot: 11 };
    let permit = issue_recovery_permit(&issuer, domain, 7, 10, 11, 12, 100, [1; 16]);
    let mut ledger = Ledger::default();
    assert_eq!(
        recover_clock(
            &p,
            key(),
            &verifier,
            domain,
            binding,
            50,
            &permit,
            &mut anchor,
            &mut ledger
        )
        .unwrap(),
        12
    );
    let anchored = AnchoredAuthenticatedClock::open(&p, binding, key(), anchor).unwrap();
    assert_eq!(anchored.slot(), 12);
    drop(anchored);
    fs::remove_file(p).unwrap();
}
#[test]
fn replay_expiry_and_transplant_fail_closed() {
    let p = path();
    let binding = AnchorBinding {
        epoch: 5,
        generation: 7,
    };
    let domain = ServiceBinding([8; 16]);
    let issuer = derive_issuer_keys(&CryptographicRootSecret::new([9; 32]), domain, 5).unwrap();
    let verifier = issuer.verifier_material();
    let c = AuthenticatedDurablePublicClock::open(&p, 5, 7, 10, key()).unwrap();
    drop(c);
    let mut anchor = Anchor { binding, slot: 11 };
    let permit = issue_recovery_permit(&issuer, domain, 7, 10, 11, 12, 40, [2; 16]);
    let mut ledger = Ledger::default();
    assert!(matches!(
        recover_clock(
            &p,
            key(),
            &verifier,
            domain,
            binding,
            41,
            &permit,
            &mut anchor,
            &mut ledger
        ),
        Err(RecoveryError::Expired)
    ));
    let mut wrong = permit.clone();
    wrong.generation = 8;
    assert!(matches!(
        recover_clock(
            &p,
            key(),
            &verifier,
            domain,
            binding,
            20,
            &wrong,
            &mut anchor,
            &mut ledger
        ),
        Err(RecoveryError::Binding)
    ));
    ledger
        .consume(permit.signature[..16].try_into().unwrap())
        .unwrap();
    assert!(matches!(
        recover_clock(
            &p,
            key(),
            &verifier,
            domain,
            binding,
            20,
            &permit,
            &mut anchor,
            &mut ledger
        ),
        Err(RecoveryError::Replay)
    ));
    fs::remove_file(p).unwrap();
}
