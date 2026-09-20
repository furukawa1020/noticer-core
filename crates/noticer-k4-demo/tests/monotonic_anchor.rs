use noticer_k4_demo::{
    authenticated_public_clock::{
        AuthenticatedClockError, AuthenticatedDurablePublicClock, PublicClockAuthKey,
    },
    monotonic_anchor::*,
};
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
#[derive(Clone)]
struct TestAnchor {
    binding: AnchorBinding,
    slot: u64,
    available: bool,
    fail: bool,
}
impl MonotonicAnchor for TestAnchor {
    fn current(&mut self, b: AnchorBinding) -> Result<u64, MonotonicAnchorError> {
        if !self.available {
            return Err(MonotonicAnchorError::Unavailable);
        }
        if b != self.binding {
            return Err(MonotonicAnchorError::BindingMismatch);
        }
        Ok(self.slot)
    }
    fn advance(&mut self, b: AnchorBinding, s: u64) -> Result<(), MonotonicAnchorError> {
        if b != self.binding {
            return Err(MonotonicAnchorError::BindingMismatch);
        }
        if self.fail || s < self.slot {
            return Err(MonotonicAnchorError::UpdateFailed);
        }
        self.slot = s;
        Ok(())
    }
}
fn path(l: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "noticer-anchor-{l}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}
fn key() -> PublicClockAuthKey {
    PublicClockAuthKey::new([49; 32])
}
fn binding() -> AnchorBinding {
    AnchorBinding {
        epoch: 5,
        generation: 8,
    }
}
#[test]
fn stale_valid_record_is_rejected() {
    let p = path("record");
    let c = AuthenticatedDurablePublicClock::open(&p, 5, 8, 10, key()).unwrap();
    drop(c);
    let old = fs::read(&p).unwrap();
    let mut c = AnchoredAuthenticatedClock::open(
        &p,
        binding(),
        key(),
        TestAnchor {
            binding: binding(),
            slot: 10,
            available: true,
            fail: false,
        },
    )
    .unwrap();
    c.advance(11).unwrap();
    drop(c);
    fs::write(&p, old).unwrap();
    assert!(matches!(
        AnchoredAuthenticatedClock::open(
            &p,
            binding(),
            key(),
            TestAnchor {
                binding: binding(),
                slot: 11,
                available: true,
                fail: false
            }
        ),
        Err(AnchoredClockError::Clock(
            AuthenticatedClockError::TrustedSlotMismatch
        ))
    ));
    fs::remove_file(p).unwrap();
}
#[test]
fn update_failure_poisons_and_stale_anchor_is_rejected() {
    let p = path("anchor");
    let c = AuthenticatedDurablePublicClock::open(&p, 5, 8, 10, key()).unwrap();
    drop(c);
    let mut c = AnchoredAuthenticatedClock::open(
        &p,
        binding(),
        key(),
        TestAnchor {
            binding: binding(),
            slot: 10,
            available: true,
            fail: true,
        },
    )
    .unwrap();
    assert!(matches!(
        c.advance(11),
        Err(AnchoredClockError::Anchor(
            MonotonicAnchorError::UpdateFailed
        ))
    ));
    assert!(matches!(c.advance(12), Err(AnchoredClockError::Poisoned)));
    drop(c);
    assert!(matches!(
        AnchoredAuthenticatedClock::open(
            &p,
            binding(),
            key(),
            TestAnchor {
                binding: binding(),
                slot: 10,
                available: true,
                fail: false
            }
        ),
        Err(AnchoredClockError::Clock(AuthenticatedClockError::Rollback))
    ));
    fs::remove_file(p).unwrap();
}
#[test]
fn unavailable_anchor_creates_no_record() {
    let p = path("down");
    assert!(matches!(
        AnchoredAuthenticatedClock::open(
            &p,
            binding(),
            key(),
            TestAnchor {
                binding: binding(),
                slot: 0,
                available: false,
                fail: false
            }
        ),
        Err(AnchoredClockError::Anchor(
            MonotonicAnchorError::Unavailable
        ))
    ));
    assert!(!p.exists());
}
