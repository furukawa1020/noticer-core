#![forbid(unsafe_code)]

//! Fixed-cadence BLE host adapters. Application-level retry is intentionally absent.

use noticer_aetp::ServiceBinding;
use noticer_menfugu_firmware::EnvelopeVerifier;
use noticer_protocol::ENVELOPE_SIZE;
use noticer_transport_core::{Fragment, TOTAL_FRAGMENT_COUNT};
use noticer_verifier::{TokenVerifier, VerificationResult, VerifierContext};

#[cfg(all(
    feature = "btleplug-adapter",
    any(target_os = "windows", target_os = "macos")
))]
pub mod btleplug_sender;

pub trait FragmentWriter {
    type Error;

    fn write_without_response(&mut self, fragment: &[u8; 20]) -> Result<(), Self::Error>;
}

pub trait PublicCadenceClock {
    fn wait_until(&mut self, public_tick: u64);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendReport {
    pub attempted: u8,
    pub failed_mask: u32,
}

/// Attempts all 20 public slots exactly once, even if a write fails.
pub fn send_fixed_cadence<W: FragmentWriter, C: PublicCadenceClock>(
    writer: &mut W,
    clock: &mut C,
    fragments: &[Fragment; TOTAL_FRAGMENT_COUNT],
    start_tick: u64,
    cadence_ticks: u64,
) -> SendReport {
    let mut failed_mask = 0_u32;
    for (ordinal, fragment) in fragments.iter().enumerate() {
        let tick = start_tick.saturating_add(cadence_ticks.saturating_mul(ordinal as u64));
        clock.wait_until(tick);
        if writer.write_without_response(&fragment.encode()).is_err() {
            failed_mask |= 1_u32 << ordinal;
        }
    }
    SendReport {
        attempted: TOTAL_FRAGMENT_COUNT as u8,
        failed_mask,
    }
}

pub struct HostVerifierAdapter {
    verifier: TokenVerifier,
    expected_service: ServiceBinding,
    expected_epoch: u32,
}

impl HostVerifierAdapter {
    pub fn new(
        verifier: TokenVerifier,
        expected_service: ServiceBinding,
        expected_epoch: u32,
    ) -> Self {
        Self {
            verifier,
            expected_service,
            expected_epoch,
        }
    }
}

impl EnvelopeVerifier for HostVerifierAdapter {
    fn verify(
        &mut self,
        envelope: &[u8; ENVELOPE_SIZE],
        public_now_slot: u32,
    ) -> VerificationResult {
        self.verifier.verify(
            envelope,
            VerifierContext {
                expected_service: self.expected_service,
                expected_epoch: self.expected_epoch,
                now_slot: public_now_slot,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noticer_protocol::ENVELOPE_SIZE;
    use noticer_transport_core::{
        derive_frame_id, fragment_envelope, TransportFrameIdentity, TransportIdKey,
    };

    #[derive(Default)]
    struct Writer {
        calls: usize,
    }

    impl FragmentWriter for Writer {
        type Error = ();

        fn write_without_response(&mut self, _fragment: &[u8; 20]) -> Result<(), Self::Error> {
            self.calls += 1;
            if self.calls == 3 {
                Err(())
            } else {
                Ok(())
            }
        }
    }

    #[derive(Default)]
    struct Clock {
        ticks: [u64; TOTAL_FRAGMENT_COUNT],
        calls: usize,
    }

    impl PublicCadenceClock for Clock {
        fn wait_until(&mut self, public_tick: u64) {
            self.ticks[self.calls] = public_tick;
            self.calls += 1;
        }
    }

    #[test]
    fn write_failure_does_not_retry_or_change_public_schedule() {
        let frame_id = derive_frame_id(
            &TransportIdKey::new([7; 32]),
            TransportFrameIdentity {
                service_alias: [1; 8],
                public_epoch: 2,
                public_bucket: 3,
                sequence: 4,
            },
        );
        let fragments = fragment_envelope(&[0; ENVELOPE_SIZE], frame_id);
        let mut writer = Writer::default();
        let mut clock = Clock::default();
        let report = send_fixed_cadence(&mut writer, &mut clock, &fragments, 10, 5);
        assert_eq!(report.attempted, 20);
        assert_eq!(writer.calls, 20);
        assert_eq!(clock.ticks[19], 105);
        assert_eq!(report.failed_mask, 1 << 2);
    }
}
