#![no_std]
#![forbid(unsafe_code)]

//! ESP-IDF-facing, platform-neutral GATT ingress and pump-output boundary.

use noticer_menfugu_core::{ActuationCommand, ExecutionPolicy, MenfuguExecutor};
use noticer_protocol::ENVELOPE_SIZE;
use noticer_transport_core::{IngestOutcome, Reassembler};
use noticer_verifier_core::VerificationResult;

pub trait EnvelopeVerifier {
    fn verify(
        &mut self,
        envelope: &[u8; ENVELOPE_SIZE],
        public_now_slot: u32,
    ) -> VerificationResult;
}

pub trait PumpOutput {
    fn set_pump(&mut self, enabled: bool);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeEvent {
    Pending,
    Duplicate,
    Rejected,
    Cover,
    PumpStarted { duration_ticks: u32 },
    PumpStopped,
}

pub struct MenfuguRuntime<V, P, const ACTIVE_FRAMES: usize, const CONSUMED_TOKENS: usize> {
    verifier: V,
    pump: P,
    reassembler: Reassembler<ACTIVE_FRAMES>,
    executor: MenfuguExecutor<CONSUMED_TOKENS>,
}

impl<V, P, const ACTIVE_FRAMES: usize, const CONSUMED_TOKENS: usize>
    MenfuguRuntime<V, P, ACTIVE_FRAMES, CONSUMED_TOKENS>
where
    V: EnvelopeVerifier,
    P: PumpOutput,
{
    pub fn new(
        verifier: V,
        mut pump: P,
        reassembly_ttl_ticks: u64,
        execution_policy: ExecutionPolicy,
    ) -> Result<Self, noticer_menfugu_core::ExecutionError> {
        pump.set_pump(false);
        Ok(Self {
            verifier,
            pump,
            reassembler: Reassembler::new(reassembly_ttl_ticks),
            executor: MenfuguExecutor::new(execution_policy)?,
        })
    }

    /// A GATT write never invokes token verification before complete reassembly.
    pub fn on_gatt_write(
        &mut self,
        bytes: &[u8],
        public_tick: u64,
        public_now_slot: u32,
    ) -> RuntimeEvent {
        match self.reassembler.ingest(bytes, public_tick) {
            Ok(IngestOutcome::Pending) => RuntimeEvent::Pending,
            Ok(IngestOutcome::Duplicate) => RuntimeEvent::Duplicate,
            Err(_) => RuntimeEvent::Rejected,
            Ok(IngestOutcome::Complete(envelope)) => {
                match self.verifier.verify(&envelope, public_now_slot) {
                    VerificationResult::Cover => RuntimeEvent::Cover,
                    VerificationResult::Rejected => RuntimeEvent::Rejected,
                    VerificationResult::Authorized(action) => {
                        match self.executor.request(action, public_now_slot, public_tick) {
                            Ok(ActuationCommand::PumpOn { duration_ticks }) => {
                                self.pump.set_pump(true);
                                RuntimeEvent::PumpStarted { duration_ticks }
                            }
                            _ => RuntimeEvent::Rejected,
                        }
                    }
                }
            }
        }
    }

    pub fn on_public_timer(&mut self, public_tick: u64, public_now_slot: u32) -> RuntimeEvent {
        if self
            .executor
            .advance(public_now_slot, public_tick)
            .is_some_and(|command| command == ActuationCommand::PumpOff)
        {
            self.pump.set_pump(false);
            RuntimeEvent::PumpStopped
        } else {
            RuntimeEvent::Pending
        }
    }

    pub const fn pump(&self) -> &P {
        &self.pump
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RejectVerifier {
        calls: usize,
    }

    impl EnvelopeVerifier for RejectVerifier {
        fn verify(
            &mut self,
            _envelope: &[u8; ENVELOPE_SIZE],
            _public_now_slot: u32,
        ) -> VerificationResult {
            self.calls += 1;
            VerificationResult::Rejected
        }
    }

    #[derive(Default)]
    struct Pump {
        enabled: bool,
    }

    impl PumpOutput for Pump {
        fn set_pump(&mut self, enabled: bool) {
            self.enabled = enabled;
        }
    }

    #[test]
    fn malformed_or_incomplete_input_never_acts() {
        let policy = ExecutionPolicy {
            pump_ticks: 10,
            maximum_pump_ticks: 10,
            cooldown_slots: 2,
            execution_period_slots: 1,
            execution_offset_slots: 0,
        };
        let mut runtime = MenfuguRuntime::<_, _, 2, 4>::new(
            RejectVerifier { calls: 0 },
            Pump::default(),
            100,
            policy,
        )
        .unwrap();
        assert_eq!(runtime.on_gatt_write(&[0; 3], 0, 0), RuntimeEvent::Rejected);
        assert!(!runtime.pump().enabled);
    }
}
