#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

pub const HARDWARE_STATUS: &str = "NOT_VERIFIED";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceMode {
    PolarLiveObserved,
    SyntheticReplay,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceAssurance {
    LiveBleObserved,
    SyntheticReplay,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamClass {
    Ppg,
    Accelerometer,
    InterBeatInterval,
}

pub struct PrivateSensorFrame {
    source: SourceMode,
    session_nonce: [u8; 16],
    sequence: u64,
    device_time_ns: u64,
    stream: StreamClass,
    samples: Vec<i32>,
}

impl PrivateSensorFrame {
    pub fn new(
        source: SourceMode,
        session_nonce: [u8; 16],
        sequence: u64,
        device_time_ns: u64,
        stream: StreamClass,
        samples: Vec<i32>,
    ) -> Result<Self, IngressError> {
        if session_nonce == [0; 16] {
            return Err(IngressError::InvalidSessionNonce);
        }
        if samples.is_empty() {
            return Err(IngressError::EmptyFrame);
        }
        Ok(Self {
            source,
            session_nonce,
            sequence,
            device_time_ns,
            stream,
            samples,
        })
    }
}

impl fmt::Debug for PrivateSensorFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateSensorFrame")
            .field("source", &self.source)
            .field("stream", &self.stream)
            .field("session_nonce", &"REDACTED")
            .field("sequence", &"REDACTED")
            .field("device_time_ns", &"REDACTED")
            .field("samples", &"REDACTED")
            .finish()
    }
}

impl Drop for PrivateSensorFrame {
    fn drop(&mut self) {
        self.session_nonce.fill(0);
        self.sequence = 0;
        self.device_time_ns = 0;
        self.samples.fill(0);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicIngressReceipt {
    pub epoch: u64,
    pub ordinal: u64,
    pub stream: StreamClass,
    pub source_assurance: SourceAssurance,
    pub hardware_status: &'static str,
}

pub struct PrivateNormalizedEvent {
    receipt: PublicIngressReceipt,
    samples: Vec<i32>,
}

impl PrivateNormalizedEvent {
    pub const fn public_receipt(&self) -> PublicIngressReceipt {
        self.receipt
    }

    pub fn consume_with<R>(mut self, consumer: impl FnOnce(&[i32]) -> R) -> R {
        let result = consumer(&self.samples);
        self.samples.fill(0);
        result
    }
}

impl fmt::Debug for PrivateNormalizedEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateNormalizedEvent")
            .field("receipt", &self.receipt)
            .field("samples", &"REDACTED")
            .finish()
    }
}

impl Drop for PrivateNormalizedEvent {
    fn drop(&mut self) {
        self.samples.fill(0);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IngressLimits {
    pub maximum_samples_per_frame: usize,
    pub maximum_gap_ns: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngressError {
    InvalidSessionNonce,
    EmptyFrame,
    FrameTooLarge,
    SessionMismatch,
    SourceChanged,
    DuplicateSequence,
    SequenceRollback,
    ClockRollback,
    ClockGap,
}

#[derive(Clone, Debug)]
pub struct PrivacyBoundaryAdapter {
    source: SourceMode,
    session_nonce: [u8; 16],
    epoch: u64,
    next_ordinal: u64,
    last_sequence: Option<u64>,
    last_device_time_ns: Option<u64>,
    limits: IngressLimits,
}

impl PrivacyBoundaryAdapter {
    pub fn start(
        source: SourceMode,
        session_nonce: [u8; 16],
        epoch: u64,
        limits: IngressLimits,
    ) -> Result<Self, IngressError> {
        if session_nonce == [0; 16] {
            return Err(IngressError::InvalidSessionNonce);
        }
        Ok(Self {
            source,
            session_nonce,
            epoch,
            next_ordinal: 0,
            last_sequence: None,
            last_device_time_ns: None,
            limits,
        })
    }

    pub fn normalize(
        &mut self,
        mut frame: PrivateSensorFrame,
    ) -> Result<PrivateNormalizedEvent, IngressError> {
        if frame.session_nonce != self.session_nonce {
            return Err(IngressError::SessionMismatch);
        }
        if frame.source != self.source {
            return Err(IngressError::SourceChanged);
        }
        if frame.samples.len() > self.limits.maximum_samples_per_frame {
            return Err(IngressError::FrameTooLarge);
        }
        if let Some(last) = self.last_sequence {
            if frame.sequence == last {
                return Err(IngressError::DuplicateSequence);
            }
            if frame.sequence < last {
                return Err(IngressError::SequenceRollback);
            }
        }
        if let Some(last) = self.last_device_time_ns {
            if frame.device_time_ns <= last {
                return Err(IngressError::ClockRollback);
            }
            if frame.device_time_ns - last > self.limits.maximum_gap_ns {
                return Err(IngressError::ClockGap);
            }
        }
        let receipt = PublicIngressReceipt {
            epoch: self.epoch,
            ordinal: self.next_ordinal,
            stream: frame.stream,
            source_assurance: match frame.source {
                SourceMode::PolarLiveObserved => SourceAssurance::LiveBleObserved,
                SourceMode::SyntheticReplay => SourceAssurance::SyntheticReplay,
            },
            hardware_status: HARDWARE_STATUS,
        };
        self.last_sequence = Some(frame.sequence);
        self.last_device_time_ns = Some(frame.device_time_ns);
        self.next_ordinal = self.next_ordinal.saturating_add(1);
        let samples = core::mem::take(&mut frame.samples);
        Ok(PrivateNormalizedEvent { receipt, samples })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, vec};

    fn frame(source: SourceMode, sequence: u64, time: u64) -> PrivateSensorFrame {
        PrivateSensorFrame::new(
            source,
            [7; 16],
            sequence,
            time,
            StreamClass::Ppg,
            vec![71234567, -1234567],
        )
        .unwrap()
    }

    fn adapter(source: SourceMode) -> PrivacyBoundaryAdapter {
        PrivacyBoundaryAdapter::start(
            source,
            [7; 16],
            3,
            IngressLimits {
                maximum_samples_per_frame: 8,
                maximum_gap_ns: 1_000,
            },
        )
        .unwrap()
    }

    #[test]
    fn live_and_replay_share_schema_without_assurance_upgrade() {
        let live = adapter(SourceMode::PolarLiveObserved)
            .normalize(frame(SourceMode::PolarLiveObserved, 1, 10))
            .unwrap()
            .public_receipt();
        let replay = adapter(SourceMode::SyntheticReplay)
            .normalize(frame(SourceMode::SyntheticReplay, 1, 10))
            .unwrap()
            .public_receipt();
        assert_eq!(live.stream, replay.stream);
        assert_eq!(live.hardware_status, "NOT_VERIFIED");
        assert_eq!(live.source_assurance, SourceAssurance::LiveBleObserved);
        assert_eq!(replay.source_assurance, SourceAssurance::SyntheticReplay);
    }

    #[test]
    fn debug_output_redacts_private_values() {
        let raw = frame(SourceMode::PolarLiveObserved, 99, 123_456);
        let debug = format!("{raw:?}");
        assert!(!debug.contains("71234567"));
        assert!(!debug.contains("123456"));
        assert!(debug.contains("REDACTED"));
        let event = adapter(SourceMode::PolarLiveObserved)
            .normalize(raw)
            .unwrap();
        assert!(!format!("{event:?}").contains("71234567"));
    }

    #[test]
    fn public_receipt_excludes_session_time_sequence_and_size() {
        let event = adapter(SourceMode::PolarLiveObserved)
            .normalize(frame(SourceMode::PolarLiveObserved, 55, 900))
            .unwrap();
        assert_eq!(event.public_receipt().ordinal, 0);
        assert_eq!(event.consume_with(|samples| samples.len()), 2);
    }

    #[test]
    fn duplicate_rollback_gap_and_source_change_are_rejected() {
        let mut ingress = adapter(SourceMode::PolarLiveObserved);
        ingress
            .normalize(frame(SourceMode::PolarLiveObserved, 5, 1_000))
            .unwrap();
        assert_eq!(
            ingress
                .normalize(frame(SourceMode::PolarLiveObserved, 5, 1_001))
                .unwrap_err(),
            IngressError::DuplicateSequence
        );
        assert_eq!(
            ingress
                .normalize(frame(SourceMode::PolarLiveObserved, 4, 1_001))
                .unwrap_err(),
            IngressError::SequenceRollback
        );
        assert_eq!(
            ingress
                .normalize(frame(SourceMode::PolarLiveObserved, 6, 3_000))
                .unwrap_err(),
            IngressError::ClockGap
        );
        assert_eq!(
            ingress
                .normalize(frame(SourceMode::SyntheticReplay, 6, 1_001))
                .unwrap_err(),
            IngressError::SourceChanged
        );
    }

    #[test]
    fn session_mismatch_and_frame_bound_fail_closed() {
        let mut ingress = adapter(SourceMode::PolarLiveObserved);
        let mismatch = PrivateSensorFrame::new(
            SourceMode::PolarLiveObserved,
            [8; 16],
            1,
            1,
            StreamClass::Ppg,
            vec![1],
        )
        .unwrap();
        assert_eq!(
            ingress.normalize(mismatch).unwrap_err(),
            IngressError::SessionMismatch
        );
        let large = PrivateSensorFrame::new(
            SourceMode::PolarLiveObserved,
            [7; 16],
            1,
            1,
            StreamClass::Ppg,
            vec![0; 9],
        )
        .unwrap();
        assert_eq!(
            ingress.normalize(large).unwrap_err(),
            IngressError::FrameTooLarge
        );
    }
}
