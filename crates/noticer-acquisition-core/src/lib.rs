#![forbid(unsafe_code)]

//! Private, bounded contracts for PPG and accelerometer acquisition.
//!
//! Raw batches deliberately do not implement `Serialize`, expose sample
//! getters, or print private values through `Debug`.
//!
//! ~~~compile_fail
//! use noticer_acquisition_core::{NegotiatedPpgSettings, PrivatePpgBatch};
//! let settings = NegotiatedPpgSettings::new(55, 22, 4).unwrap();
//! let batch = PrivatePpgBatch::new(1, 1, settings.period_ns(), settings, vec![1, 2, 3, 4]).unwrap();
//! let _ = serde_json::to_vec(&batch).unwrap();
//! ~~~
//!
//! ~~~compile_fail
//! use noticer_acquisition_core::{NegotiatedAccSettings, PrivateAccBatch};
//! let settings = NegotiatedAccSettings::new(52, 16, 3).unwrap();
//! let batch = PrivateAccBatch::new(1, 1, settings.period_ns(), settings, vec![1, 2, 3]).unwrap();
//! let _ = serde_json::to_vec(&batch).unwrap();
//! ~~~

use std::collections::VecDeque;
use std::fmt;

use noticer_ppg_features::{
    extract_private_features, EmpiricalSpoofRisk, FeatureSchema, PrivateFeatureVector,
    PrivateWindowInput, SignalQuality, FEATURE_STRIDE_NS, FEATURE_WINDOW_NS,
};
use noticer_provenance::{PolarSourceClaim, SourceAssurance};
use thiserror::Error;

const NANOS_PER_SECOND: u64 = 1_000_000_000;
const MAX_SAMPLES_PER_BATCH: usize = 16_384;
const MAX_RETAINED_BATCHES: usize = 4_096;
const MAX_RETAINED_SAMPLES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NegotiatedPpgSettings {
    sample_rate_hz: u16,
    resolution_bits: u8,
    channel_count: u8,
}

impl NegotiatedPpgSettings {
    pub fn new(
        sample_rate_hz: u16,
        resolution_bits: u8,
        channel_count: u8,
    ) -> Result<Self, AcquisitionError> {
        if !(1..=1_000).contains(&sample_rate_hz)
            || !(8..=32).contains(&resolution_bits)
            || !(1..=4).contains(&channel_count)
        {
            return Err(AcquisitionError::InvalidSettings);
        }
        Ok(Self {
            sample_rate_hz,
            resolution_bits,
            channel_count,
        })
    }

    pub const fn sample_rate_hz(self) -> u16 {
        self.sample_rate_hz
    }

    pub const fn resolution_bits(self) -> u8 {
        self.resolution_bits
    }

    pub const fn channel_count(self) -> u8 {
        self.channel_count
    }

    pub fn period_ns(self) -> u64 {
        NANOS_PER_SECOND / u64::from(self.sample_rate_hz)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NegotiatedAccSettings {
    sample_rate_hz: u16,
    resolution_bits: u8,
    axis_count: u8,
}

impl NegotiatedAccSettings {
    pub fn new(
        sample_rate_hz: u16,
        resolution_bits: u8,
        axis_count: u8,
    ) -> Result<Self, AcquisitionError> {
        if !(1..=2_000).contains(&sample_rate_hz)
            || !(8..=32).contains(&resolution_bits)
            || axis_count != 3
        {
            return Err(AcquisitionError::InvalidSettings);
        }
        Ok(Self {
            sample_rate_hz,
            resolution_bits,
            axis_count,
        })
    }

    pub const fn sample_rate_hz(self) -> u16 {
        self.sample_rate_hz
    }

    pub const fn resolution_bits(self) -> u8 {
        self.resolution_bits
    }

    pub const fn axis_count(self) -> u8 {
        self.axis_count
    }

    pub fn period_ns(self) -> u64 {
        NANOS_PER_SECOND / u64::from(self.sample_rate_hz)
    }
}

pub struct PrivatePpgBatch {
    device_time_ns: u64,
    host_monotonic_ns: u64,
    sample_period_ns: u64,
    settings: NegotiatedPpgSettings,
    samples: Box<[i32]>,
}

impl PrivatePpgBatch {
    pub fn new(
        device_time_ns: u64,
        host_monotonic_ns: u64,
        sample_period_ns: u64,
        settings: NegotiatedPpgSettings,
        samples: Vec<i32>,
    ) -> Result<Self, AcquisitionError> {
        validate_shape(
            samples.len(),
            usize::from(settings.channel_count),
            device_time_ns,
            sample_period_ns,
            settings.period_ns(),
        )?;
        Ok(Self {
            device_time_ns,
            host_monotonic_ns,
            sample_period_ns,
            settings,
            samples: samples.into_boxed_slice(),
        })
    }

    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }

    pub fn frame_count(&self) -> usize {
        self.samples.len() / usize::from(self.settings.channel_count)
    }

    pub const fn settings(&self) -> NegotiatedPpgSettings {
        self.settings
    }

    fn timing(&self) -> BatchTiming {
        BatchTiming {
            device_time_ns: self.device_time_ns,
            host_monotonic_ns: self.host_monotonic_ns,
        }
    }

    fn erase(&mut self) {
        self.samples.fill(0);
        self.device_time_ns = 0;
        self.host_monotonic_ns = 0;
        self.sample_period_ns = 0;
    }
}

impl fmt::Debug for PrivatePpgBatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivatePpgBatch")
            .field("frame_count", &self.frame_count())
            .field("channel_count", &self.settings.channel_count)
            .field("device_time_ns", &"REDACTED")
            .field("host_monotonic_ns", &"REDACTED")
            .field("samples", &"REDACTED")
            .finish()
    }
}

impl Drop for PrivatePpgBatch {
    fn drop(&mut self) {
        self.erase();
    }
}

pub struct PrivateAccBatch {
    device_time_ns: u64,
    host_monotonic_ns: u64,
    sample_period_ns: u64,
    settings: NegotiatedAccSettings,
    samples: Box<[i32]>,
}

impl PrivateAccBatch {
    pub fn new(
        device_time_ns: u64,
        host_monotonic_ns: u64,
        sample_period_ns: u64,
        settings: NegotiatedAccSettings,
        samples: Vec<i32>,
    ) -> Result<Self, AcquisitionError> {
        validate_shape(
            samples.len(),
            usize::from(settings.axis_count),
            device_time_ns,
            sample_period_ns,
            settings.period_ns(),
        )?;
        Ok(Self {
            device_time_ns,
            host_monotonic_ns,
            sample_period_ns,
            settings,
            samples: samples.into_boxed_slice(),
        })
    }

    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }

    pub fn frame_count(&self) -> usize {
        self.samples.len() / usize::from(self.settings.axis_count)
    }

    pub const fn settings(&self) -> NegotiatedAccSettings {
        self.settings
    }

    fn timing(&self) -> BatchTiming {
        BatchTiming {
            device_time_ns: self.device_time_ns,
            host_monotonic_ns: self.host_monotonic_ns,
        }
    }

    fn erase(&mut self) {
        self.samples.fill(0);
        self.device_time_ns = 0;
        self.host_monotonic_ns = 0;
        self.sample_period_ns = 0;
    }
}

impl fmt::Debug for PrivateAccBatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateAccBatch")
            .field("frame_count", &self.frame_count())
            .field("axis_count", &self.settings.axis_count)
            .field("device_time_ns", &"REDACTED")
            .field("host_monotonic_ns", &"REDACTED")
            .field("samples", &"REDACTED")
            .finish()
    }
}

impl Drop for PrivateAccBatch {
    fn drop(&mut self) {
        self.erase();
    }
}

fn validate_shape(
    sample_count: usize,
    dimensions: usize,
    device_time_ns: u64,
    sample_period_ns: u64,
    expected_period_ns: u64,
) -> Result<(), AcquisitionError> {
    if sample_count == 0 {
        return Err(AcquisitionError::EmptyBatch);
    }
    if sample_count > MAX_SAMPLES_PER_BATCH {
        return Err(AcquisitionError::BatchTooLarge);
    }
    if dimensions == 0 || sample_count % dimensions != 0 {
        return Err(AcquisitionError::InvalidDimensions);
    }
    if sample_period_ns == 0 || sample_period_ns.abs_diff(expected_period_ns) > 1 {
        return Err(AcquisitionError::SamplePeriodMismatch);
    }
    let frames = sample_count / dimensions;
    let frame_span = u64::try_from(frames - 1)
        .ok()
        .and_then(|count| count.checked_mul(sample_period_ns))
        .ok_or(AcquisitionError::TimestampOverflow)?;
    device_time_ns
        .checked_add(frame_span)
        .ok_or(AcquisitionError::TimestampOverflow)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionPhase {
    Reference,
    Calibration,
    Monitoring,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionState {
    Active(SessionPhase),
    Disconnected,
    Faulted,
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct SessionId([u8; 16]);

impl SessionId {
    pub fn new(value: [u8; 16]) -> Result<Self, AcquisitionError> {
        if value == [0; 16] {
            return Err(AcquisitionError::InvalidSessionId);
        }
        Ok(Self(value))
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionId(REDACTED)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceKind {
    SyntheticReplay,
    PolarVeritySense,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceDescriptor {
    kind: SourceKind,
    assurance: SourceAssurance,
}

impl SourceDescriptor {
    pub fn replay() -> Self {
        Self {
            kind: SourceKind::SyntheticReplay,
            assurance: SourceAssurance::synthetic_replay(),
        }
    }

    pub fn polar_verity_sense() -> Self {
        Self {
            kind: SourceKind::PolarVeritySense,
            assurance: PolarSourceClaim::from_observed_paired_session().maximum_assurance(),
        }
    }

    pub const fn kind(self) -> SourceKind {
        self.kind
    }

    pub const fn assurance(self) -> SourceAssurance {
        self.assurance
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionConfig {
    pub max_retained_batches: usize,
    pub max_retained_samples: usize,
    pub max_gap_ns: u64,
    pub max_clock_drift_ns: u64,
}

impl SessionConfig {
    pub fn validate(self) -> Result<Self, AcquisitionError> {
        if self.max_retained_batches == 0
            || self.max_retained_batches > MAX_RETAINED_BATCHES
            || self.max_retained_samples == 0
            || self.max_retained_samples > MAX_RETAINED_SAMPLES
            || self.max_gap_ns == 0
        {
            return Err(AcquisitionError::InvalidConfig);
        }
        Ok(self)
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_retained_batches: 64,
            max_retained_samples: 65_536,
            max_gap_ns: 5 * NANOS_PER_SECOND,
            max_clock_drift_ns: 250_000_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionStatus {
    pub state: SessionState,
    pub source: SourceKind,
    pub retained_batches: usize,
    pub retained_samples: usize,
}

#[derive(Clone, Copy)]
struct BatchTiming {
    device_time_ns: u64,
    host_monotonic_ns: u64,
}

#[derive(Clone, Copy, Default)]
struct ClockTrack {
    last: Option<BatchTiming>,
    max_observed_drift_ns: u64,
}

impl ClockTrack {
    fn candidate(
        self,
        timing: BatchTiming,
        config: SessionConfig,
    ) -> Result<Self, AcquisitionError> {
        if let Some(previous) = self.last {
            if timing.device_time_ns == previous.device_time_ns
                || timing.host_monotonic_ns == previous.host_monotonic_ns
            {
                return Err(AcquisitionError::DuplicateTimestamp);
            }
            if timing.device_time_ns < previous.device_time_ns
                || timing.host_monotonic_ns < previous.host_monotonic_ns
            {
                return Err(AcquisitionError::ClockRollback);
            }
            let device_delta = timing.device_time_ns - previous.device_time_ns;
            let host_delta = timing.host_monotonic_ns - previous.host_monotonic_ns;
            if device_delta > config.max_gap_ns || host_delta > config.max_gap_ns {
                return Err(AcquisitionError::ClockGap);
            }
            let drift = device_delta.abs_diff(host_delta);
            if drift > config.max_clock_drift_ns {
                return Err(AcquisitionError::ClockDrift);
            }
            return Ok(Self {
                last: Some(timing),
                max_observed_drift_ns: self.max_observed_drift_ns.max(drift),
            });
        }
        Ok(Self {
            last: Some(timing),
            max_observed_drift_ns: self.max_observed_drift_ns,
        })
    }
}

enum PrivateRecord {
    Ppg(PrivatePpgBatch),
    Acc(PrivateAccBatch),
}

impl PrivateRecord {
    fn sample_count(&self) -> usize {
        match self {
            Self::Ppg(batch) => batch.sample_count(),
            Self::Acc(batch) => batch.sample_count(),
        }
    }

    fn erase(&mut self) {
        match self {
            Self::Ppg(batch) => batch.erase(),
            Self::Acc(batch) => batch.erase(),
        }
    }
}

pub struct AcquisitionSession {
    id: SessionId,
    state: SessionState,
    source: SourceDescriptor,
    ppg_settings: Option<NegotiatedPpgSettings>,
    acc_settings: Option<NegotiatedAccSettings>,
    config: SessionConfig,
    ppg_clock: ClockTrack,
    acc_clock: ClockTrack,
    retained_samples: usize,
    transcript: VecDeque<PrivateRecord>,
    next_feature_window_ns: Option<u64>,
    next_feature_ordinal: u64,
}

impl AcquisitionSession {
    pub fn start(
        id: SessionId,
        phase: SessionPhase,
        source: SourceDescriptor,
        ppg_settings: Option<NegotiatedPpgSettings>,
        acc_settings: Option<NegotiatedAccSettings>,
        config: SessionConfig,
    ) -> Result<Self, AcquisitionError> {
        if ppg_settings.is_none() && acc_settings.is_none() {
            return Err(AcquisitionError::NoNegotiatedStream);
        }
        Ok(Self {
            id,
            state: SessionState::Active(phase),
            source,
            ppg_settings,
            acc_settings,
            config: config.validate()?,
            ppg_clock: ClockTrack::default(),
            acc_clock: ClockTrack::default(),
            retained_samples: 0,
            transcript: VecDeque::new(),
            next_feature_window_ns: None,
            next_feature_ordinal: 0,
        })
    }

    pub fn ingest_ppg(&mut self, batch: PrivatePpgBatch) -> Result<(), AcquisitionError> {
        self.require_active()?;
        if self.ppg_settings != Some(batch.settings()) {
            return Err(AcquisitionError::NegotiatedSettingsChanged);
        }
        let clock = self.ppg_clock.candidate(batch.timing(), self.config)?;
        self.prepare_capacity(batch.sample_count())?;
        if self.next_feature_window_ns.is_none() {
            self.next_feature_window_ns = Some(batch.device_time_ns);
        }
        self.ppg_clock = clock;
        self.push(PrivateRecord::Ppg(batch));
        Ok(())
    }

    pub fn ingest_acc(&mut self, batch: PrivateAccBatch) -> Result<(), AcquisitionError> {
        self.require_active()?;
        if self.acc_settings != Some(batch.settings()) {
            return Err(AcquisitionError::NegotiatedSettingsChanged);
        }
        let clock = self.acc_clock.candidate(batch.timing(), self.config)?;
        self.prepare_capacity(batch.sample_count())?;
        self.acc_clock = clock;
        self.push(PrivateRecord::Acc(batch));
        Ok(())
    }

    pub fn disconnect(&mut self) {
        self.erase_transcript();
        self.ppg_clock = ClockTrack::default();
        self.acc_clock = ClockTrack::default();
        self.state = SessionState::Disconnected;
        self.next_feature_window_ns = None;
    }

    pub fn fault(&mut self) {
        self.erase_transcript();
        self.ppg_clock = ClockTrack::default();
        self.acc_clock = ClockTrack::default();
        self.state = SessionState::Faulted;
        self.next_feature_window_ns = None;
    }

    pub fn status(&self) -> SessionStatus {
        SessionStatus {
            state: self.state,
            source: self.source.kind(),
            retained_batches: self.transcript.len(),
            retained_samples: self.retained_samples,
        }
    }

    pub const fn source_assurance(&self) -> SourceAssurance {
        self.source.assurance()
    }

    pub fn extract_next_feature_window(
        &mut self,
    ) -> Result<PrivateFeatureWindow, AcquisitionError> {
        self.require_active()?;
        let settings = self
            .ppg_settings
            .ok_or(AcquisitionError::PpgStreamRequired)?;
        let start_ns = self
            .next_feature_window_ns
            .ok_or(AcquisitionError::WindowNotReady)?;
        let end_ns = start_ns
            .checked_add(FEATURE_WINDOW_NS)
            .ok_or(AcquisitionError::TimestampOverflow)?;

        let latest_ppg_ns = self
            .transcript
            .iter()
            .filter_map(|record| match record {
                PrivateRecord::Ppg(batch) => batch.device_time_ns.checked_add(
                    u64::try_from(batch.frame_count().saturating_sub(1))
                        .ok()?
                        .checked_mul(batch.sample_period_ns)?,
                ),
                PrivateRecord::Acc(_) => None,
            })
            .max()
            .ok_or(AcquisitionError::WindowNotReady)?;
        if latest_ppg_ns.saturating_add(settings.period_ns()) < end_ns {
            return Err(AcquisitionError::WindowNotReady);
        }

        let mut ppg_samples = Vec::new();
        for record in &self.transcript {
            let PrivateRecord::Ppg(batch) = record else {
                continue;
            };
            let channels = usize::from(batch.settings.channel_count());
            for frame in 0..batch.frame_count() {
                let timestamp = batch.device_time_ns
                    + u64::try_from(frame).map_err(|_| AcquisitionError::TimestampOverflow)?
                        * batch.sample_period_ns;
                if (start_ns..end_ns).contains(&timestamp) {
                    let offset = frame * channels;
                    ppg_samples.extend_from_slice(&batch.samples[offset..offset + channels]);
                }
            }
        }

        let mut acc_samples = Vec::new();
        if self.acc_settings.is_some() {
            for record in &self.transcript {
                let PrivateRecord::Acc(batch) = record else {
                    continue;
                };
                let axes = usize::from(batch.settings.axis_count());
                for frame in 0..batch.frame_count() {
                    let timestamp = batch.device_time_ns
                        + u64::try_from(frame).map_err(|_| AcquisitionError::TimestampOverflow)?
                            * batch.sample_period_ns;
                    if (start_ns..end_ns).contains(&timestamp) {
                        let offset = frame * axes;
                        acc_samples.extend_from_slice(&batch.samples[offset..offset + axes]);
                    }
                }
            }
        }

        let drift_ratio = if self.config.max_clock_drift_ns == 0 {
            f64::from(self.ppg_clock.max_observed_drift_ns != 0)
        } else {
            self.ppg_clock.max_observed_drift_ns as f64 / self.config.max_clock_drift_ns as f64
        };
        let input = PrivateWindowInput::new(
            &ppg_samples,
            settings.channel_count(),
            settings.sample_rate_hz(),
            settings.resolution_bits(),
            if acc_samples.is_empty() {
                None
            } else {
                Some(acc_samples.as_slice())
            },
            self.acc_settings.map(NegotiatedAccSettings::sample_rate_hz),
            self.acc_settings
                .map(NegotiatedAccSettings::resolution_bits),
            drift_ratio,
        )
        .map_err(|_| AcquisitionError::FeatureExtractionFailed)?;
        let extracted = extract_private_features(input)
            .map_err(|_| AcquisitionError::FeatureExtractionFailed)?;
        let phase = match self.state {
            SessionState::Active(phase) => phase,
            SessionState::Disconnected | SessionState::Faulted => {
                return Err(AcquisitionError::SessionNotActive);
            }
        };
        let result = PrivateFeatureWindow {
            session_id: self.id,
            phase,
            ordinal: self.next_feature_ordinal,
            extracted,
        };
        self.next_feature_window_ns = Some(
            start_ns
                .checked_add(FEATURE_STRIDE_NS)
                .ok_or(AcquisitionError::TimestampOverflow)?,
        );
        self.next_feature_ordinal = self
            .next_feature_ordinal
            .checked_add(1)
            .ok_or(AcquisitionError::FeatureOrdinalOverflow)?;
        Ok(result)
    }

    fn require_active(&self) -> Result<(), AcquisitionError> {
        match self.state {
            SessionState::Active(_) => Ok(()),
            SessionState::Disconnected | SessionState::Faulted => {
                Err(AcquisitionError::SessionNotActive)
            }
        }
    }

    fn prepare_capacity(&self, incoming_samples: usize) -> Result<(), AcquisitionError> {
        if incoming_samples > self.config.max_retained_samples {
            return Err(AcquisitionError::BatchExceedsSessionCapacity);
        }
        self.retained_samples
            .checked_add(incoming_samples)
            .ok_or(AcquisitionError::SampleCountOverflow)?;
        Ok(())
    }

    fn push(&mut self, record: PrivateRecord) {
        let incoming_samples = record.sample_count();
        while self.transcript.len() >= self.config.max_retained_batches
            || self.retained_samples + incoming_samples > self.config.max_retained_samples
        {
            let mut removed = self
                .transcript
                .pop_front()
                .expect("capacity eviction requires a retained record");
            self.retained_samples -= removed.sample_count();
            removed.erase();
        }
        self.retained_samples += incoming_samples;
        self.transcript.push_back(record);
    }

    fn erase_transcript(&mut self) {
        for record in &mut self.transcript {
            record.erase();
        }
        self.transcript.clear();
        self.retained_samples = 0;
    }
}

/// Opaque feature result. Exact acquisition timestamps are intentionally not
/// available through this type.
///
/// ~~~compile_fail
/// use noticer_acquisition_core::PrivateFeatureWindow;
/// fn leak(window: &PrivateFeatureWindow) -> u64 { window.window_start_ns() }
/// ~~~
pub struct PrivateFeatureWindow {
    session_id: SessionId,
    phase: SessionPhase,
    ordinal: u64,
    extracted: noticer_ppg_features::ExtractedPrivateFeatures,
}

impl PrivateFeatureWindow {
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub const fn phase(&self) -> SessionPhase {
        self.phase
    }

    pub const fn ordinal(&self) -> u64 {
        self.ordinal
    }

    pub const fn schema(&self) -> FeatureSchema {
        self.extracted.schema()
    }

    pub const fn quality(&self) -> SignalQuality {
        self.extracted.quality()
    }

    pub const fn empirical_spoof_risk(&self) -> EmpiricalSpoofRisk {
        self.extracted.empirical_spoof_risk()
    }

    pub fn into_feature_vector(self) -> PrivateFeatureVector {
        self.extracted.into_feature_vector()
    }
}

impl fmt::Debug for PrivateFeatureWindow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateFeatureWindow")
            .field("session_id", &self.session_id)
            .field("phase", &self.phase)
            .field("ordinal", &self.ordinal)
            .field("schema", &self.schema())
            .field("quality", &self.quality())
            .field("empirical_spoof_risk", &self.empirical_spoof_risk())
            .field("exact_timing", &"REDACTED")
            .field("features", &"REDACTED")
            .finish()
    }
}

impl fmt::Debug for AcquisitionSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcquisitionSession")
            .field("id", &self.id)
            .field("state", &self.state)
            .field("source", &self.source.kind())
            .field("retained_batches", &self.transcript.len())
            .field("retained_samples", &self.retained_samples)
            .field("transcript", &"REDACTED")
            .finish()
    }
}

impl Drop for AcquisitionSession {
    fn drop(&mut self) {
        self.erase_transcript();
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AcquisitionError {
    #[error("negotiated settings are invalid")]
    InvalidSettings,
    #[error("batch is empty")]
    EmptyBatch,
    #[error("batch exceeds the hard sample limit")]
    BatchTooLarge,
    #[error("sample count does not match stream dimensions")]
    InvalidDimensions,
    #[error("sample period does not match negotiated settings")]
    SamplePeriodMismatch,
    #[error("batch timestamp range overflows")]
    TimestampOverflow,
    #[error("session identifier is invalid")]
    InvalidSessionId,
    #[error("session configuration is invalid")]
    InvalidConfig,
    #[error("session has no negotiated stream")]
    NoNegotiatedStream,
    #[error("batch timestamp duplicates the preceding timestamp")]
    DuplicateTimestamp,
    #[error("batch clock rolled backwards")]
    ClockRollback,
    #[error("batch clock gap exceeds policy")]
    ClockGap,
    #[error("device and host clocks drift beyond policy")]
    ClockDrift,
    #[error("batch settings differ from negotiated settings")]
    NegotiatedSettingsChanged,
    #[error("batch cannot fit in the bounded session")]
    BatchExceedsSessionCapacity,
    #[error("retained sample count overflows")]
    SampleCountOverflow,
    #[error("session is disconnected or faulted")]
    SessionNotActive,
    #[error("a PPG stream is required for feature extraction")]
    PpgStreamRequired,
    #[error("the next complete feature window is not available")]
    WindowNotReady,
    #[error("private feature extraction failed closed")]
    FeatureExtractionFailed,
    #[error("feature window ordinal overflowed")]
    FeatureOrdinalOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn ppg_settings() -> NegotiatedPpgSettings {
        NegotiatedPpgSettings::new(100, 22, 2).unwrap()
    }

    fn acc_settings() -> NegotiatedAccSettings {
        NegotiatedAccSettings::new(100, 16, 3).unwrap()
    }

    fn ppg(device_time_ns: u64, host_time_ns: u64, marker: i32) -> PrivatePpgBatch {
        let settings = ppg_settings();
        PrivatePpgBatch::new(
            device_time_ns,
            host_time_ns,
            settings.period_ns(),
            settings,
            vec![marker, marker + 1, marker + 2, marker + 3],
        )
        .unwrap()
    }

    fn session(config: SessionConfig) -> AcquisitionSession {
        AcquisitionSession::start(
            SessionId::new([7; 16]).unwrap(),
            SessionPhase::Monitoring,
            SourceDescriptor::replay(),
            Some(ppg_settings()),
            Some(acc_settings()),
            config,
        )
        .unwrap()
    }

    #[test]
    fn dimensions_count_period_and_overflow_are_rejected() {
        let ppg = ppg_settings();
        assert_eq!(
            PrivatePpgBatch::new(1, 1, ppg.period_ns(), ppg, vec![]).unwrap_err(),
            AcquisitionError::EmptyBatch
        );
        assert_eq!(
            PrivatePpgBatch::new(1, 1, ppg.period_ns(), ppg, vec![1, 2, 3]).unwrap_err(),
            AcquisitionError::InvalidDimensions
        );
        assert_eq!(
            PrivatePpgBatch::new(1, 1, ppg.period_ns() + 2, ppg, vec![1, 2]).unwrap_err(),
            AcquisitionError::SamplePeriodMismatch
        );
        assert_eq!(
            PrivatePpgBatch::new(u64::MAX, 1, ppg.period_ns(), ppg, vec![1, 2, 3, 4]).unwrap_err(),
            AcquisitionError::TimestampOverflow
        );
        let acc = acc_settings();
        assert_eq!(
            PrivateAccBatch::new(1, 1, acc.period_ns(), acc, vec![1, 2]).unwrap_err(),
            AcquisitionError::InvalidDimensions
        );
    }

    #[test]
    fn debug_redacts_raw_values_and_timestamps() {
        let batch = ppg(123_456_789, 987_654_321, 42_424_242);
        let output = format!("{batch:?}");
        assert!(output.contains("REDACTED"));
        assert!(!output.contains("42424242"));
        assert!(!output.contains("123456789"));
        assert!(!output.contains("987654321"));
    }

    #[test]
    fn invalid_batch_does_not_update_session_state() {
        let mut session = session(SessionConfig::default());
        session.ingest_ppg(ppg(1_000, 1_000, 10)).unwrap();
        let before = session.status();
        assert_eq!(
            session.ingest_ppg(ppg(1_000, 2_000, 20)).unwrap_err(),
            AcquisitionError::DuplicateTimestamp
        );
        assert_eq!(session.status(), before);
        session.ingest_ppg(ppg(2_000, 2_000, 30)).unwrap();
    }

    #[test]
    fn rollback_gap_and_drift_fail_closed() {
        let config = SessionConfig {
            max_gap_ns: 1_000,
            max_clock_drift_ns: 100,
            ..SessionConfig::default()
        };
        let mut rollback = session(config);
        rollback.ingest_ppg(ppg(1_000, 1_000, 1)).unwrap();
        assert_eq!(
            rollback.ingest_ppg(ppg(999, 1_100, 1)).unwrap_err(),
            AcquisitionError::ClockRollback
        );

        let mut gap = session(config);
        gap.ingest_ppg(ppg(1_000, 1_000, 1)).unwrap();
        assert_eq!(
            gap.ingest_ppg(ppg(2_001, 2_001, 1)).unwrap_err(),
            AcquisitionError::ClockGap
        );

        let mut drift = session(config);
        drift.ingest_ppg(ppg(1_000, 1_000, 1)).unwrap();
        assert_eq!(
            drift.ingest_ppg(ppg(1_500, 1_700, 1)).unwrap_err(),
            AcquisitionError::ClockDrift
        );
    }

    #[test]
    fn transcript_memory_is_bounded_and_disconnect_purges_it() {
        let config = SessionConfig {
            max_retained_batches: 2,
            max_retained_samples: 8,
            max_gap_ns: 10_000,
            max_clock_drift_ns: 0,
        };
        let mut session = session(config);
        for index in 1..=10 {
            session
                .ingest_ppg(ppg(index * 1_000, index * 1_000, index as i32))
                .unwrap();
            assert!(session.status().retained_batches <= 2);
            assert!(session.status().retained_samples <= 8);
        }
        session.disconnect();
        assert_eq!(session.status().state, SessionState::Disconnected);
        assert_eq!(session.status().retained_batches, 0);
        assert_eq!(session.status().retained_samples, 0);
        assert_eq!(
            session.ingest_ppg(ppg(11_000, 11_000, 11)).unwrap_err(),
            AcquisitionError::SessionNotActive
        );
    }

    #[test]
    fn phases_are_fixed_per_session_and_polar_claim_is_capped() {
        for phase in [
            SessionPhase::Reference,
            SessionPhase::Calibration,
            SessionPhase::Monitoring,
        ] {
            let session = AcquisitionSession::start(
                SessionId::new([phase as u8 + 1; 16]).unwrap(),
                phase,
                SourceDescriptor::polar_verity_sense(),
                Some(ppg_settings()),
                None,
                SessionConfig::default(),
            )
            .unwrap();
            assert_eq!(session.status().state, SessionState::Active(phase));
            assert_eq!(
                session.source_assurance(),
                SourceAssurance::paired_commercial_sensor()
            );
        }
    }

    #[test]
    fn four_second_windows_advance_by_public_ordinal_not_private_time() {
        let ppg_settings = NegotiatedPpgSettings::new(100, 22, 2).unwrap();
        let acc_settings = NegotiatedAccSettings::new(100, 16, 3).unwrap();
        let mut session = AcquisitionSession::start(
            SessionId::new([9; 16]).unwrap(),
            SessionPhase::Monitoring,
            SourceDescriptor::replay(),
            Some(ppg_settings),
            Some(acc_settings),
            SessionConfig::default(),
        )
        .unwrap();
        let ppg_samples = (0..400)
            .flat_map(|index| {
                let value = ((index % 20) - 10) * 1_000;
                [value, -value]
            })
            .collect();
        let acc_samples = (0..400).flat_map(|_| [10, 10, 10]).collect();
        session
            .ingest_ppg(
                PrivatePpgBatch::new(
                    71_234_567,
                    90_000_000,
                    ppg_settings.period_ns(),
                    ppg_settings,
                    ppg_samples,
                )
                .unwrap(),
            )
            .unwrap();
        session
            .ingest_acc(
                PrivateAccBatch::new(
                    71_234_567,
                    90_000_000,
                    acc_settings.period_ns(),
                    acc_settings,
                    acc_samples,
                )
                .unwrap(),
            )
            .unwrap();
        let window = session.extract_next_feature_window().unwrap();
        assert_eq!(window.ordinal(), 0);
        assert_eq!(window.schema(), FeatureSchema::PpgAccV1);
        let debug = format!("{window:?}");
        assert!(!debug.contains("71234567"));
        assert!(debug.contains("REDACTED"));
        assert_eq!(
            session.extract_next_feature_window().unwrap_err(),
            AcquisitionError::WindowNotReady
        );
    }

    proptest! {
        #[test]
        fn arbitrary_ppg_batch_never_panics(
            device_time in any::<u64>(),
            host_time in any::<u64>(),
            period in any::<u64>(),
            rate in any::<u16>(),
            resolution in any::<u8>(),
            channels in any::<u8>(),
            samples in proptest::collection::vec(any::<i32>(), 0..512),
        ) {
            if let Ok(settings) = NegotiatedPpgSettings::new(rate, resolution, channels) {
                let _ = PrivatePpgBatch::new(
                    device_time,
                    host_time,
                    period,
                    settings,
                    samples,
                );
            }
        }

        #[test]
        fn arbitrary_acc_batch_never_panics(
            device_time in any::<u64>(),
            host_time in any::<u64>(),
            period in any::<u64>(),
            rate in any::<u16>(),
            resolution in any::<u8>(),
            axes in any::<u8>(),
            samples in proptest::collection::vec(any::<i32>(), 0..512),
        ) {
            if let Ok(settings) = NegotiatedAccSettings::new(rate, resolution, axes) {
                let _ = PrivateAccBatch::new(
                    device_time,
                    host_time,
                    period,
                    settings,
                    samples,
                );
            }
        }
    }
}
