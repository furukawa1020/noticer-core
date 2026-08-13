#![forbid(unsafe_code)]

//! Deterministic, inspectable PPG/ACC features.
//!
//! `EmpiricalSpoofRisk` is an attack-fixture indicator. It is not proof that a
//! signal came from a genuine human or from a particular sensor.

use std::fmt;

pub use noticer_baseline::{PrivateFeatureVector, SignalQuality};
use thiserror::Error;

pub const FEATURE_WINDOW_NS: u64 = 4_000_000_000;
pub const FEATURE_STRIDE_NS: u64 = 2_000_000_000;
pub const MIN_PPG_COMPLETENESS: f64 = 0.95;
const MAX_PPG_CHANNELS: usize = 4;
const ACC_AXES: usize = 3;

pub const FEATURE_NAMES: [&str; 44] = [
    "ppg_ch1_mean",
    "ppg_ch1_std",
    "ppg_ch1_range",
    "ppg_ch1_lag1",
    "ppg_ch1_zero_crossing",
    "ppg_ch1_high_frequency_energy",
    "ppg_ch2_mean",
    "ppg_ch2_std",
    "ppg_ch2_range",
    "ppg_ch2_lag1",
    "ppg_ch2_zero_crossing",
    "ppg_ch2_high_frequency_energy",
    "ppg_ch3_mean",
    "ppg_ch3_std",
    "ppg_ch3_range",
    "ppg_ch3_lag1",
    "ppg_ch3_zero_crossing",
    "ppg_ch3_high_frequency_energy",
    "ppg_ch4_mean",
    "ppg_ch4_std",
    "ppg_ch4_range",
    "ppg_ch4_lag1",
    "ppg_ch4_zero_crossing",
    "ppg_ch4_high_frequency_energy",
    "ppg_corr_1_2",
    "ppg_corr_1_3",
    "ppg_corr_1_4",
    "ppg_corr_2_3",
    "ppg_corr_2_4",
    "ppg_corr_3_4",
    "acc_x_std",
    "acc_y_std",
    "acc_z_std",
    "acc_motion_rms",
    "acc_jerk_rms",
    "ppg_completeness",
    "acc_completeness",
    "stream_gap_ratio",
    "clock_drift_ratio",
    "flatline_indicator",
    "saturation_indicator",
    "ambient_indicator",
    "motion_indicator",
    "drift_indicator",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeatureSchema {
    PpgAccV1,
}

impl FeatureSchema {
    pub const fn id(self) -> &'static str {
        match self {
            Self::PpgAccV1 => "noticer.ppg-acc.v1",
        }
    }

    pub const fn dimension(self) -> usize {
        FEATURE_NAMES.len()
    }

    pub const fn names(self) -> &'static [&'static str] {
        &FEATURE_NAMES
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmpiricalSpoofRisk {
    Unknown,
    Low,
    Moderate,
    High,
}

pub struct PrivateWindowInput<'a> {
    ppg_samples: &'a [i32],
    ppg_channels: usize,
    ppg_rate_hz: usize,
    ppg_resolution_bits: u8,
    acc_samples: Option<&'a [i32]>,
    acc_rate_hz: Option<usize>,
    acc_resolution_bits: Option<u8>,
    clock_drift_ratio: f64,
}

impl<'a> PrivateWindowInput<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ppg_samples: &'a [i32],
        ppg_channels: u8,
        ppg_rate_hz: u16,
        ppg_resolution_bits: u8,
        acc_samples: Option<&'a [i32]>,
        acc_rate_hz: Option<u16>,
        acc_resolution_bits: Option<u8>,
        clock_drift_ratio: f64,
    ) -> Result<Self, FeatureError> {
        let ppg_channels = usize::from(ppg_channels);
        if !(1..=MAX_PPG_CHANNELS).contains(&ppg_channels)
            || ppg_rate_hz == 0
            || !(8..=32).contains(&ppg_resolution_bits)
            || ppg_samples.len() % ppg_channels != 0
            || !clock_drift_ratio.is_finite()
            || clock_drift_ratio < 0.0
        {
            return Err(FeatureError::InvalidInput);
        }
        match (acc_samples, acc_rate_hz, acc_resolution_bits) {
            (None, None, None) => {}
            (Some(samples), Some(rate), Some(bits))
                if rate > 0 && (8..=32).contains(&bits) && samples.len() % ACC_AXES == 0 => {}
            _ => return Err(FeatureError::InvalidInput),
        }
        Ok(Self {
            ppg_samples,
            ppg_channels,
            ppg_rate_hz: usize::from(ppg_rate_hz),
            ppg_resolution_bits,
            acc_samples,
            acc_rate_hz: acc_rate_hz.map(usize::from),
            acc_resolution_bits,
            clock_drift_ratio,
        })
    }
}

impl fmt::Debug for PrivateWindowInput<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateWindowInput")
            .field("ppg_channels", &self.ppg_channels)
            .field("ppg_samples", &"REDACTED")
            .field("acc_samples", &"REDACTED")
            .field("exact_timing", &"REDACTED")
            .finish()
    }
}

pub struct ExtractedPrivateFeatures {
    feature: PrivateFeatureVector,
    quality: SignalQuality,
    spoof_risk: EmpiricalSpoofRisk,
}

impl ExtractedPrivateFeatures {
    pub const fn schema(&self) -> FeatureSchema {
        FeatureSchema::PpgAccV1
    }

    pub const fn quality(&self) -> SignalQuality {
        self.quality
    }

    pub const fn empirical_spoof_risk(&self) -> EmpiricalSpoofRisk {
        self.spoof_risk
    }

    pub fn into_feature_vector(self) -> PrivateFeatureVector {
        self.feature
    }
}

impl fmt::Debug for ExtractedPrivateFeatures {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExtractedPrivateFeatures")
            .field("schema", &self.schema())
            .field("quality", &self.quality)
            .field("empirical_spoof_risk", &self.spoof_risk)
            .field("feature", &"REDACTED")
            .finish()
    }
}

pub fn extract_private_features(
    input: PrivateWindowInput<'_>,
) -> Result<ExtractedPrivateFeatures, FeatureError> {
    let computation = compute(&input)?;
    let quality = classify_quality(&computation);
    let spoof_risk = match quality {
        SignalQuality::Unknown => EmpiricalSpoofRisk::Unknown,
        SignalQuality::Bad => EmpiricalSpoofRisk::High,
        SignalQuality::Usable => EmpiricalSpoofRisk::Moderate,
        SignalQuality::Good => EmpiricalSpoofRisk::Low,
    };
    let feature = PrivateFeatureVector::new(computation.values)
        .map_err(|_| FeatureError::NonFiniteFeature)?;
    Ok(ExtractedPrivateFeatures {
        feature,
        quality,
        spoof_risk,
    })
}

struct Computation {
    values: Vec<f64>,
    ppg_completeness: f64,
    has_acc: bool,
    flatline: bool,
    saturation_fraction: f64,
    ambient: bool,
    motion: bool,
    drift: bool,
}

fn compute(input: &PrivateWindowInput<'_>) -> Result<Computation, FeatureError> {
    let expected_ppg_frames = input
        .ppg_rate_hz
        .checked_mul(4)
        .ok_or(FeatureError::InvalidInput)?;
    let ppg_frames = input.ppg_samples.len() / input.ppg_channels;
    let ppg_completeness = ratio(ppg_frames, expected_ppg_frames);
    let ppg_scale = full_scale(input.ppg_resolution_bits);

    let mut channels = Vec::with_capacity(MAX_PPG_CHANNELS);
    for channel in 0..MAX_PPG_CHANNELS {
        let values = if channel < input.ppg_channels {
            input
                .ppg_samples
                .iter()
                .skip(channel)
                .step_by(input.ppg_channels)
                .map(|sample| f64::from(*sample) / ppg_scale)
                .collect()
        } else {
            Vec::new()
        };
        channels.push(values);
    }

    let mut values = Vec::with_capacity(FEATURE_NAMES.len());
    let mut channel_stats = Vec::with_capacity(MAX_PPG_CHANNELS);
    for channel in &channels {
        let stats = statistics(channel);
        values.extend([
            stats.mean,
            stats.std,
            stats.range,
            stats.lag1,
            stats.zero_crossing,
            stats.high_frequency_energy,
        ]);
        channel_stats.push(stats);
    }
    for (left, right) in [(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)] {
        values.push(correlation(&channels[left], &channels[right]));
    }

    let (axis_std, motion_rms, jerk_rms, acc_completeness, has_acc) = acc_features(input)?;
    values.extend(axis_std);
    values.extend([motion_rms, jerk_rms]);

    let stream_gap_ratio = (1.0 - ppg_completeness).clamp(0.0, 1.0);
    let flatline = channel_stats
        .iter()
        .take(input.ppg_channels)
        .all(|stats| stats.std <= 1e-6 || stats.range <= 1e-5);
    let saturation_fraction = input
        .ppg_samples
        .iter()
        .filter(|sample| (f64::from(**sample) / ppg_scale).abs() >= 0.98)
        .count() as f64
        / input.ppg_samples.len().max(1) as f64;
    let ambient = input.ppg_channels == 4
        && channel_stats[3].std
            > channel_stats[..3]
                .iter()
                .map(|stats| stats.std)
                .sum::<f64>()
                / 3.0
                * 3.0
        && channel_stats[3].std > 0.02;
    let motion = motion_rms > 0.25 || jerk_rms > 0.15;
    let signal_drift = channel_stats
        .iter()
        .take(input.ppg_channels)
        .any(|stats| stats.endpoint_drift > 0.30);
    let drift = input.clock_drift_ratio > 1.0 || signal_drift;

    values.extend([
        ppg_completeness,
        acc_completeness,
        stream_gap_ratio,
        input.clock_drift_ratio,
        f64::from(flatline),
        saturation_fraction,
        f64::from(ambient),
        f64::from(motion),
        f64::from(drift),
    ]);
    if values.len() != FEATURE_NAMES.len() || !values.iter().all(|value| value.is_finite()) {
        return Err(FeatureError::NonFiniteFeature);
    }
    Ok(Computation {
        values,
        ppg_completeness,
        has_acc,
        flatline,
        saturation_fraction,
        ambient,
        motion,
        drift,
    })
}

fn classify_quality(computation: &Computation) -> SignalQuality {
    if computation.ppg_completeness < MIN_PPG_COMPLETENESS
        || computation.flatline
        || computation.saturation_fraction > 0.05
        || computation.ambient
        || computation.drift
    {
        SignalQuality::Bad
    } else if !computation.has_acc {
        SignalQuality::Unknown
    } else if computation.motion {
        SignalQuality::Usable
    } else {
        SignalQuality::Good
    }
}

fn acc_features(
    input: &PrivateWindowInput<'_>,
) -> Result<([f64; 3], f64, f64, f64, bool), FeatureError> {
    let Some(samples) = input.acc_samples else {
        return Ok(([0.0; 3], 0.0, 0.0, 0.0, false));
    };
    let rate = input.acc_rate_hz.ok_or(FeatureError::InvalidInput)?;
    let bits = input
        .acc_resolution_bits
        .ok_or(FeatureError::InvalidInput)?;
    let scale = full_scale(bits);
    let frames = samples.len() / ACC_AXES;
    let expected_frames = rate.checked_mul(4).ok_or(FeatureError::InvalidInput)?;
    let mut axes = [Vec::new(), Vec::new(), Vec::new()];
    for frame in samples.chunks_exact(ACC_AXES) {
        for axis in 0..ACC_AXES {
            axes[axis].push(f64::from(frame[axis]) / scale);
        }
    }
    let axis_std = [
        statistics(&axes[0]).std,
        statistics(&axes[1]).std,
        statistics(&axes[2]).std,
    ];
    let motion_rms = if frames == 0 {
        0.0
    } else {
        (samples
            .chunks_exact(ACC_AXES)
            .map(|frame| {
                frame
                    .iter()
                    .map(|value| (f64::from(*value) / scale).powi(2))
                    .sum::<f64>()
            })
            .sum::<f64>()
            / frames as f64)
            .sqrt()
    };
    let jerk_rms = if frames < 2 {
        0.0
    } else {
        (samples
            .chunks_exact(ACC_AXES)
            .zip(samples.chunks_exact(ACC_AXES).skip(1))
            .map(|(left, right)| {
                (0..ACC_AXES)
                    .map(|axis| ((f64::from(right[axis]) - f64::from(left[axis])) / scale).powi(2))
                    .sum::<f64>()
            })
            .sum::<f64>()
            / (frames - 1) as f64)
            .sqrt()
    };
    Ok((
        axis_std,
        motion_rms,
        jerk_rms,
        ratio(frames, expected_frames),
        true,
    ))
}

#[derive(Clone, Copy, Default)]
struct Statistics {
    mean: f64,
    std: f64,
    range: f64,
    lag1: f64,
    zero_crossing: f64,
    high_frequency_energy: f64,
    endpoint_drift: f64,
}

fn statistics(values: &[f64]) -> Statistics {
    if values.is_empty() {
        return Statistics::default();
    }
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let variance = values
        .iter()
        .map(|value| (value - mean).powi(2))
        .sum::<f64>()
        / values.len() as f64;
    let std = variance.sqrt();
    let (minimum, maximum) = values.iter().fold(
        (f64::INFINITY, f64::NEG_INFINITY),
        |(minimum, maximum), value| (minimum.min(*value), maximum.max(*value)),
    );
    let lag1 = if values.len() < 2 || variance <= f64::EPSILON {
        0.0
    } else {
        values
            .iter()
            .zip(values.iter().skip(1))
            .map(|(left, right)| (left - mean) * (right - mean))
            .sum::<f64>()
            / (values.len() - 1) as f64
            / variance
    };
    let zero_crossing = if values.len() < 2 {
        0.0
    } else {
        values
            .iter()
            .zip(values.iter().skip(1))
            .filter(|(left, right)| {
                (**left - mean).is_sign_positive() != (**right - mean).is_sign_positive()
            })
            .count() as f64
            / (values.len() - 1) as f64
    };
    let high_frequency_energy = if values.len() < 2 {
        0.0
    } else {
        values
            .iter()
            .zip(values.iter().skip(1))
            .map(|(left, right)| (right - left).powi(2))
            .sum::<f64>()
            / (values.len() - 1) as f64
    };
    Statistics {
        mean,
        std,
        range: maximum - minimum,
        lag1: lag1.clamp(-1.0, 1.0),
        zero_crossing,
        high_frequency_energy,
        endpoint_drift: (values[values.len() - 1] - values[0]).abs(),
    }
}

fn correlation(left: &[f64], right: &[f64]) -> f64 {
    let length = left.len().min(right.len());
    if length < 2 {
        return 0.0;
    }
    let left = &left[..length];
    let right = &right[..length];
    let left_stats = statistics(left);
    let right_stats = statistics(right);
    if left_stats.std <= f64::EPSILON || right_stats.std <= f64::EPSILON {
        return 0.0;
    }
    (left
        .iter()
        .zip(right)
        .map(|(left, right)| (left - left_stats.mean) * (right - right_stats.mean))
        .sum::<f64>()
        / length as f64
        / (left_stats.std * right_stats.std))
        .clamp(-1.0, 1.0)
}

fn ratio(actual: usize, expected: usize) -> f64 {
    if expected == 0 {
        0.0
    } else {
        (actual as f64 / expected as f64).clamp(0.0, 1.0)
    }
}

fn full_scale(bits: u8) -> f64 {
    if bits == 32 {
        f64::from(u32::MAX)
    } else {
        f64::from((1_u32 << bits) - 1)
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FeatureError {
    #[error("private feature input is malformed")]
    InvalidInput,
    #[error("feature computation produced a non-finite value")]
    NonFiniteFeature,
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn good_ppg(channels: usize, frames: usize) -> Vec<i32> {
        (0..frames)
            .flat_map(|frame| {
                (0..channels).map(move |channel| {
                    let wave = ((frame + channel * 3) % 25) as i32 - 12;
                    wave * (2_000 + channel as i32 * 100)
                })
            })
            .collect()
    }

    fn quiet_acc(frames: usize) -> Vec<i32> {
        (0..frames).flat_map(|_| [10, -10, 20]).collect()
    }

    fn input<'a>(ppg: &'a [i32], acc: Option<&'a [i32]>) -> PrivateWindowInput<'a> {
        PrivateWindowInput::new(ppg, 4, 100, 22, acc, acc.map(|_| 100), acc.map(|_| 16), 0.0)
            .unwrap()
    }

    #[test]
    fn schema_order_and_dimension_are_versioned() {
        let schema = FeatureSchema::PpgAccV1;
        assert_eq!(schema.id(), "noticer.ppg-acc.v1");
        assert_eq!(schema.dimension(), 44);
        assert_eq!(schema.names()[0], "ppg_ch1_mean");
        assert_eq!(schema.names()[24], "ppg_corr_1_2");
        assert_eq!(schema.names()[43], "drift_indicator");
    }

    #[test]
    fn computation_is_deterministic_and_finite() {
        let ppg = good_ppg(4, 400);
        let acc = quiet_acc(400);
        let left = compute(&input(&ppg, Some(&acc))).unwrap().values;
        let right = compute(&input(&ppg, Some(&acc))).unwrap().values;
        assert_eq!(left, right);
        assert!(left.iter().all(|value| value.is_finite()));
        assert_eq!(left.len(), FeatureSchema::PpgAccV1.dimension());
    }

    #[test]
    fn clean_fixture_is_good_but_not_a_human_proof() {
        let ppg = good_ppg(4, 400);
        let acc = quiet_acc(400);
        let output = extract_private_features(input(&ppg, Some(&acc))).unwrap();
        assert_eq!(output.quality(), SignalQuality::Good);
        assert_eq!(output.empirical_spoof_risk(), EmpiricalSpoofRisk::Low);
    }

    #[test]
    fn flatline_saturation_ambient_motion_drift_and_loss_are_detected() {
        let acc = quiet_acc(400);
        let flatline = vec![100; 400 * 4];
        assert_eq!(
            extract_private_features(input(&flatline, Some(&acc)))
                .unwrap()
                .quality(),
            SignalQuality::Bad
        );

        let saturation = vec![(1_i32 << 22) - 1; 400 * 4];
        assert_eq!(
            extract_private_features(input(&saturation, Some(&acc)))
                .unwrap()
                .quality(),
            SignalQuality::Bad
        );

        let mut ambient = good_ppg(4, 400);
        for frame in 0..400 {
            ambient[frame * 4 + 3] = if frame % 2 == 0 {
                1_000_000
            } else {
                -1_000_000
            };
        }
        assert_eq!(
            extract_private_features(input(&ambient, Some(&acc)))
                .unwrap()
                .quality(),
            SignalQuality::Bad
        );

        let ppg = good_ppg(4, 400);
        let moving_acc: Vec<i32> = (0..400)
            .flat_map(|frame| {
                let value = if frame % 2 == 0 { 20_000 } else { -20_000 };
                [value, -value, value]
            })
            .collect();
        assert_eq!(
            extract_private_features(input(&ppg, Some(&moving_acc)))
                .unwrap()
                .quality(),
            SignalQuality::Usable
        );

        let drift_input =
            PrivateWindowInput::new(&ppg, 4, 100, 22, Some(&acc), Some(100), Some(16), 1.1)
                .unwrap();
        assert_eq!(
            extract_private_features(drift_input).unwrap().quality(),
            SignalQuality::Bad
        );

        let incomplete = good_ppg(4, 379);
        assert_eq!(
            extract_private_features(input(&incomplete, Some(&acc)))
                .unwrap()
                .quality(),
            SignalQuality::Bad
        );
    }

    proptest! {
        #[test]
        fn accepted_inputs_only_produce_finite_feature_computations(
            samples in proptest::collection::vec(-2_000_000_i32..2_000_000_i32, 0..1600)
                .prop_filter("four-channel frames", |samples| samples.len() % 4 == 0),
            drift in 0.0_f64..2.0,
        ) {
            let input = PrivateWindowInput::new(&samples, 4, 100, 22, None, None, None, drift)
                .unwrap();
            let computation = compute(&input).unwrap();
            prop_assert_eq!(computation.values.len(), FEATURE_NAMES.len());
            prop_assert!(computation.values.iter().all(|value| value.is_finite()));
        }
    }
}
