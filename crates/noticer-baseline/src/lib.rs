#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use noticer_types::LogicalSlot;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ContextKey([u8; 16]);

impl ContextKey {
    pub fn opaque(label: &[u8]) -> Self {
        let digest = Sha256::digest(label);
        let mut value = [0; 16];
        value.copy_from_slice(&digest[..16]);
        Self(value)
    }

    pub fn audit_id(self) -> String {
        self.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

impl fmt::Debug for ContextKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ContextKey(REDACTED)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum SignalQuality {
    Unknown,
    Bad,
    Usable,
    Good,
}

pub struct PrivateFeatureVector {
    values: Box<[f64]>,
}

impl PrivateFeatureVector {
    pub fn new(values: Vec<f64>) -> Result<Self, BaselineError> {
        if values.is_empty() {
            return Err(BaselineError::EmptyFeature);
        }
        if !values.iter().all(|value| value.is_finite()) {
            return Err(BaselineError::NonFiniteFeature);
        }
        Ok(Self {
            values: values.into_boxed_slice(),
        })
    }

    pub fn dimension(&self) -> usize {
        self.values.len()
    }
}

impl fmt::Debug for PrivateFeatureVector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateFeatureVector")
            .field("dimension", &self.dimension())
            .field("values", &"REDACTED")
            .finish()
    }
}

pub struct PrivateObservation {
    logical_slot: LogicalSlot,
    context: ContextKey,
    quality: SignalQuality,
    feature: PrivateFeatureVector,
}

impl PrivateObservation {
    pub fn new(
        logical_slot: LogicalSlot,
        context: ContextKey,
        quality: SignalQuality,
        feature: PrivateFeatureVector,
    ) -> Self {
        Self {
            logical_slot,
            context,
            quality,
            feature,
        }
    }

    pub fn logical_slot(&self) -> LogicalSlot {
        self.logical_slot
    }

    pub fn context(&self) -> ContextKey {
        self.context
    }

    pub fn quality(&self) -> SignalQuality {
        self.quality
    }
}

impl fmt::Debug for PrivateObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateObservation")
            .field("logical_slot", &self.logical_slot)
            .field("context", &self.context)
            .field("quality", &self.quality)
            .field("feature", &"REDACTED")
            .finish()
    }
}

#[derive(Clone, Copy)]
pub struct BaselineConfig {
    pub minimum_reference_samples: usize,
    pub minimum_calibration_samples: usize,
    pub scale_floor: f64,
    pub z_cap: f64,
}

impl BaselineConfig {
    pub fn validate(self) -> Result<Self, BaselineError> {
        if self.minimum_reference_samples == 0 || self.minimum_calibration_samples == 0 {
            return Err(BaselineError::InsufficientSamples);
        }
        if !self.scale_floor.is_finite() || self.scale_floor <= 0.0 {
            return Err(BaselineError::InvalidConfig);
        }
        if !self.z_cap.is_finite() || self.z_cap <= 0.0 {
            return Err(BaselineError::InvalidConfig);
        }
        Ok(self)
    }
}

#[derive(Debug, Error, PartialEq)]
pub enum BaselineError {
    #[error("feature vector must not be empty")]
    EmptyFeature,
    #[error("feature vector contains NaN or infinity")]
    NonFiniteFeature,
    #[error("feature dimension mismatch")]
    DimensionMismatch,
    #[error("reference and calibration sample IDs overlap")]
    SplitOverlap,
    #[error("insufficient baseline samples")]
    InsufficientSamples,
    #[error("invalid baseline configuration")]
    InvalidConfig,
    #[error("context baseline is unavailable")]
    ContextUnavailable,
    #[error("shadow baseline is frozen")]
    ShadowFrozen,
    #[error("shadow update exceeds security bound")]
    DivergenceExceeded,
    #[error("shadow update budget exhausted")]
    UpdateBudgetExhausted,
    #[error("rollback version is unavailable")]
    RollbackUnavailable,
}

pub struct AnchorBaselineBuilder {
    config: BaselineConfig,
    reference: Vec<(u64, PrivateFeatureVector)>,
    calibration: Vec<(u64, PrivateFeatureVector)>,
}

impl AnchorBaselineBuilder {
    pub fn new(config: BaselineConfig) -> Result<Self, BaselineError> {
        Ok(Self {
            config: config.validate()?,
            reference: Vec::new(),
            calibration: Vec::new(),
        })
    }

    pub fn add_reference(&mut self, sample_id: u64, sample: PrivateFeatureVector) {
        self.reference.push((sample_id, sample));
    }

    pub fn add_calibration(&mut self, sample_id: u64, sample: PrivateFeatureVector) {
        self.calibration.push((sample_id, sample));
    }

    pub fn build(self, version: u64) -> Result<AnchorBaseline, BaselineError> {
        if self.reference.len() < self.config.minimum_reference_samples
            || self.calibration.len() < self.config.minimum_calibration_samples
        {
            return Err(BaselineError::InsufficientSamples);
        }
        let reference_ids: HashSet<_> = self.reference.iter().map(|entry| entry.0).collect();
        if self
            .calibration
            .iter()
            .any(|entry| reference_ids.contains(&entry.0))
        {
            return Err(BaselineError::SplitOverlap);
        }
        let dimension = self.reference[0].1.dimension();
        if self
            .reference
            .iter()
            .chain(&self.calibration)
            .any(|entry| entry.1.dimension() != dimension)
        {
            return Err(BaselineError::DimensionMismatch);
        }
        let mut location = Vec::with_capacity(dimension);
        let mut scale = Vec::with_capacity(dimension);
        for column in 0..dimension {
            let values: Vec<_> = self
                .reference
                .iter()
                .map(|entry| entry.1.values[column])
                .collect();
            let center = median(values);
            let deviations: Vec<_> = self
                .reference
                .iter()
                .map(|entry| (entry.1.values[column] - center).abs())
                .collect();
            location.push(center);
            scale.push((1.4826 * median(deviations)).max(self.config.scale_floor));
        }
        let mut anchor = AnchorBaseline {
            version,
            location: location.into_boxed_slice(),
            scale: scale.into_boxed_slice(),
            calibration_scores: Vec::new().into_boxed_slice(),
            z_cap: self.config.z_cap,
        };
        let scores: Result<Vec<_>, _> = self
            .calibration
            .iter()
            .map(|entry| anchor.score(&entry.1))
            .collect();
        anchor.calibration_scores = scores?.into_boxed_slice();
        Ok(anchor)
    }
}

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(f64::total_cmp);
    let middle = values.len() / 2;
    if values.len() % 2 == 0 {
        (values[middle - 1] + values[middle]) / 2.0
    } else {
        values[middle]
    }
}

pub struct AnchorBaseline {
    version: u64,
    location: Box<[f64]>,
    scale: Box<[f64]>,
    calibration_scores: Box<[f64]>,
    z_cap: f64,
}

impl AnchorBaseline {
    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn dimension(&self) -> usize {
        self.location.len()
    }

    pub fn calibration_scores(&self) -> &[f64] {
        &self.calibration_scores
    }

    pub fn score(&self, feature: &PrivateFeatureVector) -> Result<f64, BaselineError> {
        if feature.dimension() != self.dimension() {
            return Err(BaselineError::DimensionMismatch);
        }
        let mean_square = feature
            .values
            .iter()
            .zip(&self.location)
            .zip(&self.scale)
            .map(|((&value, &location), &scale)| {
                let z = ((value - location) / scale).clamp(-self.z_cap, self.z_cap);
                z * z
            })
            .sum::<f64>()
            / self.dimension() as f64;
        let score = mean_square.sqrt();
        if score.is_finite() {
            Ok(score)
        } else {
            Err(BaselineError::NonFiniteFeature)
        }
    }

    pub fn score_observation(
        &self,
        observation: &PrivateObservation,
    ) -> Result<f64, BaselineError> {
        self.score(&observation.feature)
    }

    pub fn new_shadow(&self, rollback_depth: usize) -> ShadowBaseline {
        ShadowBaseline {
            location: self.location.to_vec(),
            versions: VecDeque::with_capacity(rollback_depth),
            rollback_depth,
            updates: 0,
            frozen: false,
        }
    }
}

impl fmt::Debug for AnchorBaseline {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AnchorBaseline")
            .field("version", &self.version)
            .field("dimension", &self.dimension())
            .field("private_statistics", &"REDACTED")
            .finish()
    }
}

pub struct BaselineRegistry {
    contexts: HashMap<ContextKey, AnchorBaseline>,
    global_fallback: Option<ContextKey>,
}

impl BaselineRegistry {
    pub fn new(global_fallback: Option<ContextKey>) -> Self {
        Self {
            contexts: HashMap::new(),
            global_fallback,
        }
    }

    pub fn insert(&mut self, context: ContextKey, baseline: AnchorBaseline) {
        self.contexts.insert(context, baseline);
    }

    pub fn resolve(&self, context: ContextKey) -> Result<(&AnchorBaseline, bool), BaselineError> {
        if let Some(baseline) = self.contexts.get(&context) {
            return Ok((baseline, false));
        }
        self.global_fallback
            .and_then(|fallback| self.contexts.get(&fallback))
            .map(|baseline| (baseline, true))
            .ok_or(BaselineError::ContextUnavailable)
    }
}

#[derive(Clone, Copy)]
pub struct ShadowConfig {
    pub learning_rate: f64,
    pub clip_z: f64,
    pub maximum_anchor_divergence: f64,
    pub maximum_updates_per_epoch: usize,
    pub rollback_depth: usize,
}

impl ShadowConfig {
    pub fn validate(self) -> Result<Self, BaselineError> {
        if !self.learning_rate.is_finite()
            || self.learning_rate <= 0.0
            || self.learning_rate > 1.0
            || !self.clip_z.is_finite()
            || self.clip_z <= 0.0
            || !self.maximum_anchor_divergence.is_finite()
            || self.maximum_anchor_divergence < 0.0
            || self.maximum_updates_per_epoch == 0
            || self.rollback_depth == 0
        {
            return Err(BaselineError::InvalidConfig);
        }
        Ok(self)
    }
}

pub struct ShadowBaseline {
    location: Vec<f64>,
    versions: VecDeque<Vec<f64>>,
    rollback_depth: usize,
    updates: usize,
    frozen: bool,
}

impl ShadowBaseline {
    pub fn update_observation(
        &mut self,
        observation: &PrivateObservation,
        anchor: &AnchorBaseline,
        config: ShadowConfig,
    ) -> Result<f64, BaselineError> {
        self.update(&observation.feature, anchor, config)
    }

    pub fn update(
        &mut self,
        feature: &PrivateFeatureVector,
        anchor: &AnchorBaseline,
        config: ShadowConfig,
    ) -> Result<f64, BaselineError> {
        let config = config.validate()?;
        if self.frozen {
            return Err(BaselineError::ShadowFrozen);
        }
        if feature.dimension() != anchor.dimension() {
            return Err(BaselineError::DimensionMismatch);
        }
        if self.updates >= config.maximum_updates_per_epoch {
            self.frozen = true;
            return Err(BaselineError::UpdateBudgetExhausted);
        }
        let previous = self.location.clone();
        for (((shadow, &value), &anchor_location), &scale) in self
            .location
            .iter_mut()
            .zip(&feature.values)
            .zip(&anchor.location)
            .zip(&anchor.scale)
        {
            let delta = (value - *shadow).clamp(-config.clip_z * scale, config.clip_z * scale);
            *shadow += config.learning_rate * delta;
            let divergence = (*shadow - anchor_location).abs() / scale;
            if divergence > config.maximum_anchor_divergence {
                self.location = previous;
                self.frozen = true;
                return Err(BaselineError::DivergenceExceeded);
            }
        }
        if self.rollback_depth > 0 {
            if self.versions.len() == self.rollback_depth {
                self.versions.pop_front();
            }
            self.versions.push_back(previous);
        }
        self.updates += 1;
        Ok(self.maximum_divergence(anchor))
    }

    pub fn rollback(&mut self) -> Result<(), BaselineError> {
        self.location = self
            .versions
            .pop_back()
            .ok_or(BaselineError::RollbackUnavailable)?;
        self.frozen = false;
        Ok(())
    }

    pub fn maximum_divergence(&self, anchor: &AnchorBaseline) -> f64 {
        self.location
            .iter()
            .zip(&anchor.location)
            .zip(&anchor.scale)
            .map(|((&shadow, &fixed), &scale)| (shadow - fixed).abs() / scale)
            .fold(0.0, f64::max)
    }

    pub fn is_frozen(&self) -> bool {
        self.frozen
    }
}

#[must_use]
pub struct RecalibrationProposal {
    old_version: u64,
    next_version: u64,
    context: ContextKey,
    observation_count: usize,
    divergence_category: u8,
    creation_slot: LogicalSlot,
}

impl RecalibrationProposal {
    pub fn sanitized_summary(&self) -> (u64, u64, String, usize, u8, LogicalSlot) {
        (
            self.old_version,
            self.next_version,
            self.context.audit_id(),
            self.observation_count,
            self.divergence_category,
            self.creation_slot,
        )
    }
}

pub fn propose_recalibration(
    anchor: &AnchorBaseline,
    context: ContextKey,
    observation_count: usize,
    divergence_category: u8,
    creation_slot: LogicalSlot,
) -> RecalibrationProposal {
    RecalibrationProposal {
        old_version: anchor.version,
        next_version: anchor.version.saturating_add(1),
        context,
        observation_count,
        divergence_category,
        creation_slot,
    }
}

pub fn approve_recalibration(
    proposal: RecalibrationProposal,
    builder: AnchorBaselineBuilder,
) -> Result<AnchorBaseline, BaselineError> {
    builder.build(proposal.next_version)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feature(value: f64) -> PrivateFeatureVector {
        PrivateFeatureVector::new(vec![value, value + 0.1]).unwrap()
    }

    fn anchor() -> AnchorBaseline {
        let mut builder = AnchorBaselineBuilder::new(BaselineConfig {
            minimum_reference_samples: 3,
            minimum_calibration_samples: 2,
            scale_floor: 0.01,
            z_cap: 20.0,
        })
        .unwrap();
        for id in 0..3 {
            builder.add_reference(id, feature(id as f64 * 0.1));
        }
        for id in 3..5 {
            builder.add_calibration(id, feature(id as f64 * 0.1));
        }
        builder.build(1).unwrap()
    }

    #[test]
    fn shadow_does_not_mutate_anchor() {
        let anchor = anchor();
        let before = anchor.score(&feature(1.0)).unwrap().to_bits();
        let mut shadow = anchor.new_shadow(4);
        let _ = shadow.update(
            &feature(0.2),
            &anchor,
            ShadowConfig {
                learning_rate: 0.01,
                clip_z: 2.5,
                maximum_anchor_divergence: 0.75,
                maximum_updates_per_epoch: 10,
                rollback_depth: 4,
            },
        );
        assert_eq!(before, anchor.score(&feature(1.0)).unwrap().to_bits());
    }

    #[test]
    fn split_overlap_is_rejected() {
        let mut builder = AnchorBaselineBuilder::new(BaselineConfig {
            minimum_reference_samples: 1,
            minimum_calibration_samples: 1,
            scale_floor: 0.01,
            z_cap: 20.0,
        })
        .unwrap();
        builder.add_reference(1, feature(0.0));
        builder.add_calibration(1, feature(0.1));
        assert_eq!(builder.build(1).unwrap_err(), BaselineError::SplitOverlap);
    }

    #[test]
    fn shadow_divergence_is_bounded_and_rollback_restores_state() {
        let anchor = anchor();
        let mut shadow = anchor.new_shadow(4);
        let config = ShadowConfig {
            learning_rate: 0.01,
            clip_z: 2.5,
            maximum_anchor_divergence: 0.75,
            maximum_updates_per_epoch: 20,
            rollback_depth: 4,
        };
        let before = shadow.maximum_divergence(&anchor);
        let after = shadow.update(&feature(0.2), &anchor, config).unwrap();
        assert!(after <= config.maximum_anchor_divergence);
        shadow.rollback().unwrap();
        assert_eq!(
            before.to_bits(),
            shadow.maximum_divergence(&anchor).to_bits()
        );
    }
}
