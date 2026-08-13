#![forbid(unsafe_code)]

//! One-way bridge from private acquisition windows into the K1 evidence
//! engine. Neither baseline values nor `EvidencePermit` cross this API.
//!
//! ~~~compile_fail
//! use noticer_evidence_bridge::EvidenceBridge;
//! fn leak(bridge: &EvidenceBridge) { let _ = &bridge.engine; }
//! ~~~

use std::fmt;

use noticer_acquisition_core::{PrivateFeatureWindow, SessionId, SessionPhase};
use noticer_baseline::{ContextKey, PrivateObservation, SignalQuality};
use noticer_evidence::{
    EmpiricalOnly, EvidenceDecision, EvidenceEngine, EvidencePermit, ExchangeabilityAssumed,
    NoPermitReason,
};
use noticer_types::LogicalSlot;
use rand_core::RngCore;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PublicAtypicalityDecision {
    Unknown = 0,
    Usual = 1,
    SlightlyDifferent = 2,
}

impl PublicAtypicalityDecision {
    pub const fn code(self) -> u8 {
        self as u8
    }

    pub const fn artifact_label(self) -> &'static str {
        match self {
            Self::Unknown => "UNKNOWN",
            Self::Usual => "USUAL",
            Self::SlightlyDifferent => "SLIGHTLY_DIFFERENT",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SanitizedDecision {
    decision: PublicAtypicalityDecision,
}

impl SanitizedDecision {
    pub const fn decision(self) -> PublicAtypicalityDecision {
        self.decision
    }

    pub const fn code(self) -> u8 {
        self.decision.code()
    }

    pub const fn artifact_label(self) -> &'static str {
        self.decision.artifact_label()
    }

    const fn unknown() -> Self {
        Self {
            decision: PublicAtypicalityDecision::Unknown,
        }
    }

    const fn usual() -> Self {
        Self {
            decision: PublicAtypicalityDecision::Usual,
        }
    }

    const fn slightly_different() -> Self {
        Self {
            decision: PublicAtypicalityDecision::SlightlyDifferent,
        }
    }
}

pub struct EvidenceBridge {
    expected_session: SessionId,
    expected_schema_id: Box<str>,
    context: ContextKey,
    slot_base: u64,
    engine: EvidenceEngine,
    pending_permit: Option<PendingEvidencePermit>,
    latched_slightly_different: bool,
}

impl EvidenceBridge {
    pub fn new(
        expected_session: SessionId,
        expected_schema_id: impl Into<Box<str>>,
        context: ContextKey,
        slot_base: u64,
        engine: EvidenceEngine,
    ) -> Result<Self, BridgeError> {
        let expected_schema_id = expected_schema_id.into();
        if expected_schema_id.is_empty() {
            return Err(BridgeError::InvalidSchemaBinding);
        }
        Ok(Self {
            expected_session,
            expected_schema_id,
            context,
            slot_base,
            engine,
            pending_permit: None,
            latched_slightly_different: false,
        })
    }

    pub fn process<R: RngCore>(
        &mut self,
        window: PrivateFeatureWindow,
        rng: &mut R,
    ) -> SanitizedDecision {
        if window.session_id() != self.expected_session
            || window.phase() != SessionPhase::Monitoring
            || window.schema().id() != self.expected_schema_id.as_ref()
            || window.quality() < SignalQuality::Usable
        {
            return SanitizedDecision::unknown();
        }
        let Some(slot) = self
            .slot_base
            .checked_add(window.ordinal())
            .map(LogicalSlot)
        else {
            return SanitizedDecision::unknown();
        };
        let observation = PrivateObservation::new(
            slot,
            self.context,
            window.quality(),
            window.into_feature_vector(),
        );
        match self.engine.process(&observation, rng) {
            EvidenceDecision::AssumptionBoundPermit(permit) => {
                self.pending_permit = Some(PendingEvidencePermit::AssumptionBound(permit));
                self.latched_slightly_different = true;
                SanitizedDecision::slightly_different()
            }
            EvidenceDecision::EmpiricalPermit(permit) => {
                self.pending_permit = Some(PendingEvidencePermit::Empirical(permit));
                self.latched_slightly_different = true;
                SanitizedDecision::slightly_different()
            }
            EvidenceDecision::NoPermit(NoPermitReason::EvidenceBelowThreshold)
            | EvidenceDecision::NoPermit(NoPermitReason::PersistenceInsufficient) => {
                SanitizedDecision::usual()
            }
            EvidenceDecision::NoPermit(NoPermitReason::AlreadyIssued)
                if self.latched_slightly_different =>
            {
                SanitizedDecision::slightly_different()
            }
            EvidenceDecision::NoPermit(_) | EvidenceDecision::Reject(_) => {
                SanitizedDecision::unknown()
            }
        }
    }

    pub const fn has_pending_internal_permit(&self) -> bool {
        self.pending_permit.is_some()
    }
}

impl fmt::Debug for EvidenceBridge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvidenceBridge")
            .field("expected_session", &self.expected_session)
            .field("expected_schema_id", &self.expected_schema_id)
            .field("context", &"REDACTED")
            .field("slot_base", &"REDACTED")
            .field("engine", &"REDACTED")
            .field(
                "pending_guarantee",
                &self
                    .pending_permit
                    .as_ref()
                    .map(PendingEvidencePermit::guarantee_class),
            )
            .finish()
    }
}

// The typed payload remains sealed until K5-09 consumes it through the
// production provenance guard. Dropping it here would sever the K1 path.
#[allow(dead_code)]
enum PendingEvidencePermit {
    AssumptionBound(EvidencePermit<ExchangeabilityAssumed>),
    Empirical(EvidencePermit<EmpiricalOnly>),
}

impl PendingEvidencePermit {
    fn guarantee_class(&self) -> &'static str {
        match self {
            Self::AssumptionBound(_) => "exchangeability_assumed",
            Self::Empirical(_) => "empirical_only",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BridgeError {
    #[error("feature schema binding must not be empty")]
    InvalidSchemaBinding,
}

#[cfg(test)]
mod tests {
    use super::*;
    use noticer_acquisition_core::{
        AcquisitionSession, NegotiatedAccSettings, NegotiatedPpgSettings, PrivateAccBatch,
        PrivatePpgBatch, SessionConfig, SourceDescriptor,
    };
    use noticer_baseline::{
        AnchorBaselineBuilder, BaselineConfig, BaselineRegistry, PrivateFeatureVector,
    };
    use noticer_evidence::{ContextConfig, EngineConfig, EvidenceConfig, PersistenceConfig};
    use noticer_ppg_features::FeatureSchema;
    use noticer_types::{ActionCode, PolicyHash};
    use rand_core::impls;

    struct FixedRng(u64);

    impl RngCore for FixedRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }

        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            self.0
        }

        fn fill_bytes(&mut self, destination: &mut [u8]) {
            impls::fill_bytes_via_next(self, destination);
        }

        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(destination);
            Ok(())
        }
    }

    fn private_feature(value: f64) -> PrivateFeatureVector {
        PrivateFeatureVector::new(vec![value; FeatureSchema::PpgAccV1.dimension()]).unwrap()
    }

    fn engine(context: ContextKey) -> EvidenceEngine {
        let mut builder = AnchorBaselineBuilder::new(BaselineConfig {
            minimum_reference_samples: 8,
            minimum_calibration_samples: 8,
            scale_floor: 1e-6,
            z_cap: 20.0,
        })
        .unwrap();
        for index in 0..8 {
            builder.add_reference(index, private_feature(index as f64 * 1e-7));
            builder.add_calibration(index + 100, private_feature(index as f64 * 1e-7));
        }
        let mut registry = BaselineRegistry::new(None);
        registry.insert(context, builder.build(1).unwrap());
        let context_config = ContextConfig {
            id: "monitoring".into(),
            alpha_weight: 1.0,
            fallback: false,
        };
        EvidenceEngine::new(
            EngineConfig {
                evidence: EvidenceConfig {
                    alpha_total: 0.9,
                    max_monitoring_steps: 64,
                    power_epsilons: vec![0.1],
                    power_weights: vec![1.0],
                },
                persistence: PersistenceConfig {
                    window: 1,
                    required_hits: 1,
                    p_max: 1.0,
                },
                contexts: vec![context_config],
                permit_ttl_slots: 3,
            },
            registry,
            vec![(context, 1.0)],
            ActionCode::MenfuguInflateSoft,
            PolicyHash([7; 32]),
        )
        .unwrap()
    }

    fn acquisition(
        id: SessionId,
        phase: SessionPhase,
        first_window_flatline: bool,
    ) -> AcquisitionSession {
        let ppg = NegotiatedPpgSettings::new(100, 22, 4).unwrap();
        let acc = NegotiatedAccSettings::new(100, 16, 3).unwrap();
        let mut session = AcquisitionSession::start(
            id,
            phase,
            SourceDescriptor::replay(),
            Some(ppg),
            Some(acc),
            SessionConfig::default(),
        )
        .unwrap();
        let ppg_samples = (0..600)
            .flat_map(|frame| {
                let value = if first_window_flatline && frame < 400 {
                    100
                } else {
                    ((frame % 25) - 12) * 2_000
                };
                [value, -value, value + 100, -value - 100]
            })
            .collect();
        let acc_samples = (0..600).flat_map(|_| [10, -10, 20]).collect();
        session
            .ingest_ppg(
                PrivatePpgBatch::new(1_000, 1_000, ppg.period_ns(), ppg, ppg_samples).unwrap(),
            )
            .unwrap();
        session
            .ingest_acc(
                PrivateAccBatch::new(1_000, 1_000, acc.period_ns(), acc, acc_samples).unwrap(),
            )
            .unwrap();
        session
    }

    #[test]
    fn valid_monitoring_window_runs_existing_k1_path_without_exposing_permit() {
        let id = SessionId::new([1; 16]).unwrap();
        let context = ContextKey::opaque(b"bridge-valid");
        let mut bridge = EvidenceBridge::new(
            id,
            FeatureSchema::PpgAccV1.id(),
            context,
            1_000,
            engine(context),
        )
        .unwrap();
        let window = acquisition(id, SessionPhase::Monitoring, false)
            .extract_next_feature_window()
            .unwrap();
        let decision = bridge.process(window, &mut FixedRng(7));
        assert_ne!(decision.decision(), PublicAtypicalityDecision::Unknown);
        if decision.decision() == PublicAtypicalityDecision::SlightlyDifferent {
            assert!(bridge.has_pending_internal_permit());
        }
    }

    #[test]
    fn bad_quality_does_not_advance_k1_before_next_valid_window() {
        let id = SessionId::new([2; 16]).unwrap();
        let context = ContextKey::opaque(b"bridge-quality");
        let mut bridge = EvidenceBridge::new(
            id,
            FeatureSchema::PpgAccV1.id(),
            context,
            2_000,
            engine(context),
        )
        .unwrap();
        let mut session = acquisition(id, SessionPhase::Monitoring, true);
        let bad = session.extract_next_feature_window().unwrap();
        assert_eq!(bad.quality(), SignalQuality::Bad);
        assert_eq!(
            bridge.process(bad, &mut FixedRng(1)).decision(),
            PublicAtypicalityDecision::Unknown
        );
        let valid = session.extract_next_feature_window().unwrap();
        assert!(valid.quality() >= SignalQuality::Usable);
        assert_ne!(
            bridge.process(valid, &mut FixedRng(1)).decision(),
            PublicAtypicalityDecision::Unknown
        );
    }

    #[test]
    fn session_phase_and_schema_mismatch_fail_closed() {
        let expected = SessionId::new([3; 16]).unwrap();
        let other = SessionId::new([4; 16]).unwrap();
        let context = ContextKey::opaque(b"bridge-split");
        let mut bridge = EvidenceBridge::new(
            expected,
            FeatureSchema::PpgAccV1.id(),
            context,
            3_000,
            engine(context),
        )
        .unwrap();
        let other_window = acquisition(other, SessionPhase::Monitoring, false)
            .extract_next_feature_window()
            .unwrap();
        assert_eq!(
            bridge.process(other_window, &mut FixedRng(2)).decision(),
            PublicAtypicalityDecision::Unknown
        );

        let reference_window = acquisition(expected, SessionPhase::Reference, false)
            .extract_next_feature_window()
            .unwrap();
        assert_eq!(
            bridge
                .process(reference_window, &mut FixedRng(2))
                .decision(),
            PublicAtypicalityDecision::Unknown
        );

        let mut wrong_schema = EvidenceBridge::new(
            expected,
            "noticer.ppg-acc.v999",
            context,
            3_000,
            engine(context),
        )
        .unwrap();
        let valid = acquisition(expected, SessionPhase::Monitoring, false)
            .extract_next_feature_window()
            .unwrap();
        assert_eq!(
            wrong_schema.process(valid, &mut FixedRng(2)).decision(),
            PublicAtypicalityDecision::Unknown
        );
    }

    #[test]
    fn android_surface_is_three_fixed_sanitized_codes() {
        assert_eq!(PublicAtypicalityDecision::Unknown.code(), 0);
        assert_eq!(PublicAtypicalityDecision::Usual.code(), 1);
        assert_eq!(PublicAtypicalityDecision::SlightlyDifferent.code(), 2);
        assert_eq!(
            PublicAtypicalityDecision::SlightlyDifferent.artifact_label(),
            "SLIGHTLY_DIFFERENT"
        );
    }
}
