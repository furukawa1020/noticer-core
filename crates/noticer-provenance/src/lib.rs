#![forbid(unsafe_code)]

//! Conservative, product-ordered provenance assurance.
//!
//! Strong assurance values are opaque. Adapters may return only the maximum
//! value their verified evidence supports.
//!
//! A Polar adapter cannot construct sensor-signed assurance:
//!
//! ~~~compile_fail
//! use noticer_provenance::SourceAssurance;
//! let _ = SourceAssurance::SensorSigned;
//! ~~~
//!
//! A software attester cannot construct StrongBox assurance:
//!
//! ~~~compile_fail
//! use noticer_provenance::CollectorKeyAssurance;
//! let _ = CollectorKeyAssurance::StrongBoxBacked;
//! ~~~

use noticer_types::PolicyHash;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;

macro_rules! assurance_axis {
    (
        $(#[$meta:meta])*
        $name:ident,
        $rank:ident,
        [$($variant:ident => $label:literal),+ $(,)?]
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub struct $name($rank);

        // Stronger ranks are deliberately reserved until a later verifier can
        // construct them from validated evidence.
        #[allow(dead_code)]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        #[repr(u8)]
        enum $rank {
            $($variant),+
        }

        impl $name {
            pub const fn dominates(self, required: Self) -> bool {
                self.0 as u8 >= required.0 as u8
            }

            pub const fn meet(self, other: Self) -> Self {
                if self.0 as u8 <= other.0 as u8 {
                    self
                } else {
                    other
                }
            }

            pub const fn join(self, other: Self) -> Self {
                if self.0 as u8 >= other.0 as u8 {
                    self
                } else {
                    other
                }
            }

            pub const fn label(self) -> &'static str {
                match self.0 {
                    $($rank::$variant => $label),+
                }
            }

            const fn rank(self) -> u8 {
                self.0 as u8
            }
        }
    };
}

assurance_axis!(
    /// Assurance about where samples were observed.
    SourceAssurance,
    SourceRank,
    [
        SyntheticReplay => "SyntheticReplay",
        LiveBleObserved => "LiveBleObserved",
        PairedCommercialSensor => "PairedCommercialSensor",
        SensorSigned => "SensorSigned",
    ]
);

impl SourceAssurance {
    pub const fn synthetic_replay() -> Self {
        Self(SourceRank::SyntheticReplay)
    }

    pub const fn live_ble_observed() -> Self {
        Self(SourceRank::LiveBleObserved)
    }

    pub const fn paired_commercial_sensor() -> Self {
        Self(SourceRank::PairedCommercialSensor)
    }
}

assurance_axis!(
    /// Assurance about the collector signing key.
    CollectorKeyAssurance,
    CollectorKeyRank,
    [
        Software => "Software",
        TeeBacked => "TeeBacked",
        StrongBoxBacked => "StrongBoxBacked",
    ]
);

impl CollectorKeyAssurance {
    pub const fn software() -> Self {
        Self(CollectorKeyRank::Software)
    }

    /// Constructs the result of a successful TEE key appraisal. A raw profile
    /// is not an authority token; production consumers require an opaque
    /// appraiser result in addition to this value.
    #[doc(hidden)]
    pub const fn appraised_tee_backed() -> Self {
        Self(CollectorKeyRank::TeeBacked)
    }

    /// See [`Self::appraised_tee_backed`].
    #[doc(hidden)]
    pub const fn appraised_strongbox_backed() -> Self {
        Self(CollectorKeyRank::StrongBoxBacked)
    }
}

assurance_axis!(
    /// Assurance about verified boot and device-lock state.
    BootStateAssurance,
    BootStateRank,
    [
        Unknown => "Unknown",
        Reported => "Reported",
        HardwareAttestedLocked => "HardwareAttestedLocked",
    ]
);

impl BootStateAssurance {
    pub const fn unknown() -> Self {
        Self(BootStateRank::Unknown)
    }

    pub const fn reported() -> Self {
        Self(BootStateRank::Reported)
    }

    /// Constructs a locked boot-state result after certificate-chain and
    /// reference-value appraisal.
    #[doc(hidden)]
    pub const fn appraised_hardware_locked() -> Self {
        Self(BootStateRank::HardwareAttestedLocked)
    }
}

assurance_axis!(
    /// Assurance that software identity is bound to the measured pipeline.
    PipelineAssurance,
    PipelineRank,
    [
        SelfDeclared => "SelfDeclared",
        StaticManifestBound => "StaticManifestBound",
        RuntimeProofOfExecution => "RuntimeProofOfExecution",
    ]
);

impl PipelineAssurance {
    pub const fn self_declared() -> Self {
        Self(PipelineRank::SelfDeclared)
    }

    /// Constructs a static manifest binding after app identity and pipeline
    /// reference-value appraisal.
    #[doc(hidden)]
    pub const fn appraised_static_manifest_bound() -> Self {
        Self(PipelineRank::StaticManifestBound)
    }

    /// Reserved for a future runtime proof verifier.
    #[doc(hidden)]
    pub const fn appraised_runtime_proof() -> Self {
        Self(PipelineRank::RuntimeProofOfExecution)
    }
}

assurance_axis!(
    /// Assurance that appraisal is fresh.
    FreshnessAssurance,
    FreshnessRank,
    [
        None => "None",
        LocalMonotonic => "LocalMonotonic",
        VerifierChallenge => "VerifierChallenge",
    ]
);

impl FreshnessAssurance {
    pub const fn none() -> Self {
        Self(FreshnessRank::None)
    }

    pub const fn local_monotonic() -> Self {
        Self(FreshnessRank::LocalMonotonic)
    }

    /// Constructs challenge freshness only after one-shot verifier challenge
    /// validation.
    #[doc(hidden)]
    pub const fn appraised_verifier_challenge() -> Self {
        Self(FreshnessRank::VerifierChallenge)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AssuranceProfile {
    pub source: SourceAssurance,
    pub collector_key: CollectorKeyAssurance,
    pub boot_state: BootStateAssurance,
    pub pipeline: PipelineAssurance,
    pub freshness: FreshnessAssurance,
}

impl AssuranceProfile {
    pub const fn lab_reference() -> Self {
        Self {
            source: SourceAssurance::synthetic_replay(),
            collector_key: CollectorKeyAssurance::software(),
            boot_state: BootStateAssurance::unknown(),
            pipeline: PipelineAssurance::self_declared(),
            freshness: FreshnessAssurance::none(),
        }
    }

    pub const fn meet(self, other: Self) -> Self {
        Self {
            source: self.source.meet(other.source),
            collector_key: self.collector_key.meet(other.collector_key),
            boot_state: self.boot_state.meet(other.boot_state),
            pipeline: self.pipeline.meet(other.pipeline),
            freshness: self.freshness.meet(other.freshness),
        }
    }

    pub const fn join(self, other: Self) -> Self {
        Self {
            source: self.source.join(other.source),
            collector_key: self.collector_key.join(other.collector_key),
            boot_state: self.boot_state.join(other.boot_state),
            pipeline: self.pipeline.join(other.pipeline),
            freshness: self.freshness.join(other.freshness),
        }
    }

    pub fn digest(self) -> AssuranceProfileDigest {
        let mut digest = Sha256::new();
        digest.update(b"NOTICER_ASSURANCE_PROFILE_V1");
        digest.update([
            self.source.rank(),
            self.collector_key.rank(),
            self.boot_state.rank(),
            self.pipeline.rank(),
            self.freshness.rank(),
        ]);
        AssuranceProfileDigest(digest.finalize().into())
    }
}

pub const fn dominates(actual: &AssuranceProfile, required: &AssuranceProfile) -> bool {
    actual.source.dominates(required.source)
        && actual.collector_key.dominates(required.collector_key)
        && actual.boot_state.dominates(required.boot_state)
        && actual.pipeline.dominates(required.pipeline)
        && actual.freshness.dominates(required.freshness)
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AssuranceProfileDigest(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ProvenanceMode {
    LabUnattested,
    #[default]
    ProductionRequired,
}

impl ProvenanceMode {
    pub const fn artifact_label(self) -> &'static str {
        match self {
            Self::LabUnattested => "LAB_UNATTESTED",
            Self::ProductionRequired => "PRODUCTION_REQUIRED",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolarSourceClaim {
    _private: (),
}

impl PolarSourceClaim {
    pub const fn from_observed_paired_session() -> Self {
        Self { _private: () }
    }

    pub const fn maximum_assurance(self) -> SourceAssurance {
        SourceAssurance::paired_commercial_sensor()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SoftwareAttesterClaim {
    _private: (),
}

impl SoftwareAttesterClaim {
    pub const fn new() -> Self {
        Self { _private: () }
    }

    pub const fn maximum_assurance(self) -> CollectorKeyAssurance {
        CollectorKeyAssurance::software()
    }
}

impl Default for SoftwareAttesterClaim {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PipelineMeasurementHash(pub [u8; 32]);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvenanceAppraisalPolicy {
    pub minimum_assurance: AssuranceProfile,
    pub approved_pipeline_hashes: BTreeSet<PipelineMeasurementHash>,
    pub approved_policy_hashes: BTreeSet<PolicyHash>,
    pub maximum_lease_slots: u32,
}

impl ProvenanceAppraisalPolicy {
    pub fn new(
        minimum_assurance: AssuranceProfile,
        approved_pipeline_hashes: BTreeSet<PipelineMeasurementHash>,
        approved_policy_hashes: BTreeSet<PolicyHash>,
        maximum_lease_slots: u32,
    ) -> Result<Self, AssurancePolicyError> {
        if maximum_lease_slots == 0 {
            return Err(AssurancePolicyError::ZeroLeaseLifetime);
        }
        Ok(Self {
            minimum_assurance,
            approved_pipeline_hashes,
            approved_policy_hashes,
            maximum_lease_slots,
        })
    }

    pub fn permits(
        &self,
        actual: &AssuranceProfile,
        pipeline: PipelineMeasurementHash,
        policy: PolicyHash,
    ) -> bool {
        dominates(actual, &self.minimum_assurance)
            && self.approved_pipeline_hashes.contains(&pipeline)
            && self.approved_policy_hashes.contains(&policy)
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AssurancePolicyError {
    #[error("maximum provenance lease lifetime must be nonzero")]
    ZeroLeaseLifetime,
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCES: [SourceAssurance; 4] = [
        SourceAssurance(SourceRank::SyntheticReplay),
        SourceAssurance(SourceRank::LiveBleObserved),
        SourceAssurance(SourceRank::PairedCommercialSensor),
        SourceAssurance(SourceRank::SensorSigned),
    ];
    const KEYS: [CollectorKeyAssurance; 3] = [
        CollectorKeyAssurance(CollectorKeyRank::Software),
        CollectorKeyAssurance(CollectorKeyRank::TeeBacked),
        CollectorKeyAssurance(CollectorKeyRank::StrongBoxBacked),
    ];
    const BOOTS: [BootStateAssurance; 3] = [
        BootStateAssurance(BootStateRank::Unknown),
        BootStateAssurance(BootStateRank::Reported),
        BootStateAssurance(BootStateRank::HardwareAttestedLocked),
    ];
    const PIPELINES: [PipelineAssurance; 3] = [
        PipelineAssurance(PipelineRank::SelfDeclared),
        PipelineAssurance(PipelineRank::StaticManifestBound),
        PipelineAssurance(PipelineRank::RuntimeProofOfExecution),
    ];
    const FRESHNESS: [FreshnessAssurance; 3] = [
        FreshnessAssurance(FreshnessRank::None),
        FreshnessAssurance(FreshnessRank::LocalMonotonic),
        FreshnessAssurance(FreshnessRank::VerifierChallenge),
    ];

    fn profiles() -> Vec<AssuranceProfile> {
        let mut profiles = Vec::with_capacity(324);
        for source in SOURCES {
            for collector_key in KEYS {
                for boot_state in BOOTS {
                    for pipeline in PIPELINES {
                        for freshness in FRESHNESS {
                            profiles.push(AssuranceProfile {
                                source,
                                collector_key,
                                boot_state,
                                pipeline,
                                freshness,
                            });
                        }
                    }
                }
            }
        }
        profiles
    }

    #[test]
    fn product_order_is_reflexive_and_antisymmetric() {
        let profiles = profiles();
        for profile in &profiles {
            assert!(dominates(profile, profile));
        }
        for left in &profiles {
            for right in &profiles {
                if dominates(left, right) && dominates(right, left) {
                    assert_eq!(left, right);
                }
            }
        }
    }

    #[test]
    fn every_axis_is_transitive() {
        macro_rules! check_axis {
            ($values:expr) => {
                for left in $values {
                    for middle in $values {
                        for right in $values {
                            if left.dominates(*middle) && middle.dominates(*right) {
                                assert!(left.dominates(*right));
                            }
                        }
                    }
                }
            };
        }
        check_axis!(&SOURCES);
        check_axis!(&KEYS);
        check_axis!(&BOOTS);
        check_axis!(&PIPELINES);
        check_axis!(&FRESHNESS);
    }

    #[test]
    fn meet_and_join_obey_product_lattice_laws() {
        let profiles = profiles();
        for left in &profiles {
            for right in &profiles {
                let meet = left.meet(*right);
                let join = left.join(*right);
                assert!(dominates(left, &meet));
                assert!(dominates(right, &meet));
                assert!(dominates(&join, left));
                assert!(dominates(&join, right));
                assert_eq!(left.meet(*right), right.meet(*left));
                assert_eq!(left.join(*right), right.join(*left));
                assert_eq!(left.meet(*left), *left);
                assert_eq!(left.join(*left), *left);
            }
        }
    }

    #[test]
    fn incomparable_profiles_are_not_collapsed_to_a_score() {
        let source_strong = AssuranceProfile {
            source: SourceAssurance::paired_commercial_sensor(),
            ..AssuranceProfile::lab_reference()
        };
        let freshness_strong = AssuranceProfile {
            freshness: FreshnessAssurance::local_monotonic(),
            ..AssuranceProfile::lab_reference()
        };
        assert!(!dominates(&source_strong, &freshness_strong));
        assert!(!dominates(&freshness_strong, &source_strong));
    }

    #[test]
    fn adapters_never_silently_upgrade_assurance() {
        let polar = PolarSourceClaim::from_observed_paired_session();
        assert_eq!(
            polar.maximum_assurance(),
            SourceAssurance::paired_commercial_sensor()
        );
        assert!(!polar
            .maximum_assurance()
            .dominates(SourceAssurance(SourceRank::SensorSigned)));

        let software = SoftwareAttesterClaim::new();
        assert_eq!(
            software.maximum_assurance(),
            CollectorKeyAssurance::software()
        );
        assert!(!software
            .maximum_assurance()
            .dominates(CollectorKeyAssurance(CollectorKeyRank::TeeBacked)));
    }

    #[test]
    fn production_is_default_and_lab_is_explicit() {
        assert_eq!(
            ProvenanceMode::default(),
            ProvenanceMode::ProductionRequired
        );
        assert_eq!(
            ProvenanceMode::LabUnattested.artifact_label(),
            "LAB_UNATTESTED"
        );
    }

    #[test]
    fn policy_checks_every_axis_and_both_allowlists() {
        let pipeline = PipelineMeasurementHash([1; 32]);
        let policy_hash = PolicyHash([2; 32]);
        let policy = ProvenanceAppraisalPolicy::new(
            AssuranceProfile::lab_reference(),
            BTreeSet::from([pipeline]),
            BTreeSet::from([policy_hash]),
            16,
        )
        .unwrap();
        assert!(policy.permits(&AssuranceProfile::lab_reference(), pipeline, policy_hash));
        assert!(!policy.permits(
            &AssuranceProfile::lab_reference(),
            PipelineMeasurementHash([9; 32]),
            policy_hash
        ));
        assert_eq!(
            ProvenanceAppraisalPolicy::new(
                AssuranceProfile::lab_reference(),
                BTreeSet::new(),
                BTreeSet::new(),
                0
            ),
            Err(AssurancePolicyError::ZeroLeaseLifetime)
        );
    }

    #[test]
    fn digest_is_domain_separated_and_component_sensitive() {
        let profile = AssuranceProfile::lab_reference();
        let stronger_source = AssuranceProfile {
            source: SourceAssurance::live_ble_observed(),
            ..profile
        };
        assert_eq!(profile.digest(), profile.digest());
        assert_ne!(profile.digest(), stronger_source.digest());
    }
}
