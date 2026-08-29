use crate::{
    AdaptiveFuzzReport, AdaptiveHostProgram, CoverageFeedback, DeterministicCorpus,
    FuzzInconclusiveReason, FuzzVerdict, FuzzViolationKind, ShrinkInconclusiveReason, ShrinkReport,
    ShrinkVerdict,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

pub const ADAPTIVE_FUZZ_BUNDLE_SCHEMA: &str = "quotient-seal.adaptive-fuzz-reproduction-bundle.v1";

const BUNDLE_DOMAIN: &[u8] = b"QUOTIENT_SEAL_ADAPTIVE_FUZZ_REPRODUCTION_BUNDLE_V1";
const MAX_BUNDLE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BundleArtifactRole {
    FuzzReport,
    ActionProgram,
    CoverageFeedback { index: u32 },
    Corpus,
    ShrinkReport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleArtifactRef {
    pub role: BundleArtifactRole,
    pub artifact_sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BundleInconclusiveReason {
    Fuzz { reason: FuzzInconclusiveReason },
    Shrink { reason: ShrinkInconclusiveReason },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BundleVerdict {
    CounterexampleReproduced {
        kind: FuzzViolationKind,
        code: u16,
        one_minimal: bool,
    },
    Exhausted,
    Inconclusive {
        reason: BundleInconclusiveReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptiveFuzzReproductionBundle {
    pub schema: String,
    pub seed: u64,
    pub fuzz_report: AdaptiveFuzzReport,
    pub action_program: Option<AdaptiveHostProgram>,
    pub coverage_feedback: Vec<CoverageFeedback>,
    pub corpus: DeterministicCorpus,
    pub shrink_report: Option<ShrinkReport>,
    pub manifest: Vec<BundleArtifactRef>,
    pub verdict: BundleVerdict,
    pub reproduction_command: String,
    pub evidence_origin: String,
    pub hardware_status: String,
    pub artifact_sha256: [u8; 32],
}

impl AdaptiveFuzzReproductionBundle {
    pub fn build(
        fuzz_report: AdaptiveFuzzReport,
        action_program: Option<AdaptiveHostProgram>,
        coverage_feedback: Vec<CoverageFeedback>,
        corpus: DeterministicCorpus,
        shrink_report: Option<ShrinkReport>,
    ) -> Result<Self, BundleError> {
        validate_evidence(
            &fuzz_report,
            action_program.as_ref(),
            &coverage_feedback,
            &corpus,
            shrink_report.as_ref(),
        )?;
        let manifest = build_manifest(
            &fuzz_report,
            action_program.as_ref(),
            &coverage_feedback,
            &corpus,
            shrink_report.as_ref(),
        );
        let verdict = derive_verdict(&fuzz_report, shrink_report.as_ref())?;
        let mut bundle = Self {
            schema: ADAPTIVE_FUZZ_BUNDLE_SCHEMA.to_owned(),
            seed: fuzz_report.seed,
            fuzz_report,
            action_program,
            coverage_feedback,
            corpus,
            shrink_report,
            manifest,
            verdict,
            reproduction_command: "cargo run -p quotient-seal-fuzz --example adaptive_fuzz_bundle -- artifacts/quotient_seal/adaptive_fuzz_bundle.json".to_owned(),
            evidence_origin: "INJECTED_TEST_FIXTURE".to_owned(),
            hardware_status: "NOT_VERIFIED".to_owned(),
            artifact_sha256: [0; 32],
        };
        bundle.artifact_sha256 = bundle.recomputed_sha256()?;
        bundle.validate()?;
        Ok(bundle)
    }

    pub fn validate(&self) -> Result<(), BundleError> {
        if self.schema != ADAPTIVE_FUZZ_BUNDLE_SCHEMA
            || self.seed != self.fuzz_report.seed
            || self.reproduction_command
                != "cargo run -p quotient-seal-fuzz --example adaptive_fuzz_bundle -- artifacts/quotient_seal/adaptive_fuzz_bundle.json"
            || self.evidence_origin != "INJECTED_TEST_FIXTURE"
            || self.hardware_status != "NOT_VERIFIED"
        {
            return Err(BundleError::ArtifactMismatch);
        }
        validate_evidence(
            &self.fuzz_report,
            self.action_program.as_ref(),
            &self.coverage_feedback,
            &self.corpus,
            self.shrink_report.as_ref(),
        )?;
        let manifest = build_manifest(
            &self.fuzz_report,
            self.action_program.as_ref(),
            &self.coverage_feedback,
            &self.corpus,
            self.shrink_report.as_ref(),
        );
        if self.manifest != manifest
            || self.verdict != derive_verdict(&self.fuzz_report, self.shrink_report.as_ref())?
            || self.artifact_sha256 != self.recomputed_sha256()?
        {
            return Err(BundleError::ArtifactMismatch);
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, BundleError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| BundleError::Json)
    }

    pub fn decode_json(encoded: &[u8]) -> Result<Self, BundleError> {
        if encoded.is_empty() || encoded.len() > MAX_BUNDLE_BYTES {
            return Err(BundleError::Length);
        }
        let bundle: Self = serde_json::from_slice(encoded).map_err(|_| BundleError::Json)?;
        bundle.validate()?;
        if bundle.canonical_json()? != encoded {
            return Err(BundleError::NonCanonical);
        }
        Ok(bundle)
    }

    fn recomputed_sha256(&self) -> Result<[u8; 32], BundleError> {
        let mut value = self.clone();
        value.artifact_sha256 = [0; 32];
        let encoded = serde_json::to_vec(&value).map_err(|_| BundleError::Json)?;
        Ok(domain_hash(BUNDLE_DOMAIN, &encoded))
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BundleError {
    #[error("adaptive fuzz bundle evidence is inconsistent")]
    EvidenceMismatch,
    #[error("adaptive fuzz bundle is missing required action evidence")]
    MissingActionProgram,
    #[error("adaptive fuzz counterexample is missing shrink evidence")]
    MissingShrinkReport,
    #[error("adaptive fuzz bundle contains unexpected shrink evidence")]
    UnexpectedShrinkReport,
    #[error("adaptive fuzz bundle failed full recomputation")]
    ArtifactMismatch,
    #[error("adaptive fuzz bundle JSON is invalid")]
    Json,
    #[error("adaptive fuzz bundle JSON is not canonical")]
    NonCanonical,
    #[error("adaptive fuzz bundle exceeds its byte bound")]
    Length,
}

fn validate_evidence(
    fuzz_report: &AdaptiveFuzzReport,
    action_program: Option<&AdaptiveHostProgram>,
    coverage_feedback: &[CoverageFeedback],
    corpus: &DeterministicCorpus,
    shrink_report: Option<&ShrinkReport>,
) -> Result<(), BundleError> {
    fuzz_report
        .validate()
        .map_err(|_| BundleError::EvidenceMismatch)?;
    corpus
        .validate()
        .map_err(|_| BundleError::EvidenceMismatch)?;
    if fuzz_report.seed != corpus.seed
        || fuzz_report.corpus_bounds != corpus.bounds
        || fuzz_report.final_corpus_sha256 != corpus.artifact_sha256
        || fuzz_report.steps.len() != coverage_feedback.len()
    {
        return Err(BundleError::EvidenceMismatch);
    }
    for (step, feedback) in fuzz_report.steps.iter().zip(coverage_feedback) {
        feedback
            .validate()
            .map_err(|_| BundleError::EvidenceMismatch)?;
        if step.coverage_feedback_sha256 != feedback.feedback_sha256 {
            return Err(BundleError::EvidenceMismatch);
        }
        for record in &feedback.records {
            let Some(global) = corpus
                .global_coverage
                .iter()
                .find(|global| global.coverage_id == record.coverage_id)
            else {
                return Err(BundleError::EvidenceMismatch);
            };
            if global != record {
                return Err(BundleError::EvidenceMismatch);
            }
        }
    }

    if fuzz_report.steps.is_empty() {
        if action_program.is_some() {
            return Err(BundleError::EvidenceMismatch);
        }
    } else {
        let program = action_program.ok_or(BundleError::MissingActionProgram)?;
        program
            .validate()
            .map_err(|_| BundleError::EvidenceMismatch)?;
        let actions: Vec<_> = fuzz_report.steps.iter().map(|step| step.action).collect();
        if program.seed != fuzz_report.seed
            || program.bounds != fuzz_report.context_bounds
            || program.actions != actions
            || fuzz_report
                .steps
                .last()
                .is_none_or(|step| step.action_program_sha256 != program.artifact_sha256)
        {
            return Err(BundleError::EvidenceMismatch);
        }
    }

    match fuzz_report.verdict {
        FuzzVerdict::Counterexample { counterexample } => {
            let shrink = shrink_report.ok_or(BundleError::MissingShrinkReport)?;
            let program = action_program.ok_or(BundleError::MissingActionProgram)?;
            shrink
                .validate()
                .map_err(|_| BundleError::EvidenceMismatch)?;
            if shrink.seed != fuzz_report.seed
                || shrink.original_program_sha256 != program.artifact_sha256
                || shrink.expected_kind != counterexample.kind
                || shrink.expected_code != counterexample.code
            {
                return Err(BundleError::EvidenceMismatch);
            }
        }
        FuzzVerdict::Exhausted | FuzzVerdict::Inconclusive { .. } => {
            if shrink_report.is_some() {
                return Err(BundleError::UnexpectedShrinkReport);
            }
        }
    }
    Ok(())
}

fn derive_verdict(
    fuzz_report: &AdaptiveFuzzReport,
    shrink_report: Option<&ShrinkReport>,
) -> Result<BundleVerdict, BundleError> {
    match fuzz_report.verdict {
        FuzzVerdict::Counterexample { counterexample } => {
            let shrink = shrink_report.ok_or(BundleError::MissingShrinkReport)?;
            match shrink.verdict {
                ShrinkVerdict::Reproduced { one_minimal } => {
                    Ok(BundleVerdict::CounterexampleReproduced {
                        kind: counterexample.kind,
                        code: counterexample.code,
                        one_minimal,
                    })
                }
                ShrinkVerdict::Inconclusive { reason } => Ok(BundleVerdict::Inconclusive {
                    reason: BundleInconclusiveReason::Shrink { reason },
                }),
            }
        }
        FuzzVerdict::Exhausted => Ok(BundleVerdict::Exhausted),
        FuzzVerdict::Inconclusive { reason } => Ok(BundleVerdict::Inconclusive {
            reason: BundleInconclusiveReason::Fuzz { reason },
        }),
    }
}

fn build_manifest(
    fuzz_report: &AdaptiveFuzzReport,
    action_program: Option<&AdaptiveHostProgram>,
    coverage_feedback: &[CoverageFeedback],
    corpus: &DeterministicCorpus,
    shrink_report: Option<&ShrinkReport>,
) -> Vec<BundleArtifactRef> {
    let mut manifest = vec![BundleArtifactRef {
        role: BundleArtifactRole::FuzzReport,
        artifact_sha256: fuzz_report.artifact_sha256,
    }];
    if let Some(program) = action_program {
        manifest.push(BundleArtifactRef {
            role: BundleArtifactRole::ActionProgram,
            artifact_sha256: program.artifact_sha256,
        });
    }
    manifest.extend(
        coverage_feedback
            .iter()
            .enumerate()
            .map(|(index, feedback)| BundleArtifactRef {
                role: BundleArtifactRole::CoverageFeedback {
                    index: index as u32,
                },
                artifact_sha256: feedback.feedback_sha256,
            }),
    );
    manifest.push(BundleArtifactRef {
        role: BundleArtifactRole::Corpus,
        artifact_sha256: corpus.artifact_sha256,
    });
    if let Some(shrink) = shrink_report {
        manifest.push(BundleArtifactRef {
            role: BundleArtifactRole::ShrinkReport,
            artifact_sha256: shrink.artifact_sha256,
        });
    }
    manifest
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}
