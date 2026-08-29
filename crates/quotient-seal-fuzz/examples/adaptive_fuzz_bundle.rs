use quotient_seal_fuzz::{
    apply_public_feedback, run_adaptive_fuzz, shrink_counterexample, AdaptiveActionClass,
    AdaptiveContextBounds, AdaptiveContextState, AdaptiveFuzzBudget, AdaptiveFuzzConfig,
    AdaptiveFuzzReport, AdaptiveFuzzReproductionBundle, AdaptiveHostAction, AdaptiveHostProgram,
    BundleVerdict, CorpusBounds, CorpusEntry, CoverageFeedback, DeterministicCorpus, FuzzVerdict,
    FuzzViolationKind, IndependentReplayChecker, PublicCoverageSnapshot, PublicFuzzInput,
    PublicFuzzTarget, PublicObserverDivergence, PublicTargetStatus, PublicTargetStep, ReplayResult,
    ShrinkBounds,
};
use std::env;
use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::PathBuf;

struct FixtureTarget;

impl PublicFuzzTarget for FixtureTarget {
    fn execute(&mut self, input: PublicFuzzInput) -> PublicTargetStep {
        let class = AdaptiveActionClass::of(input.action);
        let marker = class.code() + 1;
        let status = if class == AdaptiveActionClass::ServiceSwitch {
            PublicTargetStatus::Counterexample {
                kind: FuzzViolationKind::ObserverTraceDivergence,
                code: 41,
                public_witness_sha256: [0xa5; 32],
            }
        } else {
            PublicTargetStatus::Continue
        };
        PublicTargetStep {
            observation: quotient_seal_fuzz::AdaptivePublicObservation {
                event_count: 1,
                action_count: 1,
                trap_count: u32::from(class == AdaptiveActionClass::Malformed),
                host_call_count: 1,
                resource_units: 2,
                public_trace_sha256: [marker; 32],
            },
            coverage: PublicCoverageSnapshot {
                target_block: u32::from(marker),
                product_source_state: input.step,
                product_target_state: u32::from(marker),
                observer_divergence: (class == AdaptiveActionClass::ServiceSwitch).then_some(
                    PublicObserverDivergence {
                        observer_profile: 1,
                        divergence_code: 3,
                        public_trace_sha256: [marker; 32],
                    },
                ),
                utility_violation: None,
            },
            logical_time_units: 1,
            status,
        }
    }
}

struct SwitchChecker {
    witness: u8,
}

impl IndependentReplayChecker for SwitchChecker {
    fn replay(&mut self, program: &AdaptiveHostProgram) -> ReplayResult {
        if program
            .actions
            .iter()
            .any(|action| matches!(action, AdaptiveHostAction::ServiceSwitch { .. }))
        {
            ReplayResult::Violation {
                kind: FuzzViolationKind::ObserverTraceDivergence,
                code: 41,
                public_witness_sha256: [self.witness; 32],
            }
        } else {
            ReplayResult::NoViolation
        }
    }
}

fn config() -> AdaptiveFuzzConfig {
    AdaptiveFuzzConfig {
        seed: 0x5eed,
        context_bounds: AdaptiveContextBounds {
            max_steps: 16,
            max_service_alias: 4,
            max_repeat: 4,
            max_faults: 4,
            max_public_events: 64,
        },
        corpus_bounds: CorpusBounds {
            max_entries: 16,
            max_coverage_points: 256,
            max_actions_per_entry: 16,
        },
        budget: AdaptiveFuzzBudget {
            max_steps: 10,
            max_states: 16,
            max_logical_time_units: 100,
        },
    }
}

fn reconstruct(
    report: &AdaptiveFuzzReport,
) -> Result<
    (
        AdaptiveHostProgram,
        Vec<CoverageFeedback>,
        DeterministicCorpus,
    ),
    Box<dyn Error>,
> {
    let mut target = FixtureTarget;
    let mut state = AdaptiveContextState::initial(report.context_bounds)?;
    let mut corpus = DeterministicCorpus::new(report.seed, report.corpus_bounds)?;
    let mut actions = Vec::new();
    let mut feedbacks = Vec::new();
    for step in &report.steps {
        let output = target.execute(PublicFuzzInput {
            step: step.index,
            state,
            action: step.action,
        });
        let transition = apply_public_feedback(state, step.action, output.observation)?;
        let feedback = CoverageFeedback::from_public_transition(&transition, output.coverage)?;
        actions.push(step.action);
        let program =
            AdaptiveHostProgram::build(report.seed, report.context_bounds, actions.clone())?;
        corpus.insert(CorpusEntry::build(
            report.seed,
            program.artifact_sha256,
            actions.len() as u32,
            feedback.clone(),
        )?)?;
        feedbacks.push(feedback);
        state = transition.after;
    }
    if actions.is_empty() {
        return Err(io::Error::other("fixture produced no actions").into());
    }
    let program = AdaptiveHostProgram::build(report.seed, report.context_bounds, actions)?;
    Ok((program, feedbacks, corpus))
}

fn to_hex(bytes: [u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn main() -> Result<(), Box<dyn Error>> {
    let output_path = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("artifacts/quotient_seal/adaptive_fuzz_bundle.json"));
    let mut target = FixtureTarget;
    let report = run_adaptive_fuzz(config(), &mut target)?;
    let expected = match report.verdict {
        FuzzVerdict::Counterexample { counterexample } => counterexample,
        _ => return Err(io::Error::other("fixture did not produce a counterexample").into()),
    };
    let (program, feedback, corpus) = reconstruct(&report)?;
    let mut primary = SwitchChecker { witness: 1 };
    let mut secondary = SwitchChecker { witness: 2 };
    let shrink = shrink_counterexample(
        &program,
        expected,
        ShrinkBounds {
            max_actions: 16,
            max_replay_attempts: 128,
        },
        &mut primary,
        &mut secondary,
    )?;
    let bundle = AdaptiveFuzzReproductionBundle::build(
        report,
        Some(program),
        feedback,
        corpus,
        Some(shrink),
    )?;
    if let Some(parent) = output_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(&output_path, bundle.canonical_json()?)?;

    let verdict = match bundle.verdict {
        BundleVerdict::CounterexampleReproduced { .. } => "COUNTEREXAMPLE_REPRODUCED",
        BundleVerdict::Exhausted => "EXHAUSTED",
        BundleVerdict::Inconclusive { .. } => "INCONCLUSIVE",
    };
    let minimized_actions = bundle
        .shrink_report
        .as_ref()
        .map_or(0, |report| report.minimized_program.actions.len());
    println!("verdict={verdict}");
    println!("evidence_origin={}", bundle.evidence_origin);
    println!("hardware_status={}", bundle.hardware_status);
    println!("steps={}", bundle.fuzz_report.steps.len());
    println!("minimized_actions={minimized_actions}");
    println!("artifact_sha256={}", to_hex(bundle.artifact_sha256));
    println!("output={}", output_path.display());
    Ok(())
}
