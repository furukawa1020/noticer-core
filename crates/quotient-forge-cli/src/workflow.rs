use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use quotient_forge_caqt::{
    verify, Certificate, CertificateLimits, CertificateVerdict, ExpectedContract,
};
use quotient_forge_check::CheckLimits;
use quotient_forge_codegen::{generate_package, CodegenConfig};
use quotient_forge_noticer::{run_handwritten_benchmark, AdapterVerdict, HandwrittenPlan};
use quotient_forge_repair::{repair, RepairLimits, RepairOperator, RepairOutcome};
use quotient_forge_synth::{find_feasible, SynthesisLimits, SynthesisOutcome};

use crate::artifact::{quote, write_binary, write_text};
use crate::fixtures::{canonical_certificate, repair_fixture, synthesis_problem};
use crate::{CheckCase, CommandName, Options};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowResult {
    pub status: String,
    pub engine: &'static str,
    pub files: Vec<PathBuf>,
    pub message_ja: String,
}

pub fn run(options: &Options) -> Result<WorkflowResult, String> {
    match options.command {
        CommandName::Check => run_check(options),
        CommandName::Synthesize => run_synthesize(options),
        CommandName::Repair => run_repair(options, false),
        CommandName::Verify => run_verify(options),
        CommandName::Frontier => run_repair(options, true),
        CommandName::Generate => run_generate(options),
    }
}

fn run_check(options: &Options) -> Result<WorkflowResult, String> {
    let plan = match options.check_case {
        CheckCase::ImmediateRelease => HandwrittenPlan::ImmediateRelease,
        CheckCase::FixedSizeOnly => HandwrittenPlan::FixedSizeOnly,
        CheckCase::CoarseBucket => HandwrittenPlan::CoarseBucket,
        CheckCase::EvidenceDependentSlot => HandwrittenPlan::EvidenceDependentSlot,
        CheckCase::Aets => HandwrittenPlan::Aets,
        CheckCase::AplotBoundedLoss => HandwrittenPlan::AplotBoundedLoss,
    };
    let evaluation = run_handwritten_benchmark(plan).map_err(|error| error.to_string())?;
    let (status, body, message) = match evaluation.verdict {
        AdapterVerdict::Valid(report) => (
            "VALID",
            format!(
                "{{\"checked_horizon\":{},\"plan\":{},\"schema\":\"quotient-forge-check-v1\",\"status\":\"VALID\"}}\n",
                report.checked_horizon,
                quote(options.check_case.as_str()),
            ),
            "bounded checkはVALIDです".to_owned(),
        ),
        AdapterVerdict::Counterexample(counterexample) => (
            "COUNTEREXAMPLE",
            format!(
                concat!(
                    "{{\"kind\":{},\"plan\":{},\"repair_candidate_count\":{},",
                    "\"schema\":\"quotient-forge-counterexample-v1\",\"slot\":{},",
                    "\"status\":\"COUNTEREXAMPLE\"}}\n"
                ),
                quote(&format!("{:?}", counterexample.kind)),
                quote(options.check_case.as_str()),
                counterexample.repair_candidates.len(),
                counterexample.slot,
            ),
            format!("slot {}に反例を検出しました", counterexample.slot),
        ),
        AdapterVerdict::Inconclusive => (
            "INCONCLUSIVE",
            format!(
                "{{\"plan\":{},\"schema\":\"quotient-forge-check-v1\",\"status\":\"INCONCLUSIVE\"}}\n",
                quote(options.check_case.as_str()),
            ),
            "resource bound内では判定不能です".to_owned(),
        ),
    };
    let file = write_text(&options.output, "counterexample.json", &body)
        .map_err(|error| error.to_string())?;
    Ok(WorkflowResult {
        status: status.to_owned(),
        engine: "quotient-forge-check",
        files: vec![file],
        message_ja: message,
    })
}

fn run_synthesize(options: &Options) -> Result<WorkflowResult, String> {
    let limits = SynthesisLimits {
        max_states: 2,
        max_candidates: 100_000,
        time_limit: Duration::from_secs(5),
        checker_limits: CheckLimits {
            max_nodes: 100_000,
            max_depth: 16,
            time_limit: Duration::from_secs(5),
        },
        seed: options.seed,
    };
    let outcome = find_feasible(&synthesis_problem(), limits).map_err(|error| error.to_string())?;
    let (status, body, message) = match outcome {
        SynthesisOutcome::Realizable(report) => (
            "REALIZABLE",
            format!(
                concat!(
                    "{{\"cost_optimized\":{},\"minimal_state_count\":{},",
                    "\"schema\":\"quotient-forge-synthesis-v1\",\"state_count\":{},",
                    "\"status\":\"REALIZABLE\"}}\n"
                ),
                report.cost_optimized,
                report.minimal_state_count,
                report.machine.state_count,
            ),
            format!("{}状態のrelease machineを合成しました", report.machine.state_count),
        ),
        SynthesisOutcome::Unrealizable(report) => (
            "UNREALIZABLE_WITHIN_BOUNDS",
            format!(
                concat!(
                    "{{\"schema\":\"quotient-forge-synthesis-v1\",",
                    "\"searched_through_states\":{},",
                    "\"status\":\"UNREALIZABLE_WITHIN_BOUNDS\"}}\n"
                ),
                report.searched_through_states,
            ),
            "指定bound内では実現不能です".to_owned(),
        ),
        SynthesisOutcome::Inconclusive { reason, .. } => (
            "INCONCLUSIVE",
            format!(
                "{{\"reason\":{},\"schema\":\"quotient-forge-synthesis-v1\",\"status\":\"INCONCLUSIVE\"}}\n",
                quote(&format!("{reason:?}")),
            ),
            "resource bound内では合成結果が確定しませんでした".to_owned(),
        ),
    };
    let file =
        write_text(&options.output, "synthesis.json", &body).map_err(|error| error.to_string())?;
    Ok(WorkflowResult {
        status: status.to_owned(),
        engine: "quotient-forge-synth-exhaustive",
        files: vec![file],
        message_ja: message,
    })
}

fn run_repair(options: &Options, full_frontier: bool) -> Result<WorkflowResult, String> {
    let (problem, machine) = repair_fixture();
    let operators = [
        RepairOperator::Cutoff {
            field: "leak".to_owned(),
            max_bytes: 0,
        },
        RepairOperator::Bucket {
            field: "leak".to_owned(),
            width: 10,
        },
    ];
    let limits = RepairLimits {
        time_limit: Duration::from_secs(5),
        checker_limits: CheckLimits {
            time_limit: Duration::from_secs(5),
            ..CheckLimits::default()
        },
        ..RepairLimits::default()
    };
    let outcome =
        repair(&problem, &machine, &operators, limits).map_err(|error| error.to_string())?;
    let schema = if full_frontier {
        "quotient-forge-frontier-v1"
    } else {
        "quotient-forge-repair-v1"
    };
    let filename = if full_frontier {
        "frontier.json"
    } else {
        "repair.json"
    };
    let (status, body, message) = match outcome {
        RepairOutcome::Repaired(frontier) => {
            let operator_names = frontier
                .points
                .iter()
                .filter_map(|point| point.provenance.operators.first())
                .map(|operator| quote(operator.name()))
                .collect::<Vec<_>>()
                .join(",");
            let status = if full_frontier {
                "FRONTIER"
            } else {
                "REPAIRED"
            };
            (
                status,
                format!(
                    concat!(
                        "{{\"operators\":[{}],\"point_count\":{},\"schema\":{},",
                        "\"status\":{},\"truncated\":{}}}\n"
                    ),
                    operator_names,
                    frontier.points.len(),
                    quote(schema),
                    quote(status),
                    frontier.truncated,
                ),
                format!("{}件の非支配repairを得ました", frontier.points.len()),
            )
        }
        RepairOutcome::NoRepair { .. } => (
            "NO_REPAIR",
            format!(
                "{{\"schema\":{},\"status\":\"NO_REPAIR\"}}\n",
                quote(schema)
            ),
            "指定operatorではrepairできませんでした".to_owned(),
        ),
        RepairOutcome::Inconclusive { reason, .. } => (
            "INCONCLUSIVE",
            format!(
                "{{\"reason\":{},\"schema\":{},\"status\":\"INCONCLUSIVE\"}}\n",
                quote(&format!("{reason:?}")),
                quote(schema),
            ),
            "resource bound内ではrepairを確定できませんでした".to_owned(),
        ),
    };
    let file = write_text(&options.output, filename, &body).map_err(|error| error.to_string())?;
    Ok(WorkflowResult {
        status: status.to_owned(),
        engine: "quotient-forge-repair",
        files: vec![file],
        message_ja: message,
    })
}

fn run_verify(options: &Options) -> Result<WorkflowResult, String> {
    let (bytes, expected) = certificate_input(options)?;
    let verdict = verify(&bytes, expected, CertificateLimits::default());
    let (status, detail, message) = match verdict {
        CertificateVerdict::Valid(report) => (
            "VALID",
            format!(
                "\"relation_pairs\":{},\"states\":{},\"transitions\":{}",
                report.relation_pairs, report.states, report.transitions
            ),
            "certificateはVALIDです".to_owned(),
        ),
        CertificateVerdict::Invalid(reason) => (
            "INVALID",
            format!("\"reason\":{}", quote(&format!("{reason:?}"))),
            "certificateはINVALIDです".to_owned(),
        ),
        CertificateVerdict::Incompatible(reason) => (
            "INCOMPATIBLE",
            format!("\"reason\":{}", quote(&format!("{reason:?}"))),
            "certificateはchecker契約と非互換です".to_owned(),
        ),
    };
    let body = format!(
        "{{{detail},\"schema\":\"quotient-forge-verification-v1\",\"status\":{}}}\n",
        quote(status)
    );
    let files = vec![
        write_binary(&options.output, "certificate.caqt", &bytes)
            .map_err(|error| error.to_string())?,
        write_text(&options.output, "verification.json", &body)
            .map_err(|error| error.to_string())?,
    ];
    Ok(WorkflowResult {
        status: status.to_owned(),
        engine: "quotient-forge-caqt",
        files,
        message_ja: message,
    })
}

fn run_generate(options: &Options) -> Result<WorkflowResult, String> {
    let (bytes, expected) = certificate_input(options)?;
    let target = options.output.join("generated-runtime");
    let package = generate_package(
        &bytes,
        expected,
        CertificateLimits::default(),
        &CodegenConfig {
            package_name: "generated-runtime".to_owned(),
            quotient_inputs: 1,
            public_inputs: 1,
            fault_inputs: 1,
            max_payload_bytes: 32,
            max_actions: 8,
        },
        &target,
    )
    .map_err(|error| error.to_string())?;
    let body = format!(
        concat!(
            "{{\"file_count\":{},\"schema\":\"quotient-forge-generation-v1\",",
            "\"status\":\"GENERATED\",\"transition_vectors\":{}}}\n"
        ),
        package.files.len(),
        package.transition_vectors,
    );
    let mut files = [
        "generated-runtime/Cargo.toml",
        "generated-runtime/src/lib.rs",
        "generated-runtime/src/vectors.rs",
        "generated-runtime/certificate.caqt",
        "generated-runtime/codegen-manifest.toml",
        "generated-runtime/test-vectors.tsv",
    ]
    .into_iter()
    .map(PathBuf::from)
    .collect::<Vec<_>>();
    files.push(
        write_text(&options.output, "generation.json", &body).map_err(|error| error.to_string())?,
    );
    Ok(WorkflowResult {
        status: "GENERATED".to_owned(),
        engine: "quotient-forge-codegen",
        files,
        message_ja: "検証済みcertificateからno_std packageを生成しました".to_owned(),
    })
}

fn certificate_input(options: &Options) -> Result<(Vec<u8>, ExpectedContract), String> {
    if let Some(path) = &options.certificate {
        let bytes = fs::read(path)
            .map_err(|error| format!("certificate {} を読めません: {error}", path.display()))?;
        let certificate = Certificate::decode(&bytes, CertificateLimits::default())
            .map_err(|error| format!("certificate parse error: {error:?}"))?;
        let expected = ExpectedContract {
            version: certificate.version,
            hashes: certificate.hashes,
            state_bound: certificate.state_bound,
            max_cost: certificate.claimed_cost,
        };
        Ok((bytes, expected))
    } else {
        Ok(canonical_certificate())
    }
}
