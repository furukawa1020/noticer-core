use std::env;
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
use quotient_forge_solver::{
    compare_bounded_backends, BackendComparisonConfig, BoundedSolverRuntime, ProcessLimits,
    QbfPlatform, QbfSolverAdapter, QbfSolverManifest, SolverMatrix, SolverPlatform, SolverRuntime,
    SolverSelection,
};
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
        CommandName::CompareBackends => run_compare_backends(options),
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

fn run_compare_backends(options: &Options) -> Result<WorkflowResult, String> {
    let (problem, _) = repair_fixture();
    let run_smt = options.solver != crate::SolverMode::Off;
    let smt_runtime = build_smt_runtime(run_smt)?;
    let qbf_adapter = build_optional_qbf_adapter()?;
    let config = BackendComparisonConfig {
        seed: options.seed,
        state_bound: 1,
        symmetry_breaking: options.symmetry_breaking,
        run_smt,
        smt_selection: SolverSelection::Auto,
        solver_timeout: Duration::from_secs(5),
        max_cegis_rounds: 1_000,
        qbf_truth_variable_limit: 24,
        exhaustive_limits: SynthesisLimits {
            max_states: 1,
            max_candidates: 100_000,
            time_limit: Duration::from_secs(5),
            checker_limits: CheckLimits {
                max_nodes: 100_000,
                max_depth: 16,
                time_limit: Duration::from_secs(5),
            },
            seed: options.seed,
        },
        checker_limits: CheckLimits {
            max_nodes: 100_000,
            max_depth: 16,
            time_limit: Duration::from_secs(5),
        },
    };
    let smt_runtime_ref = smt_runtime
        .as_ref()
        .map(|runtime| runtime as &dyn SolverRuntime);
    let artifact =
        compare_bounded_backends(&problem, &config, smt_runtime_ref, qbf_adapter.as_ref())
            .map_err(|error| error.to_string())?;
    artifact
        .write_to_directory(&options.output)
        .map_err(|error| error.to_string())?;

    let status = match artifact.agreements.exhaustive_qbf_decision {
        Some(true) => "AGREE",
        Some(false) => "DISAGREE",
        None => "INCONCLUSIVE",
    };
    Ok(WorkflowResult {
        status: status.to_owned(),
        engine: "quotient-forge-backend-comparison",
        files: vec![
            PathBuf::from("comparison.json"),
            PathBuf::from("backends/exhaustive/result.json"),
            PathBuf::from("backends/smt/result.json"),
            PathBuf::from("backends/qbf/result.json"),
        ],
        message_ja: match status {
            "AGREE" => "exhaustiveとQBFのbounded decisionが一致しました".to_owned(),
            "DISAGREE" => "exhaustiveとQBFのbounded decisionが不一致です".to_owned(),
            _ => "resourceまたはsolver境界により比較は判定不能です".to_owned(),
        },
    })
}

fn build_smt_runtime(enabled: bool) -> Result<Option<BoundedSolverRuntime>, String> {
    if !enabled {
        return Ok(None);
    }
    let matrix_path = env_path(
        "QUOTIENT_FORGE_SOLVER_MATRIX",
        "configs/quotient_forge/solver_matrix_v1.json",
    );
    let installation_root = env_path(
        "QUOTIENT_FORGE_SOLVER_ROOT",
        "artifacts/quotient-forge-solvers",
    );
    let matrix = SolverMatrix::from_path(&matrix_path).map_err(|error| {
        format!(
            "solver matrix {} を読めません: {error}",
            matrix_path.display()
        )
    })?;
    BoundedSolverRuntime::from_matrix(
        &matrix,
        &installation_root,
        current_solver_platform(),
        ProcessLimits::default(),
    )
    .map(Some)
    .map_err(|error| format!("SMT runtimeを構成できません: {error:?}"))
}

fn build_optional_qbf_adapter() -> Result<Option<QbfSolverAdapter>, String> {
    let root = env::var_os("QUOTIENT_FORGE_QBF_ROOT").map(PathBuf::from);
    let receipt = env::var_os("QUOTIENT_FORGE_QBF_RECEIPT").map(PathBuf::from);
    let (root, receipt) = match (root, receipt) {
        (None, None) => return Ok(None),
        (Some(root), Some(receipt)) => (root, receipt),
        _ => {
            return Err(
                "QUOTIENT_FORGE_QBF_ROOTとQUOTIENT_FORGE_QBF_RECEIPTは同時指定してください"
                    .to_owned(),
            )
        }
    };
    if cfg!(target_os = "windows") {
        return Err("Windows CAQE実solver経路はNOT_VERIFIEDです".to_owned());
    }
    let manifest_path = env_path(
        "QUOTIENT_FORGE_QBF_MANIFEST",
        "configs/quotient_forge/qbf_solver_manifest_v1.json",
    );
    let manifest = QbfSolverManifest::from_path(&manifest_path).map_err(|error| {
        format!(
            "QBF solver manifest {} を読めません: {error}",
            manifest_path.display()
        )
    })?;
    QbfSolverAdapter::from_installation(
        manifest,
        &root,
        &receipt,
        QbfPlatform::LinuxX86_64,
        ProcessLimits::default(),
    )
    .map(Some)
    .map_err(|error| format!("QBF solver adapterを構成できません: {error}"))
}

fn env_path(name: &str, default: &str) -> PathBuf {
    env::var_os(name).map_or_else(|| PathBuf::from(default), PathBuf::from)
}

fn current_solver_platform() -> SolverPlatform {
    if cfg!(target_os = "windows") {
        SolverPlatform::WindowsX86_64
    } else {
        SolverPlatform::LinuxX86_64
    }
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
