#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use quotient_forge_check::CheckLimits;
use quotient_forge_solver::{
    check_qbf_candidate, compile_bounded_safety_game, run_bounded_process, ProcessLimits,
    QbfCandidateDecision, QbfCompileLimits, QbfInstallReceipt, QbfPlatform, QbfSolverAdapter,
    QbfSolverManifest, QbfSolverMetadata, QbfSolverResultArtifact, QbfSolverStatus,
};
use quotient_forge_synth::scalability_reference::{
    materialize_reference_case, ScalabilityDimensions,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Serialize)]
struct BackendResult<'a> {
    schema: &'static str,
    case_id: &'a str,
    backend_id: &'static str,
    status: &'static str,
    candidate_count: u64,
    checker_node_count: u64,
    solver_call_count: u64,
    checker_verdict: &'static str,
    evidence_sha256: String,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("quotient-forge-qbf: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() != 15 {
        return Err("expected CASE_ID ROOT MANIFEST RECEIPT P M H O F Y Q SEED CANDIDATE_LIMIT TIME_LIMIT_MS OUTPUT".to_owned());
    }
    let case_id = &arguments[0];
    let root = PathBuf::from(&arguments[1]);
    let manifest_path = PathBuf::from(&arguments[2]);
    let receipt_path = PathBuf::from(&arguments[3]);
    let dimensions = ScalabilityDimensions {
        plant_states: parse(&arguments[4], "plant_states")?,
        machine_states: parse(&arguments[5], "machine_states")?,
        horizon: parse(&arguments[6], "horizon")?,
        observers: parse(&arguments[7], "observers")?,
        fault_states: parse(&arguments[8], "fault_states")?,
        output_alphabet: parse(&arguments[9], "output_alphabet")?,
        quotient_classes: parse(&arguments[10], "quotient_classes")?,
    };
    let seed = parse::<u64>(&arguments[11], "seed")?;
    let candidate_limit = parse::<u64>(&arguments[12], "candidate_limit")?;
    let time_limit_ms = parse::<u64>(&arguments[13], "time_limit_ms")?;
    let output = PathBuf::from(&arguments[14]);

    if !receipt_path.is_file() {
        return write_result(
            &output,
            result(
                case_id,
                "NOT_RUN",
                0,
                0,
                0,
                "NOT_APPLICABLE",
                "receipt-unavailable",
            ),
        );
    }
    let manifest_bytes = fs::read(&manifest_path).map_err(|error| error.to_string())?;
    let manifest =
        QbfSolverManifest::from_slice(&manifest_bytes).map_err(|error| format!("{error:?}"))?;
    let receipt: QbfInstallReceipt =
        serde_json::from_slice(&fs::read(&receipt_path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let platform = platform()?;
    if QbfSolverAdapter::from_installation(
        manifest.clone(),
        &root,
        &receipt_path,
        platform,
        ProcessLimits::default(),
    )
    .is_err()
    {
        return write_result(
            &output,
            result(
                case_id,
                "INVALID_CASE",
                0,
                0,
                0,
                "NOT_APPLICABLE",
                "installation-verification-failed",
            ),
        );
    }
    let materialized = match materialize_reference_case(dimensions) {
        Ok(value) => value,
        Err(error) => {
            return write_result(
                &output,
                result(case_id, "INVALID_CASE", 0, 0, 0, "NOT_APPLICABLE", &error),
            );
        }
    };
    let bounded_candidates = usize::try_from(candidate_limit)
        .map_err(|_| "candidate_limit exceeds platform capacity".to_owned())?;
    let compile_limits = QbfCompileLimits {
        max_machine_states: dimensions.machine_states,
        max_table_assignments: u64::from(dimensions.machine_states)
            .saturating_mul(u64::from(dimensions.quotient_classes)),
        max_candidates: bounded_candidates,
        max_scenarios: bounded_candidates,
        seed,
    };
    let compilation = match compile_bounded_safety_game(&materialized.problem, compile_limits) {
        Ok(value) => value,
        Err(error) => {
            return write_result(
                &output,
                result(
                    case_id,
                    "SOLVER_UNKNOWN",
                    0,
                    0,
                    0,
                    "NOT_APPLICABLE",
                    &format!("compile:{error:?}"),
                ),
            );
        }
    };
    let query_path = output.with_extension("qdimacs");
    if let Some(parent) = query_path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    fs::write(&query_path, &compilation.qdimacs.document).map_err(|error| error.to_string())?;
    let program = root.join(&receipt.executable_path);
    let argv = vec![
        "--qdo".to_owned(),
        query_path.to_string_lossy().into_owned(),
    ];
    let process_output = run_bounded_process(
        &program,
        &argv,
        b"",
        Duration::from_millis(time_limit_ms),
        ProcessLimits::default(),
    )
    .map_err(|error| format!("{error:?}"))?;
    let metadata = QbfSolverMetadata {
        solver: manifest.solver.clone(),
        version: manifest.version.clone(),
        platform: platform_name(platform).to_owned(),
        source_revision: manifest.source_revision.clone(),
        source_sha256: manifest.source_sha256.clone(),
        binary_sha256: receipt.binary_sha256.clone(),
        manifest_sha256: manifest
            .digest_sha256()
            .map_err(|error| format!("{error:?}"))?,
        program: receipt.executable_path.clone(),
        argv,
        timeout_ms: time_limit_ms,
        seed,
        bounds: compilation.qdimacs.metadata.bounds,
    };
    let solver_run = QbfSolverResultArtifact::from_output(
        metadata,
        &compilation.qdimacs.document,
        process_output,
    )
    .map_err(|error| format!("{error:?}"))?;
    let _ = fs::remove_file(query_path);
    let checker_nodes = product_upper_bound(dimensions);
    let backend_result = match solver_run.artifact.result {
        QbfSolverStatus::Sat => {
            let checked = check_qbf_candidate(
                &solver_run,
                &compilation,
                &materialized.problem,
                CheckLimits {
                    max_nodes: 1_000_000,
                    max_depth: dimensions.horizon.saturating_add(1),
                    time_limit: Duration::from_millis(time_limit_ms),
                },
            );
            if checked.artifact.decision == QbfCandidateDecision::Accepted {
                result(
                    case_id,
                    "COMPLETED",
                    1,
                    checker_nodes,
                    1,
                    "VERIFIED",
                    &format!("{:?}", checked.artifact),
                )
            } else {
                result(
                    case_id,
                    "INVALID_CASE",
                    1,
                    checker_nodes,
                    1,
                    "REJECTED",
                    &format!("{:?}", checked.artifact),
                )
            }
        }
        QbfSolverStatus::UnsatAtBound => result(
            case_id,
            "BOUNDED_UNSAT",
            0,
            checker_nodes,
            1,
            "NOT_APPLICABLE",
            "qbf-unsat-at-bound",
        ),
        QbfSolverStatus::Unknown | QbfSolverStatus::Timeout => result(
            case_id,
            "SOLVER_UNKNOWN",
            0,
            checker_nodes,
            1,
            "NOT_APPLICABLE",
            &format!("{:?}", solver_run.artifact.result),
        ),
        QbfSolverStatus::Malformed => result(
            case_id,
            "INVALID_CASE",
            0,
            checker_nodes,
            1,
            "NOT_APPLICABLE",
            "malformed-qbf-output",
        ),
    };
    write_result(&output, backend_result)
}

#[cfg(target_os = "windows")]
fn platform() -> Result<QbfPlatform, String> {
    Ok(QbfPlatform::WindowsX86_64)
}
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn platform() -> Result<QbfPlatform, String> {
    Ok(QbfPlatform::LinuxX86_64)
}
#[cfg(not(any(
    target_os = "windows",
    all(target_os = "linux", target_arch = "x86_64")
)))]
fn platform() -> Result<QbfPlatform, String> {
    Err("unsupported platform".to_owned())
}

fn platform_name(value: QbfPlatform) -> &'static str {
    match value {
        QbfPlatform::WindowsX86_64 => "windows-x86_64",
        QbfPlatform::LinuxX86_64 => "linux-x86_64",
    }
}

fn result<'a>(
    case_id: &'a str,
    status: &'static str,
    candidate_count: u64,
    checker_node_count: u64,
    solver_call_count: u64,
    checker_verdict: &'static str,
    evidence: &str,
) -> BackendResult<'a> {
    BackendResult {
        schema: "noticer.k7.backend-result.v1",
        case_id,
        backend_id: "qbf",
        status,
        candidate_count,
        checker_node_count,
        solver_call_count,
        checker_verdict,
        evidence_sha256: format!("{:x}", Sha256::digest(evidence.as_bytes())),
    }
}

fn write_result(output: &PathBuf, result: BackendResult<'_>) -> Result<(), String> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    fs::write(
        output,
        serde_json::to_vec_pretty(&result).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
}

fn product_upper_bound(dimensions: ScalabilityDimensions) -> u64 {
    u64::from(dimensions.plant_states)
        .saturating_mul(u64::from(dimensions.machine_states))
        .saturating_mul(u64::from(dimensions.horizon))
        .saturating_mul(u64::from(dimensions.quotient_classes))
}

fn parse<T: std::str::FromStr>(value: &str, name: &str) -> Result<T, String> {
    value
        .parse()
        .map_err(|_| format!("invalid {name}: {value}"))
}
