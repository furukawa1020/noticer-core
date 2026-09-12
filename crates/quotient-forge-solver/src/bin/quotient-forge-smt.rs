#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use quotient_forge_check::{check, CheckLimits, CheckOutcome};
use quotient_forge_solver::{
    solve, BackendConfig, BackendStatus, BoundedSolverRuntime, ProcessLimits, SolverId, SolverKind,
    SolverMatrix, SolverPlatform, SolverRuntime, SolverSelection,
};
use quotient_forge_synth::scalability_reference::{
    materialize_reference_case, ScalabilityDimensions,
};
use quotient_forge_synth::SynthesisLimits;
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
        eprintln!("quotient-forge-smt: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() != 16 {
        return Err("expected CASE_ID SOLVER SOLVER_ROOT MATRIX EXPECTED_BINARY_SHA P M H O F Y Q SEED TIME_LIMIT_MS OUTPUT".to_owned());
    }
    let case_id = &arguments[0];
    let (solver_kind, solver_id) = solver(&arguments[1])?;
    let solver_root = PathBuf::from(&arguments[2]);
    let matrix_path = PathBuf::from(&arguments[3]);
    let expected_binary_sha256 = &arguments[4];
    let dimensions = ScalabilityDimensions {
        plant_states: parse(&arguments[5], "plant_states")?,
        machine_states: parse(&arguments[6], "machine_states")?,
        horizon: parse(&arguments[7], "horizon")?,
        observers: parse(&arguments[8], "observers")?,
        fault_states: parse(&arguments[9], "fault_states")?,
        output_alphabet: parse(&arguments[10], "output_alphabet")?,
        quotient_classes: parse(&arguments[11], "quotient_classes")?,
    };
    let seed = parse::<u64>(&arguments[12], "seed")?;
    let time_limit_ms = parse::<u64>(&arguments[13], "time_limit_ms")?;
    let output = PathBuf::from(&arguments[14]);
    let declared_platform = &arguments[15];
    let platform = platform()?;
    if declared_platform != platform_name(platform) {
        return write_result(
            &output,
            result(
                case_id,
                "INVALID_CASE",
                0,
                0,
                "NOT_APPLICABLE",
                "platform-mismatch",
            ),
        );
    }

    let matrix = SolverMatrix::from_path(&matrix_path).map_err(|error| format!("{error:?}"))?;
    let runtime = BoundedSolverRuntime::from_matrix(
        &matrix,
        &solver_root,
        platform,
        ProcessLimits::default(),
    )
    .map_err(|error| format!("{error:?}"))?;
    let program = PathBuf::from(runtime.program(solver_kind));
    if !program.is_file() {
        return write_result(
            &output,
            result(
                case_id,
                "NOT_RUN",
                0,
                0,
                "NOT_APPLICABLE",
                "solver-unavailable",
            ),
        );
    }
    let actual_binary_sha256 = file_sha256(&program)?;
    if actual_binary_sha256 != *expected_binary_sha256 {
        return write_result(
            &output,
            result(
                case_id,
                "INVALID_CASE",
                0,
                0,
                "NOT_APPLICABLE",
                "binary-digest-mismatch",
            ),
        );
    }
    let version = runtime
        .version(solver_kind)
        .map_err(|error| format!("{error:?}"))?;
    let expected_version = &matrix.solver(solver_id).version;
    if !version.contains(expected_version) {
        return write_result(
            &output,
            result(
                case_id,
                "INVALID_CASE",
                0,
                0,
                "NOT_APPLICABLE",
                "solver-version-mismatch",
            ),
        );
    }
    let materialized = match materialize_reference_case(dimensions) {
        Ok(value) => value,
        Err(error) => {
            return write_result(
                &output,
                result(case_id, "INVALID_CASE", 0, 0, "NOT_APPLICABLE", &error),
            );
        }
    };
    let checker_limits = CheckLimits {
        max_nodes: 1_000_000,
        max_depth: dimensions.horizon.saturating_add(1),
        time_limit: Duration::from_millis(time_limit_ms),
    };
    let config = BackendConfig {
        selection: SolverSelection::Explicit(solver_kind),
        state_bound: dimensions.machine_states,
        exhaustive_fallback_max_cells: 0,
        solver_timeout: Duration::from_millis(time_limit_ms),
        exhaustive_limits: SynthesisLimits {
            max_states: dimensions.machine_states,
            max_candidates: 0,
            time_limit: Duration::from_millis(time_limit_ms),
            checker_limits,
            seed,
        },
        ..BackendConfig::default()
    };
    let solved =
        solve(&materialized.problem, &config, &runtime).map_err(|error| format!("{error:?}"))?;
    let checker_nodes = product_upper_bound(dimensions);
    let backend_result = if solved.status == BackendStatus::Sat {
        let Some(machine) = solved.machine else {
            return write_result(
                &output,
                result(
                    case_id,
                    "INVALID_CASE",
                    0,
                    checker_nodes,
                    "REJECTED",
                    "sat-without-model",
                ),
            );
        };
        let checked = check(
            &materialized
                .problem
                .lower_candidate(&machine)
                .map_err(|error| error.to_string())?,
            checker_limits,
        )
        .map_err(|error| format!("{error:?}"))?;
        match checked {
            CheckOutcome::Verified(_) => result(
                case_id,
                "COMPLETED",
                1,
                checker_nodes,
                "VERIFIED",
                &format!("{actual_binary_sha256}|{version}|{machine:?}"),
            ),
            CheckOutcome::Inconclusive(_) => result(
                case_id,
                "SOLVER_UNKNOWN",
                1,
                checker_nodes,
                "NOT_APPLICABLE",
                "checker-inconclusive",
            ),
            CheckOutcome::Counterexample(_) => result(
                case_id,
                "INVALID_CASE",
                1,
                checker_nodes,
                "REJECTED",
                "checker-rejected",
            ),
        }
    } else if solved.status == BackendStatus::Unsat {
        result(
            case_id,
            "BOUNDED_UNSAT",
            0,
            checker_nodes,
            "NOT_APPLICABLE",
            &format!("{actual_binary_sha256}|{version}|unsat"),
        )
    } else if solved.status == BackendStatus::NotInstalled {
        result(
            case_id,
            "NOT_RUN",
            0,
            0,
            "NOT_APPLICABLE",
            "solver-not-installed",
        )
    } else {
        result(
            case_id,
            "SOLVER_UNKNOWN",
            0,
            checker_nodes,
            "NOT_APPLICABLE",
            &format!("{:?}", solved.status),
        )
    };
    write_result(&output, backend_result)
}

fn solver(value: &str) -> Result<(SolverKind, SolverId), String> {
    match value {
        "cvc5" => Ok((SolverKind::Cvc5, SolverId::Cvc5)),
        "z3" => Ok((SolverKind::Z3, SolverId::Z3)),
        _ => Err(format!("unsupported solver: {value}")),
    }
}

#[cfg(target_os = "windows")]
fn platform() -> Result<SolverPlatform, String> {
    Ok(SolverPlatform::WindowsX86_64)
}
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn platform() -> Result<SolverPlatform, String> {
    Ok(SolverPlatform::LinuxX86_64)
}
#[cfg(not(any(
    target_os = "windows",
    all(target_os = "linux", target_arch = "x86_64")
)))]
fn platform() -> Result<SolverPlatform, String> {
    Err("unsupported platform".to_owned())
}

fn platform_name(value: SolverPlatform) -> &'static str {
    match value {
        SolverPlatform::WindowsX86_64 => "windows-x86_64",
        SolverPlatform::LinuxX86_64 => "linux-x86_64",
    }
}

fn file_sha256(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|error| format!("{error:?}"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn result<'a>(
    case_id: &'a str,
    status: &'static str,
    candidate_count: u64,
    checker_node_count: u64,
    checker_verdict: &'static str,
    evidence: &str,
) -> BackendResult<'a> {
    BackendResult {
        schema: "noticer.k7.backend-result.v1",
        case_id,
        backend_id: "smt",
        status,
        candidate_count,
        checker_node_count,
        solver_call_count: u64::from(status != "NOT_RUN" && status != "INVALID_CASE"),
        checker_verdict,
        evidence_sha256: format!("{:x}", Sha256::digest(evidence.as_bytes())),
    }
}

fn write_result(output: &PathBuf, result: BackendResult<'_>) -> Result<(), String> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("{error:?}"))?;
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
