#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use quotient_forge_check::{check, CheckLimits, CheckOutcome};
use quotient_forge_synth::scalability_reference::{
    materialize_reference_case, ScalabilityDimensions,
};
use quotient_forge_synth::{find_feasible, SynthesisLimits, SynthesisOutcome};
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
        eprintln!("quotient-forge-cegis: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() != 12 {
        return Err(
            "expected CASE_ID P M H O F Y Q SEED CANDIDATE_LIMIT TIME_LIMIT_MS OUTPUT".to_owned(),
        );
    }
    let case_id = &arguments[0];
    let dimensions = ScalabilityDimensions {
        plant_states: parse(&arguments[1], "plant_states")?,
        machine_states: parse(&arguments[2], "machine_states")?,
        horizon: parse(&arguments[3], "horizon")?,
        observers: parse(&arguments[4], "observers")?,
        fault_states: parse(&arguments[5], "fault_states")?,
        output_alphabet: parse(&arguments[6], "output_alphabet")?,
        quotient_classes: parse(&arguments[7], "quotient_classes")?,
    };
    let seed = parse::<u64>(&arguments[8], "seed")?;
    let candidate_limit = parse::<u64>(&arguments[9], "candidate_limit")?;
    let time_limit_ms = parse::<u64>(&arguments[10], "time_limit_ms")?;
    let output = PathBuf::from(&arguments[11]);

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
    let limits = SynthesisLimits {
        max_states: dimensions.machine_states,
        max_candidates: candidate_limit,
        time_limit: Duration::from_millis(time_limit_ms),
        checker_limits,
        seed,
    };
    let checker_nodes = product_upper_bound(dimensions);
    let outcome =
        find_feasible(&materialized.problem, limits).map_err(|error| error.to_string())?;
    let backend_result = match outcome {
        SynthesisOutcome::Realizable(report) => {
            let checked = check(
                &materialized
                    .problem
                    .lower_candidate(&report.machine)
                    .map_err(|error| error.to_string())?,
                checker_limits,
            )
            .map_err(|error| error.to_string())?;
            let (status, verdict) = match checked {
                CheckOutcome::Verified(_) => ("COMPLETED", "VERIFIED"),
                CheckOutcome::Inconclusive(_) => ("SOLVER_UNKNOWN", "NOT_APPLICABLE"),
                CheckOutcome::Counterexample(_) => ("INVALID_CASE", "REJECTED"),
            };
            result(
                case_id,
                status,
                report.stats.generated_candidates,
                checker_nodes,
                verdict,
                &format!("{:?}|{:?}", report.machine, report.stats),
            )
        }
        SynthesisOutcome::Unrealizable(report) => result(
            case_id,
            "BOUNDED_UNSAT",
            report.stats.generated_candidates,
            checker_nodes,
            "NOT_APPLICABLE",
            &format!("{:?}", report.stats),
        ),
        SynthesisOutcome::Inconclusive { stats, reason } => result(
            case_id,
            "SOLVER_UNKNOWN",
            stats.generated_candidates,
            checker_nodes,
            "NOT_APPLICABLE",
            &format!("{stats:?}|{reason:?}"),
        ),
    };
    write_result(&output, backend_result)
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
        backend_id: "cegis",
        status,
        candidate_count,
        checker_node_count,
        solver_call_count: 0,
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
