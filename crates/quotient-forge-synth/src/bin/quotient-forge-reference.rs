#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::PathBuf;

use quotient_forge_check::{check, CheckLimits, CheckOutcome};
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
        eprintln!("quotient-forge-reference: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() != 10 {
        return Err("expected CASE_ID P M H O F Y Q SEED OUTPUT".to_owned());
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
    let output = PathBuf::from(&arguments[9]);

    let (status, verdict, checker_nodes) = match materialize_reference_case(dimensions) {
        Ok(materialized) => {
            let checker_model = materialized
                .problem
                .lower_candidate(&materialized.candidate)
                .map_err(|error| error.to_string())?;
            let nodes = u64::from(dimensions.plant_states)
                .saturating_mul(u64::from(dimensions.machine_states))
                .saturating_mul(u64::from(dimensions.horizon))
                .saturating_mul(u64::from(dimensions.quotient_classes));
            match check(&checker_model, CheckLimits::default())
                .map_err(|error| error.to_string())?
            {
                CheckOutcome::Verified(_) => ("COMPLETED", "VERIFIED", nodes),
                CheckOutcome::Inconclusive(_) => ("SOLVER_UNKNOWN", "NOT_APPLICABLE", nodes),
                _ => ("COMPLETED", "REJECTED", nodes),
            }
        }
        Err(_) => ("INVALID_CASE", "NOT_APPLICABLE", 0),
    };
    let evidence_input = format!("{case_id}|{dimensions:?}|{seed}|{status}|{verdict}");
    let evidence_sha256 = format!("{:x}", Sha256::digest(evidence_input.as_bytes()));
    let result = BackendResult {
        schema: "noticer.k7.backend-result.v1",
        case_id,
        backend_id: "reference",
        status,
        candidate_count: u64::from(status == "COMPLETED"),
        checker_node_count: checker_nodes,
        solver_call_count: 0,
        checker_verdict: verdict,
        evidence_sha256,
    };
    let encoded = serde_json::to_vec_pretty(&result).map_err(|error| error.to_string())?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    fs::write(output, encoded).map_err(|error| error.to_string())
}

fn parse<T: std::str::FromStr>(value: &str, name: &str) -> Result<T, String> {
    value
        .parse()
        .map_err(|_| format!("invalid {name}: {value}"))
}
