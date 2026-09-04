use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use quotient_forge_solver::{
    ProcessLimits, QbfPlatform, QbfSolverAdapter, QbfSolverManifest, QbfSolverStatus, QdimacsBounds,
};

const SAT: &str = "p cnf 2 2\ne 1 0\na 2 0\n1 -2 0\n1 2 0\n";
const UNSAT: &str = "p cnf 2 2\ne 1 0\na 2 0\n-1 -2 0\n1 2 0\n";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = arguments()?;
    let manifest_path = required(&args, "manifest")?;
    let platform = QbfPlatform::parse(required(&args, "platform")?)?;
    let install_root = PathBuf::from(required(&args, "install-root")?);
    let receipt = PathBuf::from(required(&args, "receipt")?);
    let output = PathBuf::from(required(&args, "output")?);
    let timeout_ms = required(&args, "timeout-ms")?.parse::<u64>()?;
    let seed = required(&args, "seed")?.parse::<u64>()?;
    let manifest = QbfSolverManifest::from_path(&PathBuf::from(manifest_path))?;
    let adapter = QbfSolverAdapter::from_installation(
        manifest,
        &install_root,
        &receipt,
        platform,
        ProcessLimits::default(),
    )?;
    fs::create_dir_all(&output)?;
    let bounds = QdimacsBounds {
        plant_states: 1,
        machine_states: 1,
        horizon: 1,
        action_count: 1,
    };
    for (name, query, expected) in [
        ("sat", SAT, QbfSolverStatus::Sat),
        ("unsat", UNSAT, QbfSolverStatus::UnsatAtBound),
    ] {
        let run = adapter.run(query, bounds, seed, Duration::from_millis(timeout_ms))?;
        if run.artifact.result != expected || run.artifact.candidate_accepted {
            return Err(format!("{name} smoke returned {:?}", run.artifact.result).into());
        }
        run.artifact
            .write_canonical(&output.join(format!("{name}.json")))?;
        fs::write(output.join(format!("{name}.stdout")), run.stdout)?;
        fs::write(output.join(format!("{name}.stderr")), run.stderr)?;
    }
    println!("CAQE bounded SAT/UNSAT smoke: PASS");
    Ok(())
}

fn arguments() -> Result<BTreeMap<String, String>, Box<dyn std::error::Error>> {
    let mut values = BTreeMap::new();
    let mut args = env::args().skip(1);
    while let Some(flag) = args.next() {
        let key = flag
            .strip_prefix("--")
            .ok_or_else(|| format!("unexpected argument {flag}"))?;
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        if values.insert(key.to_owned(), value).is_some() {
            return Err(format!("duplicate argument {flag}").into());
        }
    }
    Ok(values)
}

fn required<'a>(
    values: &'a BTreeMap<String, String>,
    key: &str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    values
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("missing --{key}").into())
}
