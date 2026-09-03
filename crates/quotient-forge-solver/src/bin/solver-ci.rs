use std::env;
use std::error::Error;
use std::fs::{self, File};
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use quotient_forge_solver::{
    classify_runtime_output, run_capability_probe, BoundedSolverRuntime, IndependentCheckerResult,
    ProcessLimits, RuntimeOutput, SolverKind, SolverMatrix, SolverPlatform, SolverResultArtifact,
    SolverResultKind, SolverRunMetadata, SolverRuntime,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

const SMOKE_QUERY: &str = "(set-option :produce-models true)\n(set-logic QF_LIA)\n(declare-const smoke_x Int)\n(assert (= smoke_x 11))\n(check-sat)\n(get-value (smoke_x))\n(exit)\n";

struct Arguments {
    matrix: PathBuf,
    solver: String,
    platform: String,
    expected_available: bool,
    install_root: PathBuf,
    output: PathBuf,
    timeout_ms: u64,
    seed: u64,
}

struct ManifestView {
    executable_path: String,
    solve_argv: Vec<String>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("solver CI smoke failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let arguments = parse_arguments()?;
    let solver = match arguments.solver.as_str() {
        "cvc5" => SolverKind::Cvc5,
        "z3" => SolverKind::Z3,
        _ => return Err(invalid_input("solver must be cvc5 or z3").into()),
    };
    if !matches!(
        arguments.platform.as_str(),
        "linux-x86_64" | "windows-x86_64"
    ) {
        return Err(invalid_input("unsupported solver platform").into());
    }
    let platform: SolverPlatform = serde_json::from_str(&format!("\"{}\"", arguments.platform))?;
    let matrix = SolverMatrix::from_path(&arguments.matrix)?;
    let manifest = read_manifest_view(&arguments.matrix, &arguments.solver, &arguments.platform)?;
    let runtime = BoundedSolverRuntime::from_matrix(
        &matrix,
        &arguments.install_root,
        platform,
        ProcessLimits::default(),
    )
    .map_err(|error| invalid_input(format!("bounded runtime configuration failed: {error:?}")))?;
    let timeout = Duration::from_millis(arguments.timeout_ms);

    let probe = run_capability_probe(&runtime, solver, timeout);
    probe.write_canonical(&arguments.output.join("probe.json"))?;
    if !should_run_smoke(arguments.expected_available, probe.available)? {
        println!("solver_expected_unavailable=true");
        return Ok(());
    }

    let version = runtime
        .version(solver)
        .map_err(|error| invalid_input(format!("solver version probe failed: {error:?}")))?;
    let output = runtime
        .run(solver, SMOKE_QUERY, timeout)
        .map_err(|error| invalid_input(format!("solver execution failed: {error:?}")))?;
    let independent_checker = if classify_runtime_output(&output) == SolverResultKind::Sat {
        if smoke_model_is_valid(&output) {
            IndependentCheckerResult::Accepted
        } else {
            IndependentCheckerResult::Rejected
        }
    } else {
        IndependentCheckerResult::NotApplicable
    };

    let program = arguments
        .install_root
        .join(Path::new(&manifest.executable_path));
    let mut argv = vec![program.display().to_string()];
    argv.extend(manifest.solve_argv);
    let metadata = SolverRunMetadata {
        solver: arguments.solver,
        version,
        platform: arguments.platform,
        binary_sha256: sha256_file(&program)?,
        matrix_sha256: matrix.digest_sha256()?,
        program: program.display().to_string(),
        argv,
        timeout_ms: arguments.timeout_ms,
        seed: arguments.seed,
        search_bound: "canonical_smoke:qf_lia:smoke_x=11".to_owned(),
    };
    let artifact =
        SolverResultArtifact::from_runtime(metadata, SMOKE_QUERY, output, independent_checker)?;
    artifact.write_canonical(&arguments.output.join("result.json"))?;
    println!("solver_result_sha256={}", artifact.digest_sha256()?);

    if artifact.result != SolverResultKind::Sat {
        return Err(invalid_input(format!(
            "canonical solver smoke returned {:?}",
            artifact.result
        ))
        .into());
    }
    Ok(())
}

fn parse_arguments() -> Result<Arguments, io::Error> {
    let mut matrix = None;
    let mut solver = None;
    let mut platform = None;
    let mut expected_available = None;
    let mut install_root = None;
    let mut output = None;
    let mut timeout_ms = None;
    let mut seed = None;
    let mut arguments = env::args().skip(1);
    while let Some(flag) = arguments.next() {
        let value = arguments
            .next()
            .ok_or_else(|| invalid_input(format!("missing value for {flag}")))?;
        match flag.as_str() {
            "--matrix" => matrix = Some(PathBuf::from(value)),
            "--solver" => solver = Some(value),
            "--platform" => platform = Some(value),
            "--expect-available" => {
                expected_available = Some(match value.as_str() {
                    "true" => true,
                    "false" => false,
                    _ => return Err(invalid_input("expected availability must be true or false")),
                });
            }
            "--install-root" => install_root = Some(PathBuf::from(value)),
            "--output" => output = Some(PathBuf::from(value)),
            "--timeout-ms" => {
                timeout_ms = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| invalid_input("timeout must be an integer"))?,
                );
            }
            "--seed" => {
                seed = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| invalid_input("seed must be an integer"))?,
                );
            }
            _ => return Err(invalid_input(format!("unknown argument: {flag}"))),
        }
    }
    let timeout_ms = timeout_ms.ok_or_else(|| invalid_input("--timeout-ms is required"))?;
    if timeout_ms == 0 || timeout_ms > 60_000 {
        return Err(invalid_input("timeout must be between 1 and 60000 ms"));
    }
    Ok(Arguments {
        matrix: matrix.ok_or_else(|| invalid_input("--matrix is required"))?,
        solver: solver.ok_or_else(|| invalid_input("--solver is required"))?,
        platform: platform.ok_or_else(|| invalid_input("--platform is required"))?,
        expected_available: expected_available
            .ok_or_else(|| invalid_input("--expect-available is required"))?,
        install_root: install_root.ok_or_else(|| invalid_input("--install-root is required"))?,
        output: output.ok_or_else(|| invalid_input("--output is required"))?,
        timeout_ms,
        seed: seed.ok_or_else(|| invalid_input("--seed is required"))?,
    })
}

fn should_run_smoke(expected: bool, observed: bool) -> Result<bool, io::Error> {
    match (expected, observed) {
        (true, true) => Ok(true),
        (false, false) => Ok(false),
        (true, false) => Err(invalid_input(
            "solver capability probe failed but availability was required",
        )),
        (false, true) => Err(invalid_input(
            "solver capability profile changed; review and update the pinned expectation",
        )),
    }
}

fn read_manifest_view(
    path: &Path,
    solver: &str,
    platform: &str,
) -> Result<ManifestView, Box<dyn Error>> {
    let document: Value = serde_json::from_slice(&fs::read(path)?)?;
    let solver_entry = document["solvers"]
        .as_array()
        .and_then(|entries| entries.iter().find(|entry| entry["id"] == solver))
        .ok_or_else(|| invalid_input("solver missing from validated matrix"))?;
    let asset = solver_entry["assets"]
        .as_array()
        .and_then(|entries| entries.iter().find(|entry| entry["platform"] == platform))
        .ok_or_else(|| invalid_input("platform missing from validated matrix"))?;
    let executable_path = asset["executable_path"]
        .as_str()
        .ok_or_else(|| invalid_input("matrix executable path is not a string"))?
        .to_owned();
    let solve_argv = solver_entry["commands"]["solve"]
        .as_array()
        .ok_or_else(|| invalid_input("matrix solve argv is not an array"))?
        .iter()
        .map(|argument| {
            argument
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| invalid_input("matrix solve argument is not a string"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ManifestView {
        executable_path,
        solve_argv,
    })
}

fn smoke_model_is_valid(output: &RuntimeOutput) -> bool {
    let RuntimeOutput::Completed {
        stdout,
        success: true,
        ..
    } = output
    else {
        return false;
    };
    let tokens = stdout
        .split(|character: char| {
            !(character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
        })
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    tokens
        .windows(2)
        .any(|pair| pair[0] == "smoke_x" && pair[1] == "11")
}

fn sha256_file(path: &Path) -> Result<String, io::Error> {
    let mut source = BufReader::new(File::open(path)?);
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = source.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::should_run_smoke;

    #[test]
    fn availability_expectation_is_fail_closed() {
        assert!(should_run_smoke(true, true).unwrap());
        assert!(!should_run_smoke(false, false).unwrap());
        assert!(should_run_smoke(true, false).is_err());
        assert!(should_run_smoke(false, true).is_err());
    }
}
