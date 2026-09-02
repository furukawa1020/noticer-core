use std::time::Duration;

use quotient_forge_solver::{
    classify_runtime_output, run_capability_probe, CapabilityProbeStatus, IndependentCheckerResult,
    RuntimeError, RuntimeOutput, SolverArtifactError, SolverKind, SolverResultArtifact,
    SolverResultKind, SolverRunMetadata, SolverRuntime,
};

#[derive(Clone, Copy)]
enum FakeMode {
    Complete,
    MissingOptimization,
}

struct FakeRuntime {
    mode: FakeMode,
}

impl SolverRuntime for FakeRuntime {
    fn version(&self, _solver: SolverKind) -> Result<String, RuntimeError> {
        Ok("fixture 1.0".to_owned())
    }

    fn run(
        &self,
        _solver: SolverKind,
        script: &str,
        _timeout: Duration,
    ) -> Result<RuntimeOutput, RuntimeError> {
        if script.contains("minimize") {
            if matches!(self.mode, FakeMode::MissingOptimization) {
                return Ok(RuntimeOutput::Completed {
                    stdout: String::new(),
                    stderr: "unsupported".to_owned(),
                    success: false,
                });
            }
            return Ok(completed("sat\n((probe_opt 0))\n"));
        }
        if script.contains(":reason-unknown") {
            return Ok(completed("sat\n(:reason-unknown \"\")\n"));
        }
        Ok(completed("sat\n((probe_x 7))\n"))
    }
}

fn completed(stdout: &str) -> RuntimeOutput {
    RuntimeOutput::Completed {
        stdout: stdout.to_owned(),
        stderr: String::new(),
        success: true,
    }
}

fn metadata() -> SolverRunMetadata {
    SolverRunMetadata {
        solver: "z3".to_owned(),
        version: "Z3 version 4.16.0".to_owned(),
        platform: "windows-x86_64".to_owned(),
        binary_sha256: "a".repeat(64),
        matrix_sha256: "b".repeat(64),
        program: "solvers/z3/bin/z3.exe".to_owned(),
        argv: vec![
            "solvers/z3/bin/z3.exe".to_owned(),
            "-in".to_owned(),
            "-smt2".to_owned(),
        ],
        timeout_ms: 2_000,
        seed: 42,
        search_bound: "max_states=4;horizon=16".to_owned(),
    }
}

#[test]
fn all_required_capabilities_must_pass() {
    let complete = run_capability_probe(
        &FakeRuntime {
            mode: FakeMode::Complete,
        },
        SolverKind::Z3,
        Duration::from_secs(2),
    );
    assert!(complete.available);
    assert_eq!(complete.checks.len(), 3);
    assert!(complete
        .checks
        .iter()
        .all(|check| check.status == CapabilityProbeStatus::Passed));
    assert!(complete.checks.iter().all(|check| {
        check.input_sha256.len() == 64
            && check.stdout_sha256.len() == 64
            && check.stderr_sha256.len() == 64
    }));

    let incomplete = run_capability_probe(
        &FakeRuntime {
            mode: FakeMode::MissingOptimization,
        },
        SolverKind::Z3,
        Duration::from_secs(2),
    );
    assert!(!incomplete.available);
    assert_eq!(
        incomplete
            .checks
            .iter()
            .filter(|check| check.status == CapabilityProbeStatus::Failed)
            .count(),
        1
    );
}

#[test]
fn five_result_values_remain_distinct() {
    let cases = [
        (completed("sat\n(model)\n"), SolverResultKind::Sat),
        (completed("unsat\n"), SolverResultKind::UnsatAtBound),
        (completed("unknown\n"), SolverResultKind::Unknown),
        (RuntimeOutput::TimedOut, SolverResultKind::Timeout),
        (completed("maybe\n"), SolverResultKind::Malformed),
    ];
    for (output, expected) in cases {
        assert_eq!(classify_runtime_output(&output), expected);
    }
}

#[test]
fn false_sat_cannot_be_attested() {
    let rejected = SolverResultArtifact::from_runtime(
        metadata(),
        "(check-sat)\n",
        completed("sat\n(model)\n"),
        IndependentCheckerResult::Rejected,
    );
    assert!(matches!(
        rejected,
        Err(SolverArtifactError::RejectedSatCandidate)
    ));

    let unchecked = SolverResultArtifact::from_runtime(
        metadata(),
        "(check-sat)\n",
        completed("sat\n(model)\n"),
        IndependentCheckerResult::NotApplicable,
    );
    assert!(matches!(
        unchecked,
        Err(SolverArtifactError::UncheckedSatCandidate)
    ));
}

#[test]
fn canonical_artifact_is_reproducible_and_unsat_stays_bounded() {
    let build = || {
        SolverResultArtifact::from_runtime(
            metadata(),
            "(check-sat)\n",
            completed("unsat\n"),
            IndependentCheckerResult::NotApplicable,
        )
        .unwrap()
    };
    let first = build();
    let second = build();
    assert_eq!(first.result, SolverResultKind::UnsatAtBound);
    assert_eq!(
        first.canonical_json_bytes().unwrap(),
        second.canonical_json_bytes().unwrap()
    );
    assert_eq!(
        first.digest_sha256().unwrap(),
        second.digest_sha256().unwrap()
    );

    let json = String::from_utf8(first.canonical_json_bytes().unwrap()).unwrap();
    assert!(json.contains("UNSAT_AT_BOUND"));
    assert!(!json.contains("UNREALIZABLE"));
}

#[test]
fn unknown_is_not_malformed_in_artifact() {
    let unknown = SolverResultArtifact::from_runtime(
        metadata(),
        "(check-sat)\n",
        completed("unknown\n(:reason-unknown \"incomplete\")\n"),
        IndependentCheckerResult::NotApplicable,
    )
    .unwrap();
    let malformed = SolverResultArtifact::from_runtime(
        metadata(),
        "(check-sat)\n",
        completed("solver banner only\n"),
        IndependentCheckerResult::NotApplicable,
    )
    .unwrap();
    assert_eq!(unknown.result, SolverResultKind::Unknown);
    assert_eq!(malformed.result, SolverResultKind::Malformed);
    assert_ne!(
        unknown.digest_sha256().unwrap(),
        malformed.digest_sha256().unwrap()
    );
}
