use quotient_forge_synth::session::{
    run_incremental_cegis, BackendDecision, CandidateChecker, CheckerDecision,
    IncrementalAssertionBackend, RestartPolicy, SessionArtifact, SessionBlocker, SessionConfig,
    SessionContext, SessionInconclusiveReason, SessionOutcome, SolverFailure,
};
use quotient_forge_synth::BlockerClass;

fn sha256(value: u8) -> String {
    format!("{value:064x}")
}

fn context() -> SessionContext {
    SessionContext {
        problem_sha256: sha256(240),
        epoch: 7,
        seed: 41,
    }
}

fn config(restart_after: u64) -> SessionConfig {
    SessionConfig {
        max_candidates: 8,
        restart_policy: RestartPolicy {
            accepted_blockers_per_generation: restart_after,
        },
    }
}

fn blocker(source_candidate_sha256: &str, value: u8, subsumes: Vec<String>) -> SessionBlocker {
    SessionBlocker::new(
        BlockerClass::Security,
        sha256(value.saturating_add(80)),
        source_candidate_sha256,
        sha256(value.saturating_add(100)),
        sha256(value.saturating_add(120)),
        subsumes,
    )
    .unwrap()
}

#[derive(Default)]
struct CountingBackend {
    active: Vec<String>,
}

impl IncrementalAssertionBackend for CountingBackend {
    type Candidate = u8;

    fn start(&mut self, _context: &SessionContext) -> Result<(), SolverFailure> {
        self.active.clear();
        Ok(())
    }

    fn push_blocker(&mut self, blocker: &SessionBlocker) -> Result<(), SolverFailure> {
        self.active.push(blocker.blocker_sha256.clone());
        Ok(())
    }

    fn solve(&mut self) -> Result<BackendDecision<Self::Candidate>, SolverFailure> {
        Ok(match self.active.len() {
            0 => BackendDecision::Candidate {
                candidate_sha256: sha256(1),
                candidate: 1,
            },
            1 => BackendDecision::Candidate {
                candidate_sha256: sha256(2),
                candidate: 2,
            },
            _ => BackendDecision::Unsat,
        })
    }
}

struct RejectTwoCandidates;

impl CandidateChecker<u8> for RejectTwoCandidates {
    fn check(&mut self, candidate_sha256: &str, candidate: &u8) -> CheckerDecision {
        CheckerDecision::Rejected {
            blocker: blocker(candidate_sha256, *candidate, Vec::new()),
        }
    }
}

fn run_counting(restart_after: u64) -> SessionArtifact {
    run_incremental_cegis(
        &mut CountingBackend::default(),
        &mut RejectTwoCandidates,
        context(),
        config(restart_after),
        Vec::new(),
    )
    .unwrap()
}

#[test]
fn same_seed_and_input_produce_identical_transcript() {
    let first = run_counting(64);
    let second = run_counting(64);

    assert_eq!(first, second);
    first.validate().unwrap();
}

#[test]
fn deterministic_restart_preserves_the_bounded_decision() {
    let reused = run_counting(64);
    let restarted = run_counting(1);

    assert_eq!(reused.outcome, SessionOutcome::Unsat);
    assert_eq!(restarted.outcome, reused.outcome);
    assert_eq!(restarted.blockers, reused.blockers);
    assert_eq!(reused.reuse_audit.backend_generations, 1);
    assert_eq!(reused.reuse_audit.incremental_pushes, 2);
    assert_eq!(reused.reuse_audit.reused_solve_calls, 2);
    assert_eq!(restarted.metrics.restarts, 2);
    assert_eq!(restarted.reuse_audit.backend_generations, 3);
    assert_eq!(restarted.reuse_audit.replayed_pushes, 3);
    assert_eq!(restarted.reuse_audit.incremental_pushes, 0);
}

struct UnsatBackend {
    pushed: Vec<String>,
}

impl IncrementalAssertionBackend for UnsatBackend {
    type Candidate = ();

    fn start(&mut self, _context: &SessionContext) -> Result<(), SolverFailure> {
        self.pushed.clear();
        Ok(())
    }

    fn push_blocker(&mut self, blocker: &SessionBlocker) -> Result<(), SolverFailure> {
        self.pushed.push(blocker.blocker_sha256.clone());
        Ok(())
    }

    fn solve(&mut self) -> Result<BackendDecision<Self::Candidate>, SolverFailure> {
        Ok(BackendDecision::Unsat)
    }
}

struct VerifyAll;

impl<Candidate> CandidateChecker<Candidate> for VerifyAll {
    fn check(&mut self, _candidate_sha256: &str, _candidate: &Candidate) -> CheckerDecision {
        CheckerDecision::Verified
    }
}

#[test]
fn duplicate_and_subsumed_initial_blockers_are_suppressed_canonically() {
    let narrow = blocker(&sha256(1), 1, Vec::new());
    let broad = blocker(&sha256(2), 2, vec![narrow.blocker_sha256.clone()]);
    let mut backend = UnsatBackend { pushed: Vec::new() };
    let artifact = run_incremental_cegis(
        &mut backend,
        &mut VerifyAll,
        context(),
        config(64),
        vec![broad.clone(), narrow.clone(), narrow],
    )
    .unwrap();

    assert_eq!(artifact.blockers, vec![broad.clone()]);
    assert_eq!(backend.pushed, vec![broad.blocker_sha256]);
    assert_eq!(artifact.metrics.duplicate_blockers, 1);
    assert_eq!(artifact.metrics.subsumed_blockers, 1);
    assert_eq!(artifact.outcome, SessionOutcome::Unsat);
}

struct TerminalBackend {
    start_failure: Option<SolverFailure>,
    decision: Option<BackendDecision<()>>,
}

impl IncrementalAssertionBackend for TerminalBackend {
    type Candidate = ();

    fn start(&mut self, _context: &SessionContext) -> Result<(), SolverFailure> {
        self.start_failure.take().map_or(Ok(()), Err)
    }

    fn push_blocker(&mut self, _blocker: &SessionBlocker) -> Result<(), SolverFailure> {
        Ok(())
    }

    fn solve(&mut self) -> Result<BackendDecision<Self::Candidate>, SolverFailure> {
        self.decision.take().ok_or(SolverFailure::ProtocolViolation)
    }
}

fn terminal_artifact(
    start_failure: Option<SolverFailure>,
    decision: Option<BackendDecision<()>>,
) -> SessionArtifact {
    run_incremental_cegis(
        &mut TerminalBackend {
            start_failure,
            decision,
        },
        &mut VerifyAll,
        context(),
        config(64),
        Vec::new(),
    )
    .unwrap()
}

#[test]
fn timeout_resource_exhaustion_and_process_failures_never_become_unsat() {
    let cases = [
        terminal_artifact(
            None,
            Some(BackendDecision::Inconclusive {
                reason: SessionInconclusiveReason::Timeout,
            }),
        ),
        terminal_artifact(
            None,
            Some(BackendDecision::Inconclusive {
                reason: SessionInconclusiveReason::ResourceExhausted,
            }),
        ),
        terminal_artifact(Some(SolverFailure::Unavailable), None),
        terminal_artifact(Some(SolverFailure::ProcessExited), None),
    ];

    assert_eq!(
        cases[0].outcome,
        SessionOutcome::Inconclusive {
            reason: SessionInconclusiveReason::Timeout,
        }
    );
    assert_eq!(
        cases[1].outcome,
        SessionOutcome::Inconclusive {
            reason: SessionInconclusiveReason::ResourceExhausted,
        }
    );
    assert_eq!(
        cases[2].outcome,
        SessionOutcome::Inconclusive {
            reason: SessionInconclusiveReason::SolverUnavailable,
        }
    );
    assert_eq!(
        cases[3].outcome,
        SessionOutcome::Inconclusive {
            reason: SessionInconclusiveReason::ProcessFailure,
        }
    );
    assert!(cases
        .iter()
        .all(|artifact| artifact.outcome != SessionOutcome::Unsat));
}

struct WrongSourceChecker;

impl CandidateChecker<()> for WrongSourceChecker {
    fn check(&mut self, _candidate_sha256: &str, _candidate: &()) -> CheckerDecision {
        CheckerDecision::Rejected {
            blocker: blocker(&sha256(9), 9, Vec::new()),
        }
    }
}

#[test]
fn blocker_that_does_not_bind_its_source_candidate_fails_closed() {
    let artifact = run_incremental_cegis(
        &mut TerminalBackend {
            start_failure: None,
            decision: Some(BackendDecision::Candidate {
                candidate_sha256: sha256(1),
                candidate: (),
            }),
        },
        &mut WrongSourceChecker,
        context(),
        config(64),
        Vec::new(),
    )
    .unwrap();

    assert_eq!(
        artifact.outcome,
        SessionOutcome::Inconclusive {
            reason: SessionInconclusiveReason::InvalidBlocker,
        }
    );
    assert_eq!(artifact.metrics.blocker_pushes, 0);
}
