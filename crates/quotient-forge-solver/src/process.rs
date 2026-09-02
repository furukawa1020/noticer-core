use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::backend::{OutputStream, RuntimeError, RuntimeOutput, SolverKind, SolverRuntime};
use crate::matrix::{SolverId, SolverMatrix, SolverMatrixError, SolverPlatform};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessLimits {
    pub max_stdin_bytes: usize,
    pub max_stdout_bytes: usize,
    pub max_stderr_bytes: usize,
    pub poll_interval: Duration,
    pub version_timeout: Duration,
}

impl Default for ProcessLimits {
    fn default() -> Self {
        Self {
            max_stdin_bytes: 16 * 1024 * 1024,
            max_stdout_bytes: 1024 * 1024,
            max_stderr_bytes: 1024 * 1024,
            poll_interval: Duration::from_millis(5),
            version_timeout: Duration::from_secs(2),
        }
    }
}

impl ProcessLimits {
    pub fn validate(self) -> Result<Self, ProcessError> {
        if self.max_stdin_bytes == 0
            || self.max_stdout_bytes == 0
            || self.max_stderr_bytes == 0
            || self.poll_interval.is_zero()
            || self.version_timeout.is_zero()
        {
            return Err(ProcessError::InvalidLimits);
        }
        if self.max_stdin_bytes > 64 * 1024 * 1024
            || self.max_stdout_bytes > 16 * 1024 * 1024
            || self.max_stderr_bytes > 16 * 1024 * 1024
            || self.poll_interval > Duration::from_secs(1)
            || self.version_timeout > Duration::from_secs(60)
        {
            return Err(ProcessError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BoundedProcessOutput {
    Completed {
        stdout: String,
        stderr: String,
        success: bool,
    },
    TimedOut,
    OutputLimitExceeded {
        stream: OutputStream,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProcessError {
    InvalidLimits,
    InputLimitExceeded,
    NotFound,
    Io(String),
    NonUtf8Output(OutputStream),
    WorkerPanicked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SolverBinding {
    pub solver: SolverKind,
    pub program: PathBuf,
    pub version_argv: Vec<String>,
    pub solve_argv: Vec<String>,
    pub version_output_prefix: String,
    pub asset_sha256: String,
}

#[derive(Clone, Debug)]
pub struct BoundedSolverRuntime {
    bindings: BTreeMap<SolverKind, SolverBinding>,
    limits: ProcessLimits,
    matrix_sha256: String,
}

impl BoundedSolverRuntime {
    pub fn from_matrix(
        matrix: &SolverMatrix,
        installation_root: &Path,
        platform: SolverPlatform,
        limits: ProcessLimits,
    ) -> Result<Self, RuntimeError> {
        matrix
            .validate()
            .map_err(|error| RuntimeError::InvalidConfiguration(error.to_string()))?;
        let limits = limits
            .validate()
            .map_err(|error| RuntimeError::InvalidConfiguration(format!("{error:?}")))?;
        if installation_root.as_os_str().is_empty() {
            return Err(RuntimeError::InvalidConfiguration(
                "installation root may not be empty".to_owned(),
            ));
        }
        let mut bindings = BTreeMap::new();
        for (id, kind) in [
            (SolverId::Cvc5, SolverKind::Cvc5),
            (SolverId::Z3, SolverKind::Z3),
        ] {
            let pin = matrix.solver(id);
            let asset = matrix.asset(id, platform);
            let relative = asset.executable_path.split('/').collect::<PathBuf>();
            bindings.insert(
                kind,
                SolverBinding {
                    solver: kind,
                    program: installation_root.join(relative),
                    version_argv: pin.commands.version.clone(),
                    solve_argv: pin.commands.solve.clone(),
                    version_output_prefix: pin.version_output_prefix.clone(),
                    asset_sha256: asset.sha256.clone(),
                },
            );
        }
        Ok(Self {
            bindings,
            limits,
            matrix_sha256: matrix.digest_sha256().map_err(matrix_runtime_error)?,
        })
    }

    pub fn binding(&self, solver: SolverKind) -> Option<&SolverBinding> {
        self.bindings.get(&solver)
    }

    pub fn matrix_sha256(&self) -> &str {
        &self.matrix_sha256
    }

    fn execute(
        &self,
        solver: SolverKind,
        argv: &[String],
        input: &[u8],
        timeout: Duration,
    ) -> Result<BoundedProcessOutput, RuntimeError> {
        let binding = self
            .bindings
            .get(&solver)
            .ok_or(RuntimeError::NotInstalled)?;
        run_bounded_process(&binding.program, argv, input, timeout, self.limits)
            .map_err(process_runtime_error)
    }
}

impl SolverRuntime for BoundedSolverRuntime {
    fn program(&self, solver: SolverKind) -> String {
        self.binding(solver).map_or_else(
            || solver.program().to_owned(),
            |binding| binding.program.display().to_string(),
        )
    }

    fn version(&self, solver: SolverKind) -> Result<String, RuntimeError> {
        if solver == SolverKind::Exhaustive {
            return Ok(env!("CARGO_PKG_VERSION").to_owned());
        }
        let binding = self
            .bindings
            .get(&solver)
            .ok_or(RuntimeError::NotInstalled)?;
        match self.execute(
            solver,
            &binding.version_argv,
            b"",
            self.limits.version_timeout,
        )? {
            BoundedProcessOutput::Completed {
                stdout,
                stderr,
                success,
            } if success => {
                let version = stdout.lines().next().unwrap_or_default().trim().to_owned();
                if !version.starts_with(&binding.version_output_prefix) {
                    return Err(RuntimeError::VersionMismatch(version));
                }
                Ok(version)
            }
            BoundedProcessOutput::Completed { stderr, .. } => Err(RuntimeError::Io(format!(
                "version command failed: {}",
                stderr.trim()
            ))),
            BoundedProcessOutput::TimedOut => Err(RuntimeError::TimedOut),
            BoundedProcessOutput::OutputLimitExceeded { stream } => {
                Err(RuntimeError::OutputLimitExceeded(stream))
            }
        }
    }

    fn run(
        &self,
        solver: SolverKind,
        script: &str,
        timeout: Duration,
    ) -> Result<RuntimeOutput, RuntimeError> {
        let binding = self
            .bindings
            .get(&solver)
            .ok_or(RuntimeError::NotInstalled)?;
        match self.execute(solver, &binding.solve_argv, script.as_bytes(), timeout)? {
            BoundedProcessOutput::Completed {
                stdout,
                stderr,
                success,
            } => Ok(RuntimeOutput::Completed {
                stdout,
                stderr,
                success,
            }),
            BoundedProcessOutput::TimedOut => Ok(RuntimeOutput::TimedOut),
            BoundedProcessOutput::OutputLimitExceeded { stream } => {
                Ok(RuntimeOutput::OutputLimitExceeded { stream })
            }
        }
    }
}

pub fn run_bounded_process(
    program: &Path,
    argv: &[String],
    input: &[u8],
    timeout: Duration,
    limits: ProcessLimits,
) -> Result<BoundedProcessOutput, ProcessError> {
    let limits = limits.validate()?;
    if timeout.is_zero() || timeout > Duration::from_secs(24 * 60 * 60) {
        return Err(ProcessError::InvalidLimits);
    }
    if input.len() > limits.max_stdin_bytes {
        return Err(ProcessError::InputLimitExceeded);
    }
    let mut child = Command::new(program)
        .args(argv)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(process_io)?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| ProcessError::Io("child stdin unavailable".to_owned()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ProcessError::Io("child stdout unavailable".to_owned()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| ProcessError::Io("child stderr unavailable".to_owned()))?;

    let stdout_exceeded = Arc::new(AtomicBool::new(false));
    let stderr_exceeded = Arc::new(AtomicBool::new(false));
    let stdout_worker = drain_bounded(
        stdout,
        limits.max_stdout_bytes,
        Arc::clone(&stdout_exceeded),
    );
    let stderr_worker = drain_bounded(
        stderr,
        limits.max_stderr_bytes,
        Arc::clone(&stderr_exceeded),
    );
    let owned_input = input.to_vec();
    let input_worker = thread::spawn(move || {
        let mut stdin = stdin;
        stdin
            .write_all(&owned_input)
            .map_err(|error| error.to_string())
    });

    enum Termination {
        Completed,
        TimedOut,
        OutputLimitExceeded,
    }

    let started = Instant::now();
    let termination = loop {
        if stdout_exceeded.load(Ordering::Acquire) || stderr_exceeded.load(Ordering::Acquire) {
            let _ = child.kill();
            let _ = child.wait();
            break Termination::OutputLimitExceeded;
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            break Termination::TimedOut;
        }
        match child.try_wait().map_err(process_io)? {
            Some(_) => break Termination::Completed,
            None => thread::sleep(limits.poll_interval),
        }
    };

    let input_result = input_worker
        .join()
        .map_err(|_| ProcessError::WorkerPanicked)?;
    let stdout_bytes = join_drain(stdout_worker)?;
    let stderr_bytes = join_drain(stderr_worker)?;
    if stdout_exceeded.load(Ordering::Acquire) {
        return Ok(BoundedProcessOutput::OutputLimitExceeded {
            stream: OutputStream::Stdout,
        });
    }
    if stderr_exceeded.load(Ordering::Acquire) {
        return Ok(BoundedProcessOutput::OutputLimitExceeded {
            stream: OutputStream::Stderr,
        });
    }
    match termination {
        Termination::TimedOut => return Ok(BoundedProcessOutput::TimedOut),
        Termination::OutputLimitExceeded => {
            return Ok(BoundedProcessOutput::OutputLimitExceeded {
                stream: OutputStream::Stdout,
            });
        }
        Termination::Completed => input_result.map_err(ProcessError::Io)?,
    }
    let stdout = String::from_utf8(stdout_bytes)
        .map_err(|_| ProcessError::NonUtf8Output(OutputStream::Stdout))?;
    let stderr = String::from_utf8(stderr_bytes)
        .map_err(|_| ProcessError::NonUtf8Output(OutputStream::Stderr))?;
    let success = child
        .try_wait()
        .map_err(process_io)?
        .is_some_and(|status| status.success());
    Ok(BoundedProcessOutput::Completed {
        stdout,
        stderr,
        success,
    })
}

fn drain_bounded<R: Read + Send + 'static>(
    mut reader: R,
    limit: usize,
    exceeded: Arc<AtomicBool>,
) -> JoinHandle<Result<Vec<u8>, String>> {
    thread::spawn(move || {
        let mut output = Vec::with_capacity(limit.min(64 * 1024));
        let mut buffer = [0_u8; 8192];
        loop {
            let count = reader
                .read(&mut buffer)
                .map_err(|error| error.to_string())?;
            if count == 0 {
                return Ok(output);
            }
            let remaining = limit.saturating_sub(output.len());
            output.extend_from_slice(&buffer[..count.min(remaining)]);
            if count > remaining {
                exceeded.store(true, Ordering::Release);
            }
        }
    })
}

fn join_drain(worker: JoinHandle<Result<Vec<u8>, String>>) -> Result<Vec<u8>, ProcessError> {
    worker
        .join()
        .map_err(|_| ProcessError::WorkerPanicked)?
        .map_err(ProcessError::Io)
}

fn process_io(error: std::io::Error) -> ProcessError {
    if error.kind() == std::io::ErrorKind::NotFound {
        ProcessError::NotFound
    } else {
        ProcessError::Io(error.to_string())
    }
}

fn process_runtime_error(error: ProcessError) -> RuntimeError {
    match error {
        ProcessError::NotFound => RuntimeError::NotInstalled,
        ProcessError::InputLimitExceeded => RuntimeError::InputLimitExceeded,
        ProcessError::NonUtf8Output(stream) => RuntimeError::NonUtf8Output(stream),
        ProcessError::InvalidLimits => {
            RuntimeError::InvalidConfiguration("invalid process limits".to_owned())
        }
        ProcessError::Io(message) => RuntimeError::Io(message),
        ProcessError::WorkerPanicked => RuntimeError::Io("process worker panicked".to_owned()),
    }
}

fn matrix_runtime_error(error: SolverMatrixError) -> RuntimeError {
    RuntimeError::InvalidConfiguration(error.to_string())
}
