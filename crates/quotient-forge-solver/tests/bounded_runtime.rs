use std::env;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use quotient_forge_solver::{
    run_bounded_process, BoundedProcessOutput, BoundedSolverRuntime, OutputStream, ProcessError,
    ProcessLimits, SolverKind, SolverMatrix, SolverPlatform, SolverRuntime,
};

fn fixture_argv() -> Vec<String> {
    vec![
        "--exact".to_owned(),
        "runtime_fixture_process".to_owned(),
        "--nocapture".to_owned(),
    ]
}

fn tiny_limits() -> ProcessLimits {
    ProcessLimits {
        max_stdin_bytes: 1024,
        max_stdout_bytes: 4096,
        max_stderr_bytes: 4096,
        poll_interval: Duration::from_millis(2),
        version_timeout: Duration::from_secs(1),
    }
}

#[test]
fn runtime_fixture_process() {
    let mut command = String::new();
    std::io::stdin().read_to_string(&mut command).unwrap();
    match command.trim() {
        "OK" => println!("BOUNDED_OK"),
        "STDOUT_LIMIT" => {
            let chunk = vec![b'x'; 8192];
            for _ in 0..256 {
                if std::io::stdout().write_all(&chunk).is_err() {
                    break;
                }
            }
        }
        "STDERR_LIMIT" => {
            let chunk = vec![b'e'; 8192];
            for _ in 0..256 {
                if std::io::stderr().write_all(&chunk).is_err() {
                    break;
                }
            }
        }
        "NON_UTF8" => {
            std::io::stdout().write_all(&[0xff, 0xfe]).unwrap();
        }
        "TIMEOUT" => thread::sleep(Duration::from_secs(10)),
        _ => {}
    }
}

#[test]
fn completed_process_is_captured_without_a_shell() {
    let output = run_bounded_process(
        &env::current_exe().unwrap(),
        &fixture_argv(),
        b"OK",
        Duration::from_secs(2),
        tiny_limits(),
    )
    .unwrap();
    let BoundedProcessOutput::Completed {
        stdout, success, ..
    } = output
    else {
        panic!("expected completed process");
    };
    assert!(success);
    assert!(stdout.contains("BOUNDED_OK"));
}

#[test]
fn stdout_and_stderr_limits_are_distinct() {
    for (command, expected) in [
        (b"STDOUT_LIMIT".as_slice(), OutputStream::Stdout),
        (b"STDERR_LIMIT".as_slice(), OutputStream::Stderr),
    ] {
        let output = run_bounded_process(
            &env::current_exe().unwrap(),
            &fixture_argv(),
            command,
            Duration::from_secs(2),
            tiny_limits(),
        )
        .unwrap();
        assert_eq!(
            output,
            BoundedProcessOutput::OutputLimitExceeded { stream: expected }
        );
    }
}

#[test]
fn timeout_kills_and_reaps_the_child() {
    let started = Instant::now();
    let output = run_bounded_process(
        &env::current_exe().unwrap(),
        &fixture_argv(),
        b"TIMEOUT",
        Duration::from_millis(50),
        tiny_limits(),
    )
    .unwrap();
    assert_eq!(output, BoundedProcessOutput::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn invalid_utf8_and_oversized_stdin_are_typed() {
    assert_eq!(
        run_bounded_process(
            &env::current_exe().unwrap(),
            &fixture_argv(),
            b"NON_UTF8",
            Duration::from_secs(2),
            tiny_limits(),
        ),
        Err(ProcessError::NonUtf8Output(OutputStream::Stdout))
    );
    assert_eq!(
        run_bounded_process(
            &env::current_exe().unwrap(),
            &fixture_argv(),
            &vec![0_u8; 1025],
            Duration::from_secs(2),
            tiny_limits(),
        ),
        Err(ProcessError::InputLimitExceeded)
    );
}

#[test]
fn matrix_derives_cross_platform_paths_and_fixed_argv() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let matrix =
        SolverMatrix::from_path(&root.join("configs/quotient_forge/solver_matrix_v1.json"))
            .unwrap();
    let windows = BoundedSolverRuntime::from_matrix(
        &matrix,
        &PathBuf::from("solver-root"),
        SolverPlatform::WindowsX86_64,
        ProcessLimits::default(),
    )
    .unwrap();
    let binding = windows.binding(SolverKind::Z3).unwrap();
    assert!(binding.program.ends_with("z3-4.16.0-x64-win/bin/z3.exe"));
    assert_eq!(binding.solve_argv, ["-in", "-smt2"]);
    assert_eq!(windows.matrix_sha256(), matrix.digest_sha256().unwrap());
    assert!(windows.program(SolverKind::Z3).ends_with("z3.exe"));

    let linux = BoundedSolverRuntime::from_matrix(
        &matrix,
        &PathBuf::from("solver-root"),
        SolverPlatform::LinuxX86_64,
        ProcessLimits::default(),
    )
    .unwrap();
    assert!(linux
        .binding(SolverKind::Cvc5)
        .unwrap()
        .program
        .ends_with("bin/cvc5"));
}
