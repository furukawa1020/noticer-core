use std::ffi::OsString;
use std::process::Command;

use quotient_forge_cli::{CheckCase, CommandName, Options, SolverMode};

#[test]
fn parser_defaults_to_solver_free_mode() {
    let options = Options::parse([OsString::from("check")]).unwrap();
    assert_eq!(options.command, CommandName::Check);
    assert_eq!(options.solver, SolverMode::Off);
    assert_eq!(options.seed, 0);
    assert_eq!(options.check_case, CheckCase::ImmediateRelease);
}

#[test]
fn binary_help_is_japanese_and_lists_all_commands() {
    let output = Command::new(env!("CARGO_BIN_EXE_quotient-forge"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("使用法"));
    for command in CommandName::ALL {
        assert!(stdout.contains(command.as_str()));
    }
}

#[test]
fn unknown_command_is_a_diagnostic_error() {
    let error = Options::parse([OsString::from("unknown")]).unwrap_err();
    assert!(error.to_string().contains("未知のsubcommand"));
}
