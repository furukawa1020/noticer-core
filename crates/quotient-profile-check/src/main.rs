#![forbid(unsafe_code)]

use std::{env, fs, process::ExitCode};

use quotient_profile_check::{check_aqpc, CheckerMode};

fn main() -> ExitCode {
    let Some(path) = env::args_os().nth(1) else {
        eprintln!("usage: aqpc-check <profile.aqpc>");
        return ExitCode::from(2);
    };
    let Ok(bytes) = fs::read(path) else {
        println!("INVALID_PROFILE");
        return ExitCode::from(1);
    };
    let verdict = check_aqpc(&bytes, CheckerMode::Production, None);
    println!("{}", verdict.as_str());
    if verdict == quotient_profile_check::CheckVerdict::ValidProfile {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
