use quotient_commit_core::recovery_proof_verifier::{
    canonical_report, verify_canonical_json, VerificationCode,
};
use std::path::PathBuf;

fn main() {
    let mut args = std::env::args().skip(1);
    let mut input: Option<PathBuf> = None;
    let mut key_byte: Option<u8> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--input" => input = args.next().map(PathBuf::from),
            "--key-byte" => key_byte = args.next().and_then(|value| value.parse().ok()),
            _ => usage(),
        }
    }
    let (Some(path), Some(key_byte)) = (input, key_byte) else {
        usage()
    };
    let input = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        eprintln!("failed to read {}: {error}", path.display());
        std::process::exit(2)
    });
    let report = verify_canonical_json(input.trim(), [key_byte; 32]);
    println!("{}", canonical_report(report));
    if report.code != VerificationCode::Verified {
        std::process::exit(1);
    }
}

fn usage() -> ! {
    eprintln!("usage: quotient-proof-verify --input PATH --key-byte 0..255");
    std::process::exit(2)
}
