//! Offline, fail-closed verification of canonical recovery proof bundles.

use crate::recovery_proof_bundle::{verify_proof_bundle, RecoveryProofBundle};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationCode {
    Verified,
    InvalidInput,
    UnsupportedVersion,
    InvalidGeneration,
    AuthenticationFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerificationReport {
    pub code: VerificationCode,
    pub anchor_generation: u64,
    pub policy_epoch: u64,
}

#[must_use]
pub fn verify_canonical_json(input: &str, key: [u8; 32]) -> VerificationReport {
    let Some(bundle) = parse(input) else {
        return report(VerificationCode::InvalidInput, 0, 0);
    };
    let code = if bundle.version != 1 {
        VerificationCode::UnsupportedVersion
    } else if bundle.anchor_generation == 0 || bundle.policy_epoch == 0 {
        VerificationCode::InvalidGeneration
    } else if verify_proof_bundle(bundle, key).is_err() {
        VerificationCode::AuthenticationFailed
    } else {
        VerificationCode::Verified
    };
    report(code, bundle.anchor_generation, bundle.policy_epoch)
}

#[must_use]
pub fn canonical_report(value: VerificationReport) -> String {
    format!(
        "{{\"schema\":\"noticer.recovery-proof-verification.v1\",\"accepted\":{},\"code\":\"{}\",\"anchor_generation\":{},\"policy_epoch\":{}}}",
        value.code == VerificationCode::Verified,
        code_name(value.code),
        value.anchor_generation,
        value.policy_epoch
    )
}

fn report(code: VerificationCode, anchor_generation: u64, policy_epoch: u64) -> VerificationReport {
    VerificationReport {
        code,
        anchor_generation,
        policy_epoch,
    }
}

fn parse(input: &str) -> Option<RecoveryProofBundle> {
    let schema = string_field(input, "schema")?;
    if schema != "noticer.recovery-proof-bundle.v1" {
        return None;
    }
    Some(RecoveryProofBundle {
        version: 1,
        anchor_generation: number_field(input, "anchor_generation")?,
        policy_epoch: number_field(input, "policy_epoch")?,
        certificate_authenticator: digest_field(input, "certificate_authenticator")?,
        anchor_authenticator: digest_field(input, "anchor_authenticator")?,
        admission_authenticator: digest_field(input, "admission_authenticator")?,
        witness_authenticator: digest_field(input, "witness_authenticator")?,
        ceremony_authenticator: digest_field(input, "ceremony_authenticator")?,
        authenticator: digest_field(input, "authenticator")?,
    })
}

fn string_field<'a>(input: &'a str, name: &str) -> Option<&'a str> {
    let marker = format!("\"{name}\":\"");
    let rest = input.split_once(&marker)?.1;
    Some(rest.split_once('"')?.0)
}
fn number_field(input: &str, name: &str) -> Option<u64> {
    let marker = format!("\"{name}\":");
    let rest = input.split_once(&marker)?.1;
    let end = rest.find([',', '}']).unwrap_or(rest.len());
    rest[..end].parse().ok()
}
fn digest_field(input: &str, name: &str) -> Option<[u8; 32]> {
    let value = string_field(input, name)?;
    if value.len() != 64 {
        return None;
    }
    let mut out = [0; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(out)
}
fn code_name(code: VerificationCode) -> &'static str {
    match code {
        VerificationCode::Verified => "verified",
        VerificationCode::InvalidInput => "invalid_input",
        VerificationCode::UnsupportedVersion => "unsupported_version",
        VerificationCode::InvalidGeneration => "invalid_generation",
        VerificationCode::AuthenticationFailed => "authentication_failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery_proof_bundle::canonical_json;

    #[test]
    fn malformed_and_tampered_inputs_fail_closed() {
        assert_eq!(
            verify_canonical_json("{}", [7; 32]).code,
            VerificationCode::InvalidInput
        );
        let bundle = RecoveryProofBundle {
            version: 1,
            anchor_generation: 2,
            policy_epoch: 3,
            certificate_authenticator: [1; 32],
            anchor_authenticator: [2; 32],
            admission_authenticator: [3; 32],
            witness_authenticator: [4; 32],
            ceremony_authenticator: [5; 32],
            authenticator: [6; 32],
        };
        let value = verify_canonical_json(&canonical_json(bundle), [7; 32]);
        assert_eq!(value.code, VerificationCode::AuthenticationFailed);
        assert!(canonical_report(value).contains("\"accepted\":false"));
    }
}
