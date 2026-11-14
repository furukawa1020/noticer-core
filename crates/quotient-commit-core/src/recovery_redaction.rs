//! Fail-closed redaction verification for recovery postmortems.
use std::collections::BTreeSet;
const MAX_FIELDS: usize = 64;
const MAX_BYTES: usize = 16_384;
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PublicField {
    ReasonCode,
    ArtifactDigest,
    PolicyEpoch,
    TimeBucket,
    GateResult,
    RemediationCode,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedactedField {
    pub field: PublicField,
    pub value: String,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedactionError {
    Empty,
    TooManyFields,
    TooLarge,
    DuplicateField,
    EmptyValue,
    ForbiddenContent,
    ControlCharacter,
}
pub fn verify(fields: &[RedactedField]) -> Result<(), RedactionError> {
    if fields.is_empty() {
        return Err(RedactionError::Empty);
    }
    if fields.len() > MAX_FIELDS {
        return Err(RedactionError::TooManyFields);
    }
    if fields.iter().map(|f| f.value.len()).sum::<usize>() > MAX_BYTES {
        return Err(RedactionError::TooLarge);
    }
    let mut seen = BTreeSet::new();
    for f in fields {
        if !seen.insert(f.field) {
            return Err(RedactionError::DuplicateField);
        }
        if f.value.is_empty() {
            return Err(RedactionError::EmptyValue);
        }
        if f.value.chars().any(char::is_control) {
            return Err(RedactionError::ControlCharacter);
        }
        let lower = f.value.to_ascii_lowercase();
        if [
            "subject",
            "identity",
            "biosignal",
            "ppg",
            "ibi",
            "secret_key",
            "raw_signal",
        ]
        .iter()
        .any(|term| lower.contains(term))
        {
            return Err(RedactionError::ForbiddenContent);
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn allowlisted_public_fields_pass() {
        assert_eq!(
            verify(&[
                RedactedField {
                    field: PublicField::ReasonCode,
                    value: "LEASE_FENCED".into()
                },
                RedactedField {
                    field: PublicField::ArtifactDigest,
                    value: "a1b2".into()
                }
            ]),
            Ok(())
        )
    }
    #[test]
    fn private_words_duplicates_and_size_fail() {
        assert_eq!(
            verify(&[RedactedField {
                field: PublicField::ReasonCode,
                value: "raw_signal leaked".into()
            }]),
            Err(RedactionError::ForbiddenContent)
        );
        let f = RedactedField {
            field: PublicField::ReasonCode,
            value: "x".into(),
        };
        assert_eq!(verify(&[f.clone(), f]), Err(RedactionError::DuplicateField));
        assert_eq!(
            verify(&[RedactedField {
                field: PublicField::ReasonCode,
                value: "x".repeat(MAX_BYTES + 1)
            }]),
            Err(RedactionError::TooLarge)
        );
    }
}
