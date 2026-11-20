//! Public explanation projection that excludes evidence values and internal state.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateRepairExplanation {
    pub public_patch_label: String,
    pub public_reason_code: String,
    pub private_evidence: Vec<u8>,
    pub internal_state: Vec<u8>,
    pub certificate_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicRepairExplanation {
    pub patch_label: String,
    pub reason_code: String,
    pub certificate_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedactionError {
    UnsafeLabel,
    ZeroCertificateDigest,
}

fn safe_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.is_ascii()
        && !value.contains(['=', ':', '\n', '\r'])
}

pub fn redact(
    source: &PrivateRepairExplanation,
) -> Result<PublicRepairExplanation, RedactionError> {
    if !safe_label(&source.public_patch_label) || !safe_label(&source.public_reason_code) {
        return Err(RedactionError::UnsafeLabel);
    }
    if source.certificate_digest == [0; 32] {
        return Err(RedactionError::ZeroCertificateDigest);
    }
    Ok(PublicRepairExplanation {
        patch_label: source.public_patch_label.clone(),
        reason_code: source.public_reason_code.clone(),
        certificate_digest: source.certificate_digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_buffers_do_not_cross_projection() {
        let source = PrivateRepairExplanation {
            public_patch_label: "delay_gate".into(),
            public_reason_code: "cause_blocked".into(),
            private_evidence: vec![147],
            internal_state: vec![9],
            certificate_digest: [1; 32],
        };
        let public = redact(&source).unwrap();
        assert_eq!(public.patch_label, "delay_gate");
        assert!(!format!("{public:?}").contains("147"));
    }

    #[test]
    fn assignment_shaped_label_is_rejected() {
        let source = PrivateRepairExplanation {
            public_patch_label: "hr=147".into(),
            public_reason_code: "cause".into(),
            private_evidence: vec![],
            internal_state: vec![],
            certificate_digest: [1; 32],
        };
        assert_eq!(redact(&source), Err(RedactionError::UnsafeLabel));
    }
}
