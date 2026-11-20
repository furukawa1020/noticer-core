//! Monotonic privacy check for repaired public traces.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivacyEvidence {
    pub baseline_distinctions: u32,
    pub repaired_distinctions: u32,
    pub action_classes: u32,
    pub observer_model_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivacyError {
    ZeroObserverModel,
    NoActionClasses,
    NewPrivateDistinction,
}

pub fn verify(evidence: PrivacyEvidence) -> Result<(), PrivacyError> {
    if evidence.observer_model_digest == [0; 32] {
        return Err(PrivacyError::ZeroObserverModel);
    }
    if evidence.action_classes == 0 {
        return Err(PrivacyError::NoActionClasses);
    }
    if evidence.repaired_distinctions > evidence.baseline_distinctions {
        return Err(PrivacyError::NewPrivateDistinction);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privacy_must_not_degrade() {
        assert_eq!(
            verify(PrivacyEvidence {
                baseline_distinctions: 1,
                repaired_distinctions: 2,
                action_classes: 1,
                observer_model_digest: [1; 32]
            }),
            Err(PrivacyError::NewPrivateDistinction)
        );
        assert_eq!(
            verify(PrivacyEvidence {
                baseline_distinctions: 2,
                repaired_distinctions: 1,
                action_classes: 1,
                observer_model_digest: [1; 32]
            }),
            Ok(())
        );
    }
}
