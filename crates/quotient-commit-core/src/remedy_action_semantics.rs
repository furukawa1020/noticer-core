//! Binding for action semantics that remediation is not allowed to change.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectedActionSemantics {
    relation_digest: [u8; 32],
    action_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SemanticsError {
    ZeroDigest,
    RelationChanged,
    ActionChanged,
}

impl ProtectedActionSemantics {
    pub fn new(relation_digest: [u8; 32], action_digest: [u8; 32]) -> Result<Self, SemanticsError> {
        if relation_digest == [0; 32] || action_digest == [0; 32] {
            return Err(SemanticsError::ZeroDigest);
        }
        Ok(Self {
            relation_digest,
            action_digest,
        })
    }

    pub fn verify_preserved(self, candidate: Self) -> Result<(), SemanticsError> {
        if self.relation_digest != candidate.relation_digest {
            return Err(SemanticsError::RelationChanged);
        }
        if self.action_digest != candidate.action_digest {
            return Err(SemanticsError::ActionChanged);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changed_action_semantics_are_rejected() {
        let baseline = ProtectedActionSemantics::new([1; 32], [2; 32]).unwrap();
        let changed = ProtectedActionSemantics::new([1; 32], [3; 32]).unwrap();
        assert_eq!(
            baseline.verify_preserved(changed),
            Err(SemanticsError::ActionChanged)
        );
    }

    #[test]
    fn zero_binding_is_invalid() {
        assert_eq!(
            ProtectedActionSemantics::new([0; 32], [2; 32]),
            Err(SemanticsError::ZeroDigest)
        );
    }
}
