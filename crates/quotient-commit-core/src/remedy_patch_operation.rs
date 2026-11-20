//! Closed, serializable operations accepted by the remediation compiler.

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PatchOperation {
    Disable,
    Substitute { public_code: u16 },
    Clamp { minimum: i32, maximum: i32 },
    Delay { slots: u16 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PatchOperationError {
    ReversedClamp,
    ZeroDelay,
    DelayTooLarge,
}

impl PatchOperation {
    pub fn validate(self) -> Result<Self, PatchOperationError> {
        match self {
            Self::Clamp { minimum, maximum } if minimum > maximum => {
                Err(PatchOperationError::ReversedClamp)
            }
            Self::Delay { slots: 0 } => Err(PatchOperationError::ZeroDelay),
            Self::Delay { slots } if slots > 4096 => Err(PatchOperationError::DelayTooLarge),
            _ => Ok(self),
        }
    }

    #[must_use]
    pub const fn public_tag(self) -> &'static str {
        match self {
            Self::Disable => "disable",
            Self::Substitute { .. } => "substitute",
            Self::Clamp { .. } => "clamp",
            Self::Delay { .. } => "delay",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_operations_validate_deterministically() {
        assert_eq!(
            PatchOperation::Disable.validate(),
            Ok(PatchOperation::Disable)
        );
        assert_eq!(PatchOperation::Delay { slots: 4 }.unwrap_tag(), "delay");
    }

    #[test]
    fn malformed_parameters_fail_closed() {
        assert_eq!(
            PatchOperation::Clamp {
                minimum: 9,
                maximum: 2
            }
            .validate(),
            Err(PatchOperationError::ReversedClamp)
        );
        assert_eq!(
            PatchOperation::Delay { slots: 0 }.validate(),
            Err(PatchOperationError::ZeroDelay)
        );
    }

    trait ValidatedTag {
        fn unwrap_tag(self) -> &'static str;
    }

    impl ValidatedTag for PatchOperation {
        fn unwrap_tag(self) -> &'static str {
            self.validate().unwrap().public_tag()
        }
    }
}
