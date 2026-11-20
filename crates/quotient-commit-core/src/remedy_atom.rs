//! Public-safe identifiers for repairable release-machine locations.

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RepairAtom {
    slot: u32,
    target: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairAtomError {
    EmptyTarget,
    TargetTooLong,
    PrivateAssignment,
    NonAsciiTarget,
}

impl RepairAtom {
    pub fn new(slot: u32, target: impl Into<String>) -> Result<Self, RepairAtomError> {
        let target = target.into();
        if target.is_empty() {
            return Err(RepairAtomError::EmptyTarget);
        }
        if target.len() > 64 {
            return Err(RepairAtomError::TargetTooLong);
        }
        if !target.is_ascii() {
            return Err(RepairAtomError::NonAsciiTarget);
        }
        if target.contains(['=', ':']) {
            return Err(RepairAtomError::PrivateAssignment);
        }
        Ok(Self { slot, target })
    }

    #[must_use]
    pub const fn slot(&self) -> u32 {
        self.slot
    }

    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atom_exposes_only_public_location() {
        let atom = RepairAtom::new(7, "release_gate").unwrap();
        assert_eq!(atom.slot(), 7);
        assert_eq!(atom.target(), "release_gate");
    }

    #[test]
    fn assignment_shaped_private_values_are_rejected() {
        assert_eq!(
            RepairAtom::new(1, "heart_rate=147"),
            Err(RepairAtomError::PrivateAssignment)
        );
    }
}
