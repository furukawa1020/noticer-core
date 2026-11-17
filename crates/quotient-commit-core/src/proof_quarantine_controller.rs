use crate::proof_contradiction_detector::Contradiction;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuarantineState {
    Active,
    Quarantined { subject: [u8; 16], position: u64 },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuarantineError {
    Quarantined,
    AlreadyQuarantined,
}
pub struct QuarantineController {
    state: QuarantineState,
}
impl QuarantineController {
    pub fn new() -> Self {
        Self {
            state: QuarantineState::Active,
        }
    }
    pub fn quarantine(&mut self, c: Contradiction) -> Result<(), QuarantineError> {
        if !matches!(self.state, QuarantineState::Active) {
            return Err(QuarantineError::AlreadyQuarantined);
        }
        self.state = QuarantineState::Quarantined {
            subject: c.subject,
            position: c.position,
        };
        Ok(())
    }
    pub fn authorize_release(&self) -> Result<(), QuarantineError> {
        if matches!(self.state, QuarantineState::Active) {
            Ok(())
        } else {
            Err(QuarantineError::Quarantined)
        }
    }
    pub fn state(&self) -> QuarantineState {
        self.state
    }
}
impl Default for QuarantineController {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn contradiction() -> Contradiction {
        Contradiction {
            subject: [1; 16],
            position: 2,
            first: [3; 32],
            second: [4; 32],
        }
    }
    #[test]
    fn active_allows_release() {
        assert_eq!(QuarantineController::new().authorize_release(), Ok(()))
    }
    #[test]
    fn quarantine_is_sticky() {
        let mut q = QuarantineController::new();
        q.quarantine(contradiction()).unwrap();
        assert_eq!(q.authorize_release(), Err(QuarantineError::Quarantined));
        assert_eq!(
            q.quarantine(contradiction()),
            Err(QuarantineError::AlreadyQuarantined)
        );
    }
}
