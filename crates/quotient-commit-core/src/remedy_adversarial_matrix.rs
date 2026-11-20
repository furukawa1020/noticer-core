//! Canonical adversarial campaign for the repair proof boundary.

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RepairAttack {
    CertificateSubstitution,
    PatchMutation,
    SemanticDrift,
    FailOpenReplay,
    BudgetConfusion,
    BoundaryEscape,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttackObservation {
    pub attack: RepairAttack,
    pub blocked: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdversarialMatrix {
    observations: Vec<AttackObservation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatrixError {
    Incomplete,
    DuplicateAttack,
    AttackSucceeded(RepairAttack),
}

impl AdversarialMatrix {
    pub fn verify(mut observations: Vec<AttackObservation>) -> Result<Self, MatrixError> {
        observations.sort_by_key(|item| item.attack);
        if observations
            .windows(2)
            .any(|pair| pair[0].attack == pair[1].attack)
        {
            return Err(MatrixError::DuplicateAttack);
        }
        let expected = [
            RepairAttack::CertificateSubstitution,
            RepairAttack::PatchMutation,
            RepairAttack::SemanticDrift,
            RepairAttack::FailOpenReplay,
            RepairAttack::BudgetConfusion,
            RepairAttack::BoundaryEscape,
        ];
        if observations.iter().map(|item| item.attack).ne(expected) {
            return Err(MatrixError::Incomplete);
        }
        if let Some(item) = observations.iter().find(|item| !item.blocked) {
            return Err(MatrixError::AttackSucceeded(item.attack));
        }
        Ok(Self { observations })
    }

    #[must_use]
    pub fn passed(&self) -> usize {
        self.observations.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_unblocked_attack_fails_the_campaign() {
        let observations = [
            RepairAttack::CertificateSubstitution,
            RepairAttack::PatchMutation,
            RepairAttack::SemanticDrift,
            RepairAttack::FailOpenReplay,
            RepairAttack::BudgetConfusion,
            RepairAttack::BoundaryEscape,
        ]
        .map(|attack| AttackObservation {
            attack,
            blocked: attack != RepairAttack::SemanticDrift,
        });
        assert_eq!(
            AdversarialMatrix::verify(observations.to_vec()),
            Err(MatrixError::AttackSucceeded(RepairAttack::SemanticDrift))
        );
    }
}
