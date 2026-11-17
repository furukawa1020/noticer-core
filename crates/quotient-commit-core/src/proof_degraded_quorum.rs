use crate::proof_availability_vector::{AvailabilityVector, ProofComponent};
use std::collections::BTreeSet;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentRequirement {
    pub component: ProofComponent,
    pub minimum_regions: usize,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DegradedPolicy {
    pub requirements: Vec<ComponentRequirement>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DegradedError {
    Empty,
    DuplicateComponent,
    ZeroMinimum,
    Unsatisfied,
}
pub fn compile(requirements: &[ComponentRequirement]) -> Result<DegradedPolicy, DegradedError> {
    if requirements.is_empty() {
        return Err(DegradedError::Empty);
    }
    let mut seen = BTreeSet::new();
    for r in requirements {
        if r.minimum_regions == 0 {
            return Err(DegradedError::ZeroMinimum);
        }
        if !seen.insert(r.component) {
            return Err(DegradedError::DuplicateComponent);
        }
    }
    let mut out = requirements.to_vec();
    out.sort_by_key(|r| r.component);
    Ok(DegradedPolicy { requirements: out })
}
pub fn evaluate(policy: &DegradedPolicy, vector: &AvailabilityVector) -> Result<(), DegradedError> {
    for r in &policy.requirements {
        let count = vector
            .cells
            .iter()
            .filter(|c| c.component == r.component && c.available)
            .map(|c| c.region)
            .collect::<BTreeSet<_>>()
            .len();
        if count < r.minimum_regions {
            return Err(DegradedError::Unsatisfied);
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof_availability_vector::{normalize, AvailabilityCell};
    #[test]
    fn accepts_safe_degradation() {
        let p = compile(&[ComponentRequirement {
            component: ProofComponent::Audit,
            minimum_regions: 1,
        }])
        .unwrap();
        let v = normalize(&[AvailabilityCell {
            region: 1,
            component: ProofComponent::Audit,
            available: true,
        }])
        .unwrap();
        assert_eq!(evaluate(&p, &v), Ok(()))
    }
    #[test]
    fn rejects_loss() {
        let p = compile(&[ComponentRequirement {
            component: ProofComponent::Audit,
            minimum_regions: 1,
        }])
        .unwrap();
        let v = normalize(&[AvailabilityCell {
            region: 1,
            component: ProofComponent::Audit,
            available: false,
        }])
        .unwrap();
        assert_eq!(evaluate(&p, &v), Err(DegradedError::Unsatisfied));
    }
}
