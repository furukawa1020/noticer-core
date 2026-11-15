use std::collections::BTreeMap;
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum QuorumRole {
    Auditor,
    Operator,
    Commander,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoleRequirement {
    pub role: QuorumRole,
    pub required: u16,
    pub available: u16,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuorumPolicy {
    pub requirements: Vec<RoleRequirement>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyError {
    Empty,
    DuplicateRole,
    ZeroThreshold,
    Unsatisfiable,
}
pub fn compile(input: &[RoleRequirement]) -> Result<QuorumPolicy, PolicyError> {
    if input.is_empty() {
        return Err(PolicyError::Empty);
    }
    let mut m = BTreeMap::new();
    for r in input {
        if r.required == 0 {
            return Err(PolicyError::ZeroThreshold);
        }
        if r.required > r.available {
            return Err(PolicyError::Unsatisfiable);
        }
        if m.insert(r.role, *r).is_some() {
            return Err(PolicyError::DuplicateRole);
        }
    }
    Ok(QuorumPolicy {
        requirements: m.into_values().collect(),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonicalizes() {
        let p = compile(&[
            RoleRequirement {
                role: QuorumRole::Commander,
                required: 1,
                available: 2,
            },
            RoleRequirement {
                role: QuorumRole::Auditor,
                required: 2,
                available: 3,
            },
        ])
        .unwrap();
        assert_eq!(p.requirements[0].role, QuorumRole::Auditor)
    }
    #[test]
    fn rejects_impossible() {
        assert_eq!(
            compile(&[RoleRequirement {
                role: QuorumRole::Operator,
                required: 3,
                available: 2
            }]),
            Err(PolicyError::Unsatisfiable)
        );
    }
}
