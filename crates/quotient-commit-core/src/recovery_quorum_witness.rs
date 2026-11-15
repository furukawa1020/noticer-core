use crate::recovery_quorum_policy::{QuorumPolicy, QuorumRole};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Member {
    pub id: [u8; 16],
    pub role: QuorumRole,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuorumWitness {
    pub members: Vec<Member>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessError {
    DuplicateMember,
    Unsatisfied,
}
pub fn build(policy: &QuorumPolicy, members: &[Member]) -> Result<QuorumWitness, WitnessError> {
    let mut ids = BTreeSet::new();
    let mut by = BTreeMap::<QuorumRole, Vec<Member>>::new();
    for m in members {
        if !ids.insert(m.id) {
            return Err(WitnessError::DuplicateMember);
        }
        by.entry(m.role).or_default().push(*m)
    }
    let mut out = Vec::new();
    for r in &policy.requirements {
        let list = by.get_mut(&r.role).ok_or(WitnessError::Unsatisfied)?;
        list.sort();
        if list.len() < r.required as usize {
            return Err(WitnessError::Unsatisfied);
        }
        out.extend_from_slice(&list[..r.required as usize]);
    }
    Ok(QuorumWitness { members: out })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery_quorum_policy::{compile, RoleRequirement};
    #[test]
    fn minimal() {
        let p = compile(&[RoleRequirement {
            role: QuorumRole::Operator,
            required: 1,
            available: 2,
        }])
        .unwrap();
        let w = build(
            &p,
            &[
                Member {
                    id: [2; 16],
                    role: QuorumRole::Operator,
                },
                Member {
                    id: [1; 16],
                    role: QuorumRole::Operator,
                },
            ],
        )
        .unwrap();
        assert_eq!(
            w.members,
            vec![Member {
                id: [1; 16],
                role: QuorumRole::Operator
            }]
        )
    }
    #[test]
    fn rejects_duplicate() {
        let p = compile(&[RoleRequirement {
            role: QuorumRole::Operator,
            required: 1,
            available: 2,
        }])
        .unwrap();
        let m = Member {
            id: [1; 16],
            role: QuorumRole::Operator,
        };
        assert_eq!(build(&p, &[m, m]), Err(WitnessError::DuplicateMember));
    }
}
