use crate::receipt::hmac_sha256;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreComponent {
    pub id: u16,
    pub dependencies: Vec<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestorePlan {
    pub ordered_components: Vec<u16>,
    pub digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanError {
    Empty,
    DuplicateComponent,
    MissingDependency,
    Cycle,
}

pub fn compile(components: &[RestoreComponent], key: [u8; 32]) -> Result<RestorePlan, PlanError> {
    if components.is_empty() {
        return Err(PlanError::Empty);
    }
    let mut graph = BTreeMap::new();
    for component in components {
        if graph
            .insert(
                component.id,
                component
                    .dependencies
                    .iter()
                    .copied()
                    .collect::<BTreeSet<_>>(),
            )
            .is_some()
        {
            return Err(PlanError::DuplicateComponent);
        }
    }
    if graph
        .values()
        .flatten()
        .any(|dependency| !graph.contains_key(dependency))
    {
        return Err(PlanError::MissingDependency);
    }
    let mut completed = BTreeSet::new();
    let mut ordered = Vec::with_capacity(graph.len());
    while ordered.len() < graph.len() {
        let next = graph.iter().find_map(|(id, dependencies)| {
            (!completed.contains(id) && dependencies.is_subset(&completed)).then_some(*id)
        });
        let Some(id) = next else {
            return Err(PlanError::Cycle);
        };
        completed.insert(id);
        ordered.push(id);
    }
    let mut bytes = Vec::with_capacity(ordered.len() * 2 + 24);
    bytes.extend_from_slice(b"noticer.restore-plan.v1");
    for id in &ordered {
        bytes.extend_from_slice(&id.to_be_bytes());
    }
    Ok(RestorePlan {
        ordered_components: ordered,
        digest: hmac_sha256(key, &bytes),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const KEY: [u8; 32] = [4; 32];
    #[test]
    fn compiles_a_deterministic_dependency_order() {
        let components = [
            RestoreComponent {
                id: 3,
                dependencies: vec![1, 2],
            },
            RestoreComponent {
                id: 2,
                dependencies: vec![1],
            },
            RestoreComponent {
                id: 1,
                dependencies: vec![],
            },
        ];
        let plan = compile(&components, KEY).unwrap();
        assert_eq!(plan.ordered_components, vec![1, 2, 3]);
        assert_eq!(plan, compile(&components, KEY).unwrap());
    }
    #[test]
    fn rejects_missing_dependencies_and_cycles() {
        assert_eq!(
            compile(
                &[RestoreComponent {
                    id: 1,
                    dependencies: vec![2]
                }],
                KEY
            ),
            Err(PlanError::MissingDependency)
        );
        let cycle = [
            RestoreComponent {
                id: 1,
                dependencies: vec![2],
            },
            RestoreComponent {
                id: 2,
                dependencies: vec![1],
            },
        ];
        assert_eq!(compile(&cycle, KEY), Err(PlanError::Cycle));
    }
}
