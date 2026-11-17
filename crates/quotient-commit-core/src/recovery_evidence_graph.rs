use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceNode {
    pub id: u32,
    pub dependencies: Vec<u32>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceGraph {
    nodes: BTreeMap<u32, BTreeSet<u32>>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GraphError {
    Empty,
    Duplicate,
    MissingDependency,
    Cycle,
}
impl EvidenceGraph {
    pub fn compile(input: &[EvidenceNode]) -> Result<Self, GraphError> {
        if input.is_empty() {
            return Err(GraphError::Empty);
        }
        let mut nodes: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
        for n in input {
            if nodes
                .insert(n.id, n.dependencies.iter().copied().collect())
                .is_some()
            {
                return Err(GraphError::Duplicate);
            }
        }
        if nodes
            .iter()
            .any(|(id, deps)| deps.contains(id) || deps.iter().any(|d| !nodes.contains_key(d)))
        {
            return Err(GraphError::MissingDependency);
        }
        let mut done = BTreeSet::new();
        while done.len() < nodes.len() {
            let ready = nodes.iter().find_map(|(id, deps)| {
                (!done.contains(id) && deps.is_subset(&done)).then_some(*id)
            });
            let Some(id) = ready else {
                return Err(GraphError::Cycle);
            };
            done.insert(id);
        }
        Ok(Self { nodes })
    }
    pub fn dependencies(&self, id: u32) -> Option<&BTreeSet<u32>> {
        self.nodes.get(&id)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compiles_dag() {
        let g = EvidenceGraph::compile(&[
            EvidenceNode {
                id: 2,
                dependencies: vec![1],
            },
            EvidenceNode {
                id: 1,
                dependencies: vec![],
            },
        ])
        .unwrap();
        assert_eq!(g.dependencies(2).unwrap(), &BTreeSet::from([1]));
    }
    #[test]
    fn rejects_cycle() {
        assert_eq!(
            EvidenceGraph::compile(&[
                EvidenceNode {
                    id: 1,
                    dependencies: vec![2]
                },
                EvidenceNode {
                    id: 2,
                    dependencies: vec![1]
                }
            ]),
            Err(GraphError::Cycle)
        );
    }
}
