//! Separates patch size, semantic distance, search effort, and time.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepairCostMetric {
    pub edits: u32,
    pub semantic_distance: u32,
    pub explored_nodes: u64,
    pub elapsed_nanos: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairCostError {
    EmptyRepair,
    NoSearch,
    ZeroElapsed,
}

impl RepairCostMetric {
    pub fn new(
        edits: u32,
        semantic_distance: u32,
        explored_nodes: u64,
        elapsed_nanos: u64,
    ) -> Result<Self, RepairCostError> {
        if edits == 0 {
            return Err(RepairCostError::EmptyRepair);
        }
        if explored_nodes == 0 {
            return Err(RepairCostError::NoSearch);
        }
        if elapsed_nanos == 0 {
            return Err(RepairCostError::ZeroElapsed);
        }
        Ok(Self {
            edits,
            semantic_distance,
            explored_nodes,
            elapsed_nanos,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn no_op_is_not_reported_as_a_repair() {
        assert_eq!(
            RepairCostMetric::new(0, 0, 1, 1),
            Err(RepairCostError::EmptyRepair)
        );
    }
}
