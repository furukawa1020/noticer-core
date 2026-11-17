use std::collections::BTreeSet;
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProofComponent {
    Identity,
    Timestamp,
    Quorum,
    Audit,
}
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AvailabilityCell {
    pub region: u16,
    pub component: ProofComponent,
    pub available: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AvailabilityVector {
    pub cells: Vec<AvailabilityCell>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VectorError {
    Empty,
    DuplicateCell,
}
pub fn normalize(cells: &[AvailabilityCell]) -> Result<AvailabilityVector, VectorError> {
    if cells.is_empty() {
        return Err(VectorError::Empty);
    }
    let mut keys = BTreeSet::new();
    for c in cells {
        if !keys.insert((c.region, c.component)) {
            return Err(VectorError::DuplicateCell);
        }
    }
    let mut out = cells.to_vec();
    out.sort();
    Ok(AvailabilityVector { cells: out })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn normalizes() {
        let v = normalize(&[
            AvailabilityCell {
                region: 2,
                component: ProofComponent::Audit,
                available: true,
            },
            AvailabilityCell {
                region: 1,
                component: ProofComponent::Identity,
                available: true,
            },
        ])
        .unwrap();
        assert_eq!(v.cells[0].region, 1)
    }
    #[test]
    fn rejects_duplicate() {
        let c = AvailabilityCell {
            region: 1,
            component: ProofComponent::Audit,
            available: true,
        };
        assert_eq!(normalize(&[c, c]), Err(VectorError::DuplicateCell));
    }
}
