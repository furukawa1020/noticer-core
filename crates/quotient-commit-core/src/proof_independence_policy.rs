use crate::proof_producer_identity::ProducerFamily;
use std::collections::BTreeSet;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndependencePolicy {
    pub allowed_families: Vec<ProducerFamily>,
    pub minimum_families: usize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyError {
    Empty,
    DuplicateFamily,
    InvalidMinimum,
}
pub fn compile(
    families: &[ProducerFamily],
    minimum_families: usize,
) -> Result<IndependencePolicy, PolicyError> {
    if families.is_empty() {
        return Err(PolicyError::Empty);
    }
    let set = families.iter().copied().collect::<BTreeSet<_>>();
    if set.len() != families.len() {
        return Err(PolicyError::DuplicateFamily);
    }
    if minimum_families == 0 || minimum_families > set.len() {
        return Err(PolicyError::InvalidMinimum);
    }
    Ok(IndependencePolicy {
        allowed_families: set.into_iter().collect(),
        minimum_families,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonicalizes() {
        let p = compile(&[ProducerFamily::Wasm, ProducerFamily::Native], 2).unwrap();
        assert_eq!(
            p.allowed_families,
            vec![ProducerFamily::Native, ProducerFamily::Wasm]
        )
    }
    #[test]
    fn rejects_impossible() {
        assert_eq!(
            compile(&[ProducerFamily::Native], 2),
            Err(PolicyError::InvalidMinimum)
        );
    }
}
