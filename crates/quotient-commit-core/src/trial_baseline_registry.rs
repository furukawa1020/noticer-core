//! Closed baseline registry preventing post-hoc comparator substitution.

use crate::trial_system_descriptor::EvaluatedSystemKind;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BaselineRegistry {
    entries: BTreeMap<String, EvaluatedSystemKind>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BaselineRegistryError {
    Empty,
    UnsafeName,
    DuplicateName,
}

impl BaselineRegistry {
    pub fn new(
        entries: impl IntoIterator<Item = (String, EvaluatedSystemKind)>,
    ) -> Result<Self, BaselineRegistryError> {
        let mut map = BTreeMap::new();
        for (name, kind) in entries {
            if name.is_empty() || !name.is_ascii() || name.contains(['=', ':']) {
                return Err(BaselineRegistryError::UnsafeName);
            }
            if map.insert(name, kind).is_some() {
                return Err(BaselineRegistryError::DuplicateName);
            }
        }
        if map.is_empty() {
            return Err(BaselineRegistryError::Empty);
        }
        Ok(Self { entries: map })
    }
    #[must_use]
    pub fn entries(&self) -> &BTreeMap<String, EvaluatedSystemKind> {
        &self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registry_is_nonempty_and_named_publicly() {
        assert_eq!(BaselineRegistry::new([]), Err(BaselineRegistryError::Empty));
        assert!(
            BaselineRegistry::new([("fixed-rate".into(), EvaluatedSystemKind::FixedRate)]).is_ok()
        );
    }
}
