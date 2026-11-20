//! Inclusion minimality evidence for a successful repair.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubsetCheck {
    pub removed_edit_index: usize,
    pub failure_prevented: bool,
    pub semantics_preserved: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MinimalityError {
    EmptyRepair,
    IncompleteSubsetChecks,
    DuplicateSubsetCheck,
    NonMinimal { removable_edit_index: usize },
}

pub fn verify(edit_count: usize, checks: &[SubsetCheck]) -> Result<(), MinimalityError> {
    if edit_count == 0 {
        return Err(MinimalityError::EmptyRepair);
    }
    if checks.len() != edit_count {
        return Err(MinimalityError::IncompleteSubsetChecks);
    }
    let mut seen = vec![false; edit_count];
    for check in checks {
        let Some(entry) = seen.get_mut(check.removed_edit_index) else {
            return Err(MinimalityError::IncompleteSubsetChecks);
        };
        if *entry {
            return Err(MinimalityError::DuplicateSubsetCheck);
        }
        *entry = true;
        if check.failure_prevented && check.semantics_preserved {
            return Err(MinimalityError::NonMinimal {
                removable_edit_index: check.removed_edit_index,
            });
        }
    }
    if seen.iter().all(|seen| *seen) {
        Ok(())
    } else {
        Err(MinimalityError::IncompleteSubsetChecks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removable_edit_breaks_minimality() {
        assert_eq!(
            verify(
                2,
                &[
                    SubsetCheck {
                        removed_edit_index: 0,
                        failure_prevented: false,
                        semantics_preserved: true
                    },
                    SubsetCheck {
                        removed_edit_index: 1,
                        failure_prevented: true,
                        semantics_preserved: true
                    },
                ]
            ),
            Err(MinimalityError::NonMinimal {
                removable_edit_index: 1
            })
        );
    }

    #[test]
    fn every_single_removal_must_fail() {
        assert_eq!(
            verify(
                2,
                &[
                    SubsetCheck {
                        removed_edit_index: 1,
                        failure_prevented: false,
                        semantics_preserved: true
                    },
                    SubsetCheck {
                        removed_edit_index: 0,
                        failure_prevented: false,
                        semantics_preserved: true
                    },
                ]
            ),
            Ok(())
        );
    }
}
