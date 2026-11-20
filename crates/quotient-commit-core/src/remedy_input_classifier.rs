//! Pre-search classification of malformed or contradictory repair inputs.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepairInputFacts {
    pub certificate_authenticated: bool,
    pub model_bound: bool,
    pub constraints_satisfiable: bool,
    pub targets_inside_boundary: bool,
    pub cause_nonempty: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidInput {
    UnauthenticatedCertificate,
    ModelMismatch,
    ContradictoryConstraints,
    BoundaryViolation,
    EmptyCause,
}

pub fn classify(facts: RepairInputFacts) -> Result<(), InvalidInput> {
    if !facts.certificate_authenticated {
        return Err(InvalidInput::UnauthenticatedCertificate);
    }
    if !facts.model_bound {
        return Err(InvalidInput::ModelMismatch);
    }
    if !facts.constraints_satisfiable {
        return Err(InvalidInput::ContradictoryConstraints);
    }
    if !facts.targets_inside_boundary {
        return Err(InvalidInput::BoundaryViolation);
    }
    if !facts.cause_nonempty {
        return Err(InvalidInput::EmptyCause);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> RepairInputFacts {
        RepairInputFacts {
            certificate_authenticated: true,
            model_bound: true,
            constraints_satisfiable: true,
            targets_inside_boundary: true,
            cause_nonempty: true,
        }
    }

    #[test]
    fn authentication_failure_has_priority() {
        let mut facts = valid();
        facts.certificate_authenticated = false;
        facts.targets_inside_boundary = false;
        assert_eq!(
            classify(facts),
            Err(InvalidInput::UnauthenticatedCertificate)
        );
    }

    #[test]
    fn complete_input_is_admitted() {
        assert_eq!(classify(valid()), Ok(()));
    }
}
