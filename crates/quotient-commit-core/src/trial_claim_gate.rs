//! Fail-closed gate for publication-facing comparative claims.

use crate::trial_noninferiority::NonInferiorityResult;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimEvidence {
    pub reproducible: bool,
    pub matrix_complete: bool,
    pub authenticated: bool,
    pub confidence_interval_excludes_null: bool,
    pub meaningful_effect: bool,
    pub noninferiority: NonInferiorityResult,
    pub multiplicity_corrected: bool,
    pub censoring_disclosed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimGateError {
    NotReproducible,
    IncompleteMatrix,
    Unauthenticated,
    Uncertain,
    TrivialEffect,
    Inferior,
    UncorrectedMultiplicity,
    HiddenCensoring,
}

pub fn authorize(evidence: ClaimEvidence) -> Result<(), ClaimGateError> {
    if !evidence.reproducible {
        return Err(ClaimGateError::NotReproducible);
    }
    if !evidence.matrix_complete {
        return Err(ClaimGateError::IncompleteMatrix);
    }
    if !evidence.authenticated {
        return Err(ClaimGateError::Unauthenticated);
    }
    if !evidence.confidence_interval_excludes_null {
        return Err(ClaimGateError::Uncertain);
    }
    if !evidence.meaningful_effect {
        return Err(ClaimGateError::TrivialEffect);
    }
    if evidence.noninferiority != NonInferiorityResult::Pass {
        return Err(ClaimGateError::Inferior);
    }
    if !evidence.multiplicity_corrected {
        return Err(ClaimGateError::UncorrectedMultiplicity);
    }
    if !evidence.censoring_disclosed {
        return Err(ClaimGateError::HiddenCensoring);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn valid() -> ClaimEvidence {
        ClaimEvidence {
            reproducible: true,
            matrix_complete: true,
            authenticated: true,
            confidence_interval_excludes_null: true,
            meaningful_effect: true,
            noninferiority: NonInferiorityResult::Pass,
            multiplicity_corrected: true,
            censoring_disclosed: true,
        }
    }
    #[test]
    fn every_publication_gate_is_mandatory() {
        assert_eq!(authorize(valid()), Ok(()));
        let mut hidden = valid();
        hidden.censoring_disclosed = false;
        assert_eq!(authorize(hidden), Err(ClaimGateError::HiddenCensoring));
    }
}
