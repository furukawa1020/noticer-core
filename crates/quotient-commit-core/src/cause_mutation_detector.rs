//! Field-level mutation diagnostics for causality certificates.

use crate::{
    cause_certificate::CausalityCertificate, cause_certificate_auth::AuthenticatedCertificate,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationReport {
    Clean,
    Version,
    Model,
    ActualWorld,
    Witness,
    Predicate,
    Exploration,
    Replay,
    Verdict,
    Authentication,
}

pub fn inspect(
    key: [u8; 32],
    trusted: &CausalityCertificate,
    candidate: &AuthenticatedCertificate,
) -> MutationReport {
    if candidate.verify(key) && &candidate.certificate == trusted {
        return MutationReport::Clean;
    }
    let value = &candidate.certificate;
    if value.version != trusted.version {
        MutationReport::Version
    } else if value.model_digest != trusted.model_digest {
        MutationReport::Model
    } else if value.actual_world_digest != trusted.actual_world_digest {
        MutationReport::ActualWorld
    } else if value.witness_digest != trusted.witness_digest {
        MutationReport::Witness
    } else if value.predicate_code != trusted.predicate_code {
        MutationReport::Predicate
    } else if value.explored_worlds != trusted.explored_worlds {
        MutationReport::Exploration
    } else if value.replay_digests != trusted.replay_digests {
        MutationReport::Replay
    } else if value.verdict != trusted.verdict {
        MutationReport::Verdict
    } else {
        MutationReport::Authentication
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cause_verdict::CausalityVerdict;

    fn certificate() -> CausalityCertificate {
        CausalityCertificate::create(
            [1; 32],
            [2; 32],
            [3; 32],
            1,
            5,
            [[4; 32], [4; 32]],
            CausalityVerdict::Causal {
                cause_size: 1,
                contingency_size: 0,
            },
        )
        .unwrap()
    }

    #[test]
    fn unchanged_certificate_is_clean() {
        let trusted = certificate();
        let envelope = AuthenticatedCertificate::issue([8; 32], trusted.clone());
        assert_eq!(inspect([8; 32], &trusted, &envelope), MutationReport::Clean);
    }

    #[test]
    fn witness_and_verdict_mutations_are_distinct() {
        let trusted = certificate();
        let mut witness = AuthenticatedCertificate::issue([8; 32], trusted.clone());
        witness.certificate.witness_digest[0] ^= 1;
        assert_eq!(
            inspect([8; 32], &trusted, &witness),
            MutationReport::Witness
        );

        let mut verdict = AuthenticatedCertificate::issue([8; 32], trusted.clone());
        verdict.certificate.verdict = CausalityVerdict::NonCausal {
            examined_interventions: 5,
        };
        assert_eq!(
            inspect([8; 32], &trusted, &verdict),
            MutationReport::Verdict
        );
    }

    #[test]
    fn replay_mutation_is_detected() {
        let trusted = certificate();
        let mut envelope = AuthenticatedCertificate::issue([8; 32], trusted.clone());
        envelope.certificate.replay_digests[1][0] ^= 1;
        assert_eq!(
            inspect([8; 32], &trusted, &envelope),
            MutationReport::Replay
        );
    }
}
