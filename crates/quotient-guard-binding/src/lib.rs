#![no_std]
#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};

pub const BINDING_DOMAIN: &[u8] = b"QUOTIENT_GUARD_BINDING_V1";
pub type Digest32 = [u8; 32];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BindingComponents {
    pub certificate: Digest32,
    pub mechanism: Digest32,
    pub observer: Digest32,
    pub runtime_config: Digest32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BindingCapsule {
    pub components: BindingComponents,
    pub epoch: u64,
    pub previous_capsule: Digest32,
    pub capsule_digest: Digest32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BindingExpectation {
    pub components: BindingComponents,
    pub minimum_epoch: u64,
    pub previous_capsule: Digest32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingError {
    ZeroComponentDigest,
    CapsuleDigestMismatch,
    CertificateMismatch,
    MechanismMismatch,
    ObserverMismatch,
    RuntimeConfigMismatch,
    EpochRollback,
    PreviousCapsuleMismatch,
}

pub fn seal_binding(
    components: BindingComponents,
    epoch: u64,
    previous_capsule: Digest32,
) -> Result<BindingCapsule, BindingError> {
    validate_components(components)?;
    let capsule_digest = binding_digest(components, epoch, previous_capsule);
    Ok(BindingCapsule {
        components,
        epoch,
        previous_capsule,
        capsule_digest,
    })
}

pub fn verify_binding(
    capsule: &BindingCapsule,
    expected: BindingExpectation,
) -> Result<(), BindingError> {
    validate_components(capsule.components)?;
    if capsule.capsule_digest
        != binding_digest(capsule.components, capsule.epoch, capsule.previous_capsule)
    {
        return Err(BindingError::CapsuleDigestMismatch);
    }
    if capsule.components.certificate != expected.components.certificate {
        return Err(BindingError::CertificateMismatch);
    }
    if capsule.components.mechanism != expected.components.mechanism {
        return Err(BindingError::MechanismMismatch);
    }
    if capsule.components.observer != expected.components.observer {
        return Err(BindingError::ObserverMismatch);
    }
    if capsule.components.runtime_config != expected.components.runtime_config {
        return Err(BindingError::RuntimeConfigMismatch);
    }
    if capsule.epoch < expected.minimum_epoch {
        return Err(BindingError::EpochRollback);
    }
    if capsule.previous_capsule != expected.previous_capsule {
        return Err(BindingError::PreviousCapsuleMismatch);
    }
    Ok(())
}

pub fn binding_digest(
    components: BindingComponents,
    epoch: u64,
    previous_capsule: Digest32,
) -> Digest32 {
    let mut hash = Sha256::new();
    hash.update((BINDING_DOMAIN.len() as u32).to_be_bytes());
    hash.update(BINDING_DOMAIN);
    for digest in [
        components.certificate,
        components.mechanism,
        components.observer,
        components.runtime_config,
        previous_capsule,
    ] {
        hash.update(digest);
    }
    hash.update(epoch.to_be_bytes());
    hash.finalize().into()
}

fn validate_components(components: BindingComponents) -> Result<(), BindingError> {
    if [
        components.certificate,
        components.mechanism,
        components.observer,
        components.runtime_config,
    ]
    .contains(&[0; 32])
    {
        return Err(BindingError::ZeroComponentDigest);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn components() -> BindingComponents {
        BindingComponents {
            certificate: [1; 32],
            mechanism: [2; 32],
            observer: [3; 32],
            runtime_config: [4; 32],
        }
    }

    fn expectation(epoch: u64, previous: Digest32) -> BindingExpectation {
        BindingExpectation {
            components: components(),
            minimum_epoch: epoch,
            previous_capsule: previous,
        }
    }

    #[test]
    fn exact_binding_and_chain_are_accepted() {
        let previous = [9; 32];
        let capsule = seal_binding(components(), 7, previous).unwrap();
        assert_eq!(verify_binding(&capsule, expectation(7, previous)), Ok(()));
    }

    #[test]
    fn every_component_substitution_has_a_distinct_error() {
        let previous = [9; 32];
        let capsule = seal_binding(components(), 7, previous).unwrap();
        let cases = [
            (0, BindingError::CertificateMismatch),
            (1, BindingError::MechanismMismatch),
            (2, BindingError::ObserverMismatch),
            (3, BindingError::RuntimeConfigMismatch),
        ];
        for (index, error) in cases {
            let mut expected = components();
            match index {
                0 => expected.certificate[0] ^= 1,
                1 => expected.mechanism[0] ^= 1,
                2 => expected.observer[0] ^= 1,
                _ => expected.runtime_config[0] ^= 1,
            }
            assert_eq!(
                verify_binding(
                    &capsule,
                    BindingExpectation {
                        components: expected,
                        minimum_epoch: 7,
                        previous_capsule: previous,
                    },
                ),
                Err(error)
            );
        }
    }

    #[test]
    fn capsule_mutation_is_rejected_before_component_acceptance() {
        let previous = [9; 32];
        let mut capsule = seal_binding(components(), 7, previous).unwrap();
        capsule.mechanism_mutation_for_test();
        assert_eq!(
            verify_binding(&capsule, expectation(7, previous)),
            Err(BindingError::CapsuleDigestMismatch)
        );
    }

    #[test]
    fn epoch_rollback_and_chain_splice_are_rejected() {
        let previous = [9; 32];
        let capsule = seal_binding(components(), 7, previous).unwrap();
        assert_eq!(
            verify_binding(&capsule, expectation(8, previous)),
            Err(BindingError::EpochRollback)
        );
        assert_eq!(
            verify_binding(&capsule, expectation(7, [8; 32])),
            Err(BindingError::PreviousCapsuleMismatch)
        );
    }

    #[test]
    fn zero_component_digest_is_never_bindable() {
        let mut invalid = components();
        invalid.observer = [0; 32];
        assert_eq!(
            seal_binding(invalid, 1, [0; 32]),
            Err(BindingError::ZeroComponentDigest)
        );
    }

    trait MutateForTest {
        fn mechanism_mutation_for_test(&mut self);
    }
    impl MutateForTest for BindingCapsule {
        fn mechanism_mutation_for_test(&mut self) {
            self.components.mechanism[0] ^= 1;
        }
    }
}
