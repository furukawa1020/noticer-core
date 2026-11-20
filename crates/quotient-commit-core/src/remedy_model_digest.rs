//! Domain-separated commitment to every semantic repair model component.

const DOMAIN: &[u8] = b"noticer.quotient-remedy.model.v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepairModelParts {
    pub equation_digest: [u8; 32],
    pub policy_digest: [u8; 32],
    pub cost_model_digest: [u8; 32],
    pub verifier_digests: Vec<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelDigestError {
    ZeroComponent,
    NoVerifier,
}

pub fn digest(mut parts: RepairModelParts) -> Result<[u8; 32], ModelDigestError> {
    if parts.equation_digest == [0; 32]
        || parts.policy_digest == [0; 32]
        || parts.cost_model_digest == [0; 32]
    {
        return Err(ModelDigestError::ZeroComponent);
    }
    if parts.verifier_digests.is_empty() {
        return Err(ModelDigestError::NoVerifier);
    }
    parts.verifier_digests.sort();
    parts.verifier_digests.dedup();
    if parts.verifier_digests.contains(&[0; 32]) {
        return Err(ModelDigestError::ZeroComponent);
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&parts.equation_digest);
    bytes.extend_from_slice(&parts.policy_digest);
    bytes.extend_from_slice(&parts.cost_model_digest);
    for verifier in parts.verifier_digests {
        bytes.extend_from_slice(&verifier);
    }
    Ok(crate::sha256::sha256(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_order_does_not_change_model_digest() {
        let parts = |verifier_digests| RepairModelParts {
            equation_digest: [1; 32],
            policy_digest: [2; 32],
            cost_model_digest: [3; 32],
            verifier_digests,
        };
        assert_eq!(
            digest(parts(vec![[5; 32], [4; 32]])).unwrap(),
            digest(parts(vec![[4; 32], [5; 32]])).unwrap()
        );
    }
}
