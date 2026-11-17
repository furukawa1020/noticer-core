use crate::receipt::hmac_sha256;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RollbackWitness {
    pub frontier_digest: [u8; 32],
    pub policy_epoch: u64,
    pub artifact_generation: u64,
    pub authenticator: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessError {
    EmptyFrontier,
    PolicyRollback,
    GenerationRollback,
    Authentication,
}
pub fn issue(
    frontier_digest: [u8; 32],
    policy_epoch: u64,
    artifact_generation: u64,
    key: [u8; 32],
) -> Result<RollbackWitness, WitnessError> {
    if frontier_digest == [0; 32] {
        return Err(WitnessError::EmptyFrontier);
    }
    let mut v = RollbackWitness {
        frontier_digest,
        policy_epoch,
        artifact_generation,
        authenticator: [0; 32],
    };
    v.authenticator = auth(v, key);
    Ok(v)
}
pub fn verify(
    v: RollbackWitness,
    min_epoch: u64,
    min_generation: u64,
    key: [u8; 32],
) -> Result<(), WitnessError> {
    if v.authenticator != auth(v, key) {
        return Err(WitnessError::Authentication);
    }
    if v.policy_epoch < min_epoch {
        return Err(WitnessError::PolicyRollback);
    }
    if v.artifact_generation < min_generation {
        return Err(WitnessError::GenerationRollback);
    }
    Ok(())
}
fn auth(mut v: RollbackWitness, key: [u8; 32]) -> [u8; 32] {
    v.authenticator = [0; 32];
    let mut b = Vec::new();
    b.extend_from_slice(b"noticer.rollback-witness.v1");
    b.extend_from_slice(&v.frontier_digest);
    b.extend_from_slice(&v.policy_epoch.to_be_bytes());
    b.extend_from_slice(&v.artifact_generation.to_be_bytes());
    hmac_sha256(key, &b)
}
#[cfg(test)]
mod tests {
    use super::*;
    const K: [u8; 32] = [8; 32];
    #[test]
    fn proves_floors() {
        let v = issue([1; 32], 7, 9, K).unwrap();
        assert_eq!(verify(v, 7, 8, K), Ok(()))
    }
    #[test]
    fn rejects_rollback() {
        let v = issue([1; 32], 7, 9, K).unwrap();
        assert_eq!(verify(v, 8, 9, K), Err(WitnessError::PolicyRollback));
    }
}
