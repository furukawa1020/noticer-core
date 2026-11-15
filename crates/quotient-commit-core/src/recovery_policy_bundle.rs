use crate::receipt::hmac_sha256;
const D: &[u8] = b"noticer.recovery-policy-bundle.v1\0";
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyBundle {
    pub epoch: u64,
    pub generation: u64,
    pub config_digest: [u8; 32],
    pub valid_from: u64,
    pub valid_until: u64,
    pub authenticator: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyError {
    InvalidKey,
    InvalidEpoch,
    InvalidWindow,
    MissingDigest,
    NotActive,
    AuthenticationFailed,
}
pub fn seal(
    epoch: u64,
    generation: u64,
    digest: [u8; 32],
    from: u64,
    until: u64,
    key: [u8; 32],
) -> Result<PolicyBundle, PolicyError> {
    validate(epoch, generation, digest, from, until, key)?;
    let mut p = PolicyBundle {
        epoch,
        generation,
        config_digest: digest,
        valid_from: from,
        valid_until: until,
        authenticator: [0; 32],
    };
    p.authenticator = auth(p, key);
    Ok(p)
}
pub fn verify(p: PolicyBundle, now: u64, key: [u8; 32]) -> Result<(), PolicyError> {
    validate(
        p.epoch,
        p.generation,
        p.config_digest,
        p.valid_from,
        p.valid_until,
        key,
    )?;
    if now < p.valid_from || now > p.valid_until {
        return Err(PolicyError::NotActive);
    }
    if p.authenticator != auth(p, key) {
        Err(PolicyError::AuthenticationFailed)
    } else {
        Ok(())
    }
}
fn validate(e: u64, g: u64, d: [u8; 32], f: u64, u: u64, k: [u8; 32]) -> Result<(), PolicyError> {
    if k == [0; 32] {
        return Err(PolicyError::InvalidKey);
    }
    if e == 0 || g == 0 {
        return Err(PolicyError::InvalidEpoch);
    }
    if d == [0; 32] {
        return Err(PolicyError::MissingDigest);
    }
    if f >= u {
        return Err(PolicyError::InvalidWindow);
    }
    Ok(())
}
fn auth(mut p: PolicyBundle, k: [u8; 32]) -> [u8; 32] {
    p.authenticator = [0; 32];
    let mut b = Vec::from(D);
    b.extend_from_slice(&p.epoch.to_be_bytes());
    b.extend_from_slice(&p.generation.to_be_bytes());
    b.extend_from_slice(&p.config_digest);
    b.extend_from_slice(&p.valid_from.to_be_bytes());
    b.extend_from_slice(&p.valid_until.to_be_bytes());
    hmac_sha256(k, &b)
}
#[cfg(test)]
mod tests {
    use super::*;
    const K: [u8; 32] = [1; 32];
    #[test]
    fn active_bundle_verifies() {
        let p = seal(2, 3, [4; 32], 10, 20, K).unwrap();
        assert_eq!(verify(p, 15, K), Ok(()));
        assert_eq!(verify(p, 21, K), Err(PolicyError::NotActive))
    }
    #[test]
    fn substitution_fails() {
        let mut p = seal(2, 3, [4; 32], 10, 20, K).unwrap();
        p.config_digest = [9; 32];
        assert_eq!(verify(p, 15, K), Err(PolicyError::AuthenticationFailed));
    }
}
