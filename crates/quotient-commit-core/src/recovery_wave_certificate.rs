use crate::receipt::hmac_sha256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaveCertificate {
    pub wave_index: u32,
    pub previous_digest: [u8; 32],
    pub successes: u32,
    pub failures: u32,
    pub result_digest: [u8; 32],
    pub authenticator: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateError {
    InvalidGenesis,
    MissingPredecessor,
    IndexMismatch,
    PredecessorMismatch,
    EmptyResult,
    AuthenticationFailed,
}

pub fn issue(
    wave_index: u32,
    previous_digest: [u8; 32],
    successes: u32,
    failures: u32,
    result_digest: [u8; 32],
    key: [u8; 32],
) -> Result<WaveCertificate, CertificateError> {
    if result_digest == [0; 32] {
        return Err(CertificateError::EmptyResult);
    }
    if wave_index == 0 && previous_digest != [0; 32] {
        return Err(CertificateError::InvalidGenesis);
    }
    if wave_index > 0 && previous_digest == [0; 32] {
        return Err(CertificateError::MissingPredecessor);
    }
    let mut certificate = WaveCertificate {
        wave_index,
        previous_digest,
        successes,
        failures,
        result_digest,
        authenticator: [0; 32],
    };
    certificate.authenticator = authenticate(certificate, key);
    Ok(certificate)
}

pub fn verify_next(
    previous: WaveCertificate,
    next: WaveCertificate,
    key: [u8; 32],
) -> Result<(), CertificateError> {
    if previous.authenticator != authenticate(previous, key)
        || next.authenticator != authenticate(next, key)
    {
        return Err(CertificateError::AuthenticationFailed);
    }
    if next.wave_index != previous.wave_index + 1 {
        return Err(CertificateError::IndexMismatch);
    }
    if next.previous_digest != previous.authenticator {
        return Err(CertificateError::PredecessorMismatch);
    }
    Ok(())
}

fn authenticate(mut value: WaveCertificate, key: [u8; 32]) -> [u8; 32] {
    value.authenticator = [0; 32];
    let mut bytes = Vec::with_capacity(96);
    bytes.extend_from_slice(b"noticer.wave-certificate.v1");
    bytes.extend_from_slice(&value.wave_index.to_be_bytes());
    bytes.extend_from_slice(&value.previous_digest);
    bytes.extend_from_slice(&value.successes.to_be_bytes());
    bytes.extend_from_slice(&value.failures.to_be_bytes());
    bytes.extend_from_slice(&value.result_digest);
    hmac_sha256(key, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    const KEY: [u8; 32] = [1; 32];
    #[test]
    fn verifies_a_chained_wave_progression() {
        let first = issue(0, [0; 32], 1, 0, [7; 32], KEY).unwrap();
        let second = issue(1, first.authenticator, 3, 0, [8; 32], KEY).unwrap();
        assert_eq!(verify_next(first, second, KEY), Ok(()));
    }
    #[test]
    fn rejects_substitution_and_index_skip() {
        let first = issue(0, [0; 32], 1, 0, [7; 32], KEY).unwrap();
        let wrong = issue(2, first.authenticator, 3, 0, [8; 32], KEY).unwrap();
        assert_eq!(
            verify_next(first, wrong, KEY),
            Err(CertificateError::IndexMismatch)
        );
        let substituted = issue(1, [9; 32], 3, 0, [8; 32], KEY).unwrap();
        assert_eq!(
            verify_next(first, substituted, KEY),
            Err(CertificateError::PredecessorMismatch)
        );
    }
}
