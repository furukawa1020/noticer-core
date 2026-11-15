use crate::receipt::hmac_sha256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ExportPurpose {
    Audit = 1,
    IncidentResponse = 2,
    RegulatoryEvidence = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExportPermit {
    pub purpose: ExportPurpose,
    pub allowed_fields: u64,
    pub reservation_digest: [u8; 32],
    pub epoch: u64,
    pub expires_at: u64,
    pub maximum_bytes: u64,
    pub authenticator: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportError {
    EmptyFields,
    EmptyReservation,
    AuthenticationFailed,
    EpochMismatch,
    Expired,
    FieldsExceeded,
    SizeExceeded,
}

pub fn issue(
    purpose: ExportPurpose,
    allowed_fields: u64,
    reservation_digest: [u8; 32],
    epoch: u64,
    expires_at: u64,
    maximum_bytes: u64,
    key: [u8; 32],
) -> Result<ExportPermit, ExportError> {
    if allowed_fields == 0 {
        return Err(ExportError::EmptyFields);
    }
    if reservation_digest == [0; 32] {
        return Err(ExportError::EmptyReservation);
    }
    let mut permit = ExportPermit {
        purpose,
        allowed_fields,
        reservation_digest,
        epoch,
        expires_at,
        maximum_bytes,
        authenticator: [0; 32],
    };
    permit.authenticator = authenticate(permit, key);
    Ok(permit)
}

pub fn authorize(
    permit: ExportPermit,
    requested_fields: u64,
    requested_bytes: u64,
    epoch: u64,
    now: u64,
    key: [u8; 32],
) -> Result<(), ExportError> {
    if permit.authenticator != authenticate(permit, key) {
        return Err(ExportError::AuthenticationFailed);
    }
    if permit.epoch != epoch {
        return Err(ExportError::EpochMismatch);
    }
    if now > permit.expires_at {
        return Err(ExportError::Expired);
    }
    if requested_fields == 0 || requested_fields & !permit.allowed_fields != 0 {
        return Err(ExportError::FieldsExceeded);
    }
    if requested_bytes > permit.maximum_bytes {
        return Err(ExportError::SizeExceeded);
    }
    Ok(())
}

fn authenticate(mut permit: ExportPermit, key: [u8; 32]) -> [u8; 32] {
    permit.authenticator = [0; 32];
    let mut bytes = Vec::with_capacity(96);
    bytes.extend_from_slice(b"noticer.export-permit.v1");
    bytes.push(permit.purpose as u8);
    bytes.extend_from_slice(&permit.allowed_fields.to_be_bytes());
    bytes.extend_from_slice(&permit.reservation_digest);
    bytes.extend_from_slice(&permit.epoch.to_be_bytes());
    bytes.extend_from_slice(&permit.expires_at.to_be_bytes());
    bytes.extend_from_slice(&permit.maximum_bytes.to_be_bytes());
    hmac_sha256(key, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    const KEY: [u8; 32] = [8; 32];
    #[test]
    fn authorizes_only_bounded_export() {
        let permit = issue(ExportPurpose::Audit, 0b011, [7; 32], 4, 100, 1024, KEY).unwrap();
        assert_eq!(authorize(permit, 0b001, 512, 4, 90, KEY), Ok(()));
        assert_eq!(
            authorize(permit, 0b100, 512, 4, 90, KEY),
            Err(ExportError::FieldsExceeded)
        );
        assert_eq!(
            authorize(permit, 0b001, 2048, 4, 90, KEY),
            Err(ExportError::SizeExceeded)
        );
    }
    #[test]
    fn rejects_expired_or_tampered_permit() {
        let mut permit = issue(
            ExportPurpose::IncidentResponse,
            1,
            [7; 32],
            4,
            100,
            1024,
            KEY,
        )
        .unwrap();
        assert_eq!(
            authorize(permit, 1, 1, 4, 101, KEY),
            Err(ExportError::Expired)
        );
        permit.maximum_bytes = 4096;
        assert_eq!(
            authorize(permit, 1, 1, 4, 90, KEY),
            Err(ExportError::AuthenticationFailed)
        );
    }
}
