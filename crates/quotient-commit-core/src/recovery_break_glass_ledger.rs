use crate::receipt::hmac_sha256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BreakGlassAuditEntry {
    pub sequence: u64,
    pub permit_id: [u8; 16],
    pub operation_digest: [u8; 32],
    pub previous_authenticator: [u8; 32],
    pub authenticator: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LedgerError {
    EmptyKey,
    EmptyOperation,
    InvalidChain,
}

pub struct BreakGlassLedger {
    key: [u8; 32],
    entries: Vec<BreakGlassAuditEntry>,
}

impl BreakGlassLedger {
    pub fn new(key: [u8; 32]) -> Result<Self, LedgerError> {
        if key == [0; 32] {
            return Err(LedgerError::EmptyKey);
        }
        Ok(Self {
            key,
            entries: Vec::new(),
        })
    }

    pub fn append(
        &mut self,
        permit_id: [u8; 16],
        operation_digest: [u8; 32],
    ) -> Result<&BreakGlassAuditEntry, LedgerError> {
        if operation_digest == [0; 32] {
            return Err(LedgerError::EmptyOperation);
        }
        let sequence = self.entries.len() as u64;
        let previous_authenticator = self
            .entries
            .last()
            .map_or([0; 32], |entry| entry.authenticator);
        let authenticator = authenticate(
            self.key,
            sequence,
            permit_id,
            operation_digest,
            previous_authenticator,
        );
        self.entries.push(BreakGlassAuditEntry {
            sequence,
            permit_id,
            operation_digest,
            previous_authenticator,
            authenticator,
        });
        Ok(self.entries.last().expect("entry was appended"))
    }

    pub fn entries(&self) -> &[BreakGlassAuditEntry] {
        &self.entries
    }

    pub fn verify(&self) -> Result<(), LedgerError> {
        let mut previous = [0; 32];
        for (sequence, entry) in self.entries.iter().enumerate() {
            let expected = authenticate(
                self.key,
                sequence as u64,
                entry.permit_id,
                entry.operation_digest,
                previous,
            );
            if entry.sequence != sequence as u64
                || entry.previous_authenticator != previous
                || entry.authenticator != expected
            {
                return Err(LedgerError::InvalidChain);
            }
            previous = entry.authenticator;
        }
        Ok(())
    }
}

fn authenticate(
    key: [u8; 32],
    sequence: u64,
    permit_id: [u8; 16],
    operation_digest: [u8; 32],
    previous: [u8; 32],
) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(88);
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(&permit_id);
    bytes.extend_from_slice(&operation_digest);
    bytes.extend_from_slice(&previous);
    hmac_sha256(key, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_an_append_only_chain() {
        let mut ledger = BreakGlassLedger::new([7; 32]).unwrap();
        ledger.append([1; 16], [2; 32]).unwrap();
        ledger.append([3; 16], [4; 32]).unwrap();
        assert_eq!(
            ledger.entries()[1].previous_authenticator,
            ledger.entries()[0].authenticator
        );
        assert_eq!(ledger.verify(), Ok(()));
    }

    #[test]
    fn detects_entry_tampering() {
        let mut ledger = BreakGlassLedger::new([7; 32]).unwrap();
        ledger.append([1; 16], [2; 32]).unwrap();
        ledger.entries[0].operation_digest = [9; 32];
        assert_eq!(ledger.verify(), Err(LedgerError::InvalidChain));
    }
}
