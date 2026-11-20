//! Canonical timestamped observation accepted by the sentinel.

use crate::sentinel_observation_atom::RuntimeObservationAtom;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MonitorSample {
    pub sequence: u64,
    pub monotonic_millis: u64,
    pub atom: RuntimeObservationAtom,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MonitorSampleError {
    ZeroSequence,
    ZeroTimestamp,
}

impl MonitorSample {
    pub fn new(
        sequence: u64,
        monotonic_millis: u64,
        atom: RuntimeObservationAtom,
    ) -> Result<Self, MonitorSampleError> {
        if sequence == 0 {
            return Err(MonitorSampleError::ZeroSequence);
        }
        if monotonic_millis == 0 {
            return Err(MonitorSampleError::ZeroTimestamp);
        }
        Ok(Self {
            sequence,
            monotonic_millis,
            atom,
        })
    }

    #[must_use]
    pub fn digest(self) -> [u8; 32] {
        let mut bytes = b"noticer.quotient-sentinel.sample.v1\0".to_vec();
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(&self.monotonic_millis.to_be_bytes());
        bytes.extend_from_slice(&self.atom.digest());
        crate::sha256::sha256(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sentinel_observation_atom::PublicRuntimeEvent;

    #[test]
    fn missing_sequence_is_invalid() {
        let atom = RuntimeObservationAtom::new(1, PublicRuntimeEvent::Release, 1, 0).unwrap();
        assert_eq!(
            MonitorSample::new(0, 1, atom),
            Err(MonitorSampleError::ZeroSequence)
        );
    }
}
