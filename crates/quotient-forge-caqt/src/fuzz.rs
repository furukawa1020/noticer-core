use alloc::vec::Vec;
use core::fmt::{self, Display, Formatter};

use crate::{Certificate, CertificateLimits};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BinaryFuzzLimits {
    pub max_cases: usize,
    pub max_input_bytes: usize,
    pub certificate: CertificateLimits,
}

impl BinaryFuzzLimits {
    fn validate(self) -> Result<Self, BinaryFuzzError> {
        if self.max_cases == 0
            || self.max_cases > 4_096
            || self.max_input_bytes == 0
            || self.max_input_bytes > 1_048_576
            || self.certificate.max_bytes > self.max_input_bytes
        {
            return Err(BinaryFuzzError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BinaryFuzzError {
    InvalidLimits,
    TooManyCases,
}

impl Display for BinaryFuzzError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("CAQT fuzz limits are invalid"),
            Self::TooManyCases => formatter.write_str("CAQT fuzz corpus exceeds the case budget"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BinaryFuzzReport {
    pub seed: u64,
    pub supplied_cases: usize,
    pub executed_mutations: usize,
    pub resource_rejections: usize,
    pub parser_rejections: usize,
    pub parser_acceptances: usize,
    pub noncanonical_acceptances: usize,
    pub unstable_round_trips: usize,
}

pub fn run_binary_fuzz(
    seed: u64,
    corpus: &[Vec<u8>],
    limits: BinaryFuzzLimits,
) -> Result<BinaryFuzzReport, BinaryFuzzError> {
    let limits = limits.validate()?;
    if corpus.len() > limits.max_cases {
        return Err(BinaryFuzzError::TooManyCases);
    }
    let mut report = BinaryFuzzReport {
        seed,
        supplied_cases: corpus.len(),
        executed_mutations: 0,
        resource_rejections: 0,
        parser_rejections: 0,
        parser_acceptances: 0,
        noncanonical_acceptances: 0,
        unstable_round_trips: 0,
    };
    for input in corpus {
        for mutated in mutations(seed, input) {
            if mutated.len() > limits.max_input_bytes {
                report.resource_rejections += 1;
                continue;
            }
            report.executed_mutations += 1;
            match Certificate::decode(&mutated, limits.certificate) {
                Err(_) => report.parser_rejections += 1,
                Ok(certificate) => {
                    report.parser_acceptances += 1;
                    let encoded = certificate.encode();
                    if encoded != mutated {
                        report.noncanonical_acceptances += 1;
                    }
                    match Certificate::decode(&encoded, limits.certificate) {
                        Ok(round_trip) if round_trip.encode() == encoded => {}
                        _ => report.unstable_round_trips += 1,
                    }
                }
            }
        }
    }
    Ok(report)
}

fn mutations(seed: u64, input: &[u8]) -> [Vec<u8>; 6] {
    let mut flipped = input.to_vec();
    if !flipped.is_empty() {
        let index = (seed as usize) % flipped.len();
        flipped[index] ^= 1_u8 << ((seed >> 8) & 7);
    }
    let mut trailing = input.to_vec();
    trailing.push(0xa5);
    let mut oversized_length = input.to_vec();
    oversized_length.extend_from_slice(&u32::MAX.to_le_bytes());
    [
        input.to_vec(),
        Vec::new(),
        input[..input.len() / 2].to_vec(),
        flipped,
        trailing,
        oversized_length,
    ]
}
