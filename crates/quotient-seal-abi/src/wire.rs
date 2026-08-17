use crate::{PublicFault, PublicInputError, PublicSlot, ServiceAlias};

pub const WIRE_MAGIC: [u8; 4] = *b"QSAB";
pub const WIRE_VERSION: u8 = 1;
pub const PUBLIC_REQUEST_BYTES: usize = 24;

const METHOD_TICK: u8 = 1;
const METHOD_RESET: u8 = 2;
const METHOD_HANDOFF: u8 = 3;
const METHOD_STATUS: u8 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicRequest {
    Tick {
        service: ServiceAlias,
        slot: PublicSlot,
        fault: PublicFault,
    },
    Reset,
    Handoff {
        slot: PublicSlot,
    },
    Status,
}

impl PublicRequest {
    pub(crate) const fn tick(service: ServiceAlias, slot: PublicSlot, fault: PublicFault) -> Self {
        Self::Tick {
            service,
            slot,
            fault,
        }
    }

    pub(crate) const fn reset() -> Self {
        Self::Reset
    }

    pub(crate) const fn handoff(slot: PublicSlot) -> Self {
        Self::Handoff { slot }
    }

    pub(crate) const fn status() -> Self {
        Self::Status
    }

    #[must_use]
    pub fn encode(self) -> [u8; PUBLIC_REQUEST_BYTES] {
        PublicWireEncode::encode(&self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() != PUBLIC_REQUEST_BYTES {
            return Err(WireError::Length {
                actual: bytes.len(),
                expected: PUBLIC_REQUEST_BYTES,
            });
        }
        if bytes[..4] != WIRE_MAGIC {
            return Err(WireError::Magic);
        }
        if bytes[4] != WIRE_VERSION {
            return Err(WireError::Version(bytes[4]));
        }
        if bytes[7] != 0 || bytes[20..24] != [0; 4] {
            return Err(WireError::NonCanonicalReserved);
        }
        let service_value = u32::from_le_bytes(bytes[8..12].try_into().unwrap_or([0; 4]));
        let slot = PublicSlot(u64::from_le_bytes(
            bytes[12..20].try_into().unwrap_or([0; 8]),
        ));
        let fault = PublicFault::try_from(bytes[6]).map_err(WireError::PublicInput)?;
        match bytes[5] {
            METHOD_TICK => Ok(Self::Tick {
                service: ServiceAlias::new(service_value).map_err(WireError::PublicInput)?,
                slot,
                fault,
            }),
            METHOD_RESET => {
                require_zero_fields(service_value, slot, fault)?;
                Ok(Self::Reset)
            }
            METHOD_HANDOFF => {
                if service_value != 0 || fault != PublicFault::None {
                    return Err(WireError::NonCanonicalFields);
                }
                Ok(Self::Handoff { slot })
            }
            METHOD_STATUS => {
                require_zero_fields(service_value, slot, fault)?;
                Ok(Self::Status)
            }
            value => Err(WireError::UnknownMethod(value)),
        }
    }
}

pub trait PublicWireEncode {
    fn encode(&self) -> [u8; PUBLIC_REQUEST_BYTES];
}

impl PublicWireEncode for PublicRequest {
    fn encode(&self) -> [u8; PUBLIC_REQUEST_BYTES] {
        let mut bytes = [0_u8; PUBLIC_REQUEST_BYTES];
        bytes[..4].copy_from_slice(&WIRE_MAGIC);
        bytes[4] = WIRE_VERSION;
        match *self {
            Self::Tick {
                service,
                slot,
                fault,
            } => {
                bytes[5] = METHOD_TICK;
                bytes[6] = fault as u8;
                bytes[8..12].copy_from_slice(&service.get().to_le_bytes());
                bytes[12..20].copy_from_slice(&slot.0.to_le_bytes());
            }
            Self::Reset => bytes[5] = METHOD_RESET,
            Self::Handoff { slot } => {
                bytes[5] = METHOD_HANDOFF;
                bytes[12..20].copy_from_slice(&slot.0.to_le_bytes());
            }
            Self::Status => bytes[5] = METHOD_STATUS,
        }
        bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WireError {
    Length { actual: usize, expected: usize },
    Magic,
    Version(u8),
    UnknownMethod(u8),
    PublicInput(PublicInputError),
    NonCanonicalReserved,
    NonCanonicalFields,
}

fn require_zero_fields(
    service: u32,
    slot: PublicSlot,
    fault: PublicFault,
) -> Result<(), WireError> {
    if service == 0 && slot.0 == 0 && fault == PublicFault::None {
        Ok(())
    } else {
        Err(WireError::NonCanonicalFields)
    }
}
