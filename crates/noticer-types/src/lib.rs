#![no_std]
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LogicalSlot(pub u64);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Epoch(pub u64);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CapabilityId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PolicyHash(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ActionCode {
    NoAction = 0,
    MenfuguInflateSoft = 1,
    RenderAmbientPulse = 2,
    RenderReviewPrompt = 3,
}

impl ActionCode {
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::NoAction),
            1 => Some(Self::MenfuguInflateSoft),
            2 => Some(Self::RenderAmbientPulse),
            3 => Some(Self::RenderReviewPrompt),
            _ => None,
        }
    }
}
