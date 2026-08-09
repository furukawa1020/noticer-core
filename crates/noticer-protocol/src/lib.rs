#![no_std]
#![forbid(unsafe_code)]

use noticer_types::{ActionCode, Epoch, PolicyHash};

pub const SIGN_DOMAIN: &[u8] = b"NOTICER_CAPABILITY_V1";
pub const BODY_LENGTH: usize = 89;

pub struct CapabilityBody {
    pub audience_binding: [u8; 32],
    pub action: ActionCode,
    pub policy_hash: PolicyHash,
    pub epoch: Epoch,
    pub nonce: [u8; 16],
}

impl CapabilityBody {
    pub fn encode(&self) -> [u8; BODY_LENGTH] {
        let mut body = [0_u8; BODY_LENGTH];
        body[..32].copy_from_slice(&self.audience_binding);
        body[32] = self.action as u8;
        body[33..65].copy_from_slice(&self.policy_hash.0);
        body[65..73].copy_from_slice(&self.epoch.0.to_be_bytes());
        body[73..].copy_from_slice(&self.nonce);
        body
    }
}
