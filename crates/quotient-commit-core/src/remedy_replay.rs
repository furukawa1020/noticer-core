//! Minimal independent replay path over immutable verification facts.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepairReplayInput {
    pub certificate_digest: [u8; 32],
    pub patch_digest: [u8; 32],
    pub model_digest: [u8; 32],
    pub safety: bool,
    pub action_equivalence: bool,
    pub liveness: bool,
    pub privacy: bool,
    pub minimality: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayVerdict {
    Verified,
    Rejected,
    Invalid,
}

pub fn replay(input: RepairReplayInput) -> ReplayVerdict {
    if input.certificate_digest == [0; 32]
        || input.patch_digest == [0; 32]
        || input.model_digest == [0; 32]
    {
        return ReplayVerdict::Invalid;
    }
    if input.safety
        && input.action_equivalence
        && input.liveness
        && input.privacy
        && input.minimality
    {
        ReplayVerdict::Verified
    } else {
        ReplayVerdict::Rejected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> RepairReplayInput {
        RepairReplayInput {
            certificate_digest: [1; 32],
            patch_digest: [2; 32],
            model_digest: [3; 32],
            safety: true,
            action_equivalence: true,
            liveness: true,
            privacy: true,
            minimality: true,
        }
    }

    #[test]
    fn every_independent_check_is_required() {
        assert_eq!(replay(valid()), ReplayVerdict::Verified);
        let mut changed = valid();
        changed.privacy = false;
        assert_eq!(replay(changed), ReplayVerdict::Rejected);
    }
}
