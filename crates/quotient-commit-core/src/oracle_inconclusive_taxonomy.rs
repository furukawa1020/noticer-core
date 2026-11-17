use crate::oracle_verdict::InconclusiveReason;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopCause {
    Nodes,
    Transitions,
    Depth,
    UnsupportedFeature,
    ReplayMismatch,
}
pub fn classify(cause: StopCause) -> InconclusiveReason {
    match cause {
        StopCause::Nodes => InconclusiveReason::NodeLimit,
        StopCause::Transitions => InconclusiveReason::TransitionLimit,
        StopCause::Depth => InconclusiveReason::DepthLimit,
        StopCause::UnsupportedFeature => InconclusiveReason::Unsupported,
        StopCause::ReplayMismatch => InconclusiveReason::ReplayDisagreement,
    }
}
pub fn code(reason: InconclusiveReason) -> &'static str {
    match reason {
        InconclusiveReason::NodeLimit => "NODE_LIMIT",
        InconclusiveReason::TransitionLimit => "TRANSITION_LIMIT",
        InconclusiveReason::DepthLimit => "DEPTH_LIMIT",
        InconclusiveReason::Unsupported => "UNSUPPORTED",
        InconclusiveReason::ReplayDisagreement => "REPLAY_DISAGREEMENT",
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn codes_are_stable() {
        assert_eq!(code(classify(StopCause::Nodes)), "NODE_LIMIT");
        assert_eq!(
            code(classify(StopCause::ReplayMismatch)),
            "REPLAY_DISAGREEMENT"
        )
    }
    #[test]
    fn unsupported_is_not_limit() {
        assert_eq!(
            classify(StopCause::UnsupportedFeature),
            InconclusiveReason::Unsupported
        )
    }
}
