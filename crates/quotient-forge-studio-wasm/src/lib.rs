//! Raw WebAssembly ABI for the browser-only QuotientForge small-model checker.

pub const FLAG_VISIBLE_PRIVATE: u32 = 1 << 0;
pub const FLAG_FIXED_CADENCE: u32 = 1 << 1;
pub const FLAG_AUTHORIZED_ACTION: u32 = 1 << 2;
pub const FLAG_DEADLINE_MET: u32 = 1 << 3;
pub const FLAG_RECOVERY_PRESENT: u32 = 1 << 4;
pub const FLAG_TRANSITIONS_TOTAL: u32 = 1 << 5;

pub const VERDICT_VALID: u32 = 0;
pub const VERDICT_SECURITY_DIVERGENCE: u32 = 1;
pub const VERDICT_UNAUTHORIZED_ACTION: u32 = 2;
pub const VERDICT_MISSED_DEADLINE: u32 = 3;
pub const VERDICT_RECOVERY_ABSENT: u32 = 4;
pub const VERDICT_PARTIAL_TRANSITION: u32 = 5;

#[no_mangle]
pub extern "C" fn qf_version() -> u32 {
    1
}

#[no_mangle]
pub extern "C" fn qf_check(flags: u32) -> u32 {
    if flags & FLAG_TRANSITIONS_TOTAL == 0 {
        return VERDICT_PARTIAL_TRANSITION;
    }
    if flags & FLAG_VISIBLE_PRIVATE != 0 && flags & FLAG_FIXED_CADENCE == 0 {
        return VERDICT_SECURITY_DIVERGENCE;
    }
    if flags & FLAG_AUTHORIZED_ACTION == 0 {
        return VERDICT_UNAUTHORIZED_ACTION;
    }
    if flags & FLAG_DEADLINE_MET == 0 {
        return VERDICT_MISSED_DEADLINE;
    }
    if flags & FLAG_RECOVERY_PRESENT == 0 {
        return VERDICT_RECOVERY_ABSENT;
    }
    VERDICT_VALID
}

#[no_mangle]
pub extern "C" fn qf_repair(flags: u32) -> u32 {
    (flags
        | FLAG_FIXED_CADENCE
        | FLAG_AUTHORIZED_ACTION
        | FLAG_DEADLINE_MET
        | FLAG_RECOVERY_PRESENT
        | FLAG_TRANSITIONS_TOTAL)
        & !FLAG_VISIBLE_PRIVATE
}

#[no_mangle]
pub extern "C" fn qf_cost(flags: u32) -> u32 {
    let release_cost = if flags & FLAG_FIXED_CADENCE != 0 {
        18
    } else {
        7
    };
    let action_cost = if flags & FLAG_AUTHORIZED_ACTION != 0 {
        5
    } else {
        0
    };
    let recovery_cost = if flags & FLAG_RECOVERY_PRESENT != 0 {
        4
    } else {
        0
    };
    release_cost + action_cost + recovery_cost
}

#[no_mangle]
pub extern "C" fn qf_frontier_cost(index: u32) -> u32 {
    match index {
        0 => 27,
        1 => 31,
        2 => 39,
        _ => u32::MAX,
    }
}

#[no_mangle]
pub extern "C" fn qf_verify_certificate(actual: u32, expected: u32) -> u32 {
    u32::from(actual == expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_FLAGS: u32 = FLAG_FIXED_CADENCE
        | FLAG_AUTHORIZED_ACTION
        | FLAG_DEADLINE_MET
        | FLAG_RECOVERY_PRESENT
        | FLAG_TRANSITIONS_TOTAL;

    #[test]
    fn every_small_model_violation_has_a_stable_verdict() {
        assert_eq!(qf_check(VALID_FLAGS), VERDICT_VALID);
        assert_eq!(
            qf_check((VALID_FLAGS | FLAG_VISIBLE_PRIVATE) & !FLAG_FIXED_CADENCE),
            VERDICT_SECURITY_DIVERGENCE
        );
        assert_eq!(
            qf_check(VALID_FLAGS & !FLAG_AUTHORIZED_ACTION),
            VERDICT_UNAUTHORIZED_ACTION
        );
        assert_eq!(
            qf_check(VALID_FLAGS & !FLAG_DEADLINE_MET),
            VERDICT_MISSED_DEADLINE
        );
        assert_eq!(
            qf_check(VALID_FLAGS & !FLAG_RECOVERY_PRESENT),
            VERDICT_RECOVERY_ABSENT
        );
        assert_eq!(
            qf_check(VALID_FLAGS & !FLAG_TRANSITIONS_TOTAL),
            VERDICT_PARTIAL_TRANSITION
        );
    }

    #[test]
    fn repair_produces_a_valid_small_model() {
        let broken = FLAG_VISIBLE_PRIVATE;
        let repaired = qf_repair(broken);
        assert_eq!(qf_check(repaired), VERDICT_VALID);
        assert_eq!(repaired & FLAG_VISIBLE_PRIVATE, 0);
        assert!(qf_cost(repaired) > qf_cost(broken));
    }

    #[test]
    fn frontier_and_tamper_contract_are_deterministic() {
        assert!(qf_frontier_cost(0) < qf_frontier_cost(1));
        assert!(qf_frontier_cost(1) < qf_frontier_cost(2));
        assert_eq!(qf_frontier_cost(3), u32::MAX);
        assert_eq!(qf_verify_certificate(0xA5A5, 0xA5A5), 1);
        assert_eq!(qf_verify_certificate(0xA5A4, 0xA5A5), 0);
        assert_eq!(qf_version(), 1);
    }
}
