use std::marker::PhantomData;

use noticer_evidence::{EmpiricalOnly, EvidenceEpochId, EvidencePermit};
use noticer_types::{ActionCode, LogicalSlot, PolicyHash};

fn main() {
    let _ = EvidencePermit::<EmpiricalOnly> {
        action: ActionCode::NoAction,
        policy_hash: PolicyHash([0; 32]),
        issued_slot: LogicalSlot(1),
        expires_slot: LogicalSlot(2),
        evidence_epoch: EvidenceEpochId(1),
        marker: PhantomData,
    };
}

