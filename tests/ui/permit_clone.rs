use noticer_evidence::{EmpiricalOnly, EvidencePermit};

fn clone_permit(permit: EvidencePermit<EmpiricalOnly>) {
    let _second = permit.clone();
}

fn main() {}
