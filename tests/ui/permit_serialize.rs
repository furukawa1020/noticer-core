use noticer_evidence::{EmpiricalOnly, EvidencePermit};

fn serialize(permit: &EvidencePermit<EmpiricalOnly>) {
    let _ = serde_json::to_string(permit);
}

fn main() {}

