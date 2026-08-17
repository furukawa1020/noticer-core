use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use quotient_forge_caqt::{
    Certificate, CostVector, DomainHashes, ExpectedContract, ObserverRecord, OutputRecord,
    RelationPair, TransitionRecord, FORMAT_VERSION,
};
use quotient_forge_codegen::CodegenConfig;

pub fn certificate() -> (Vec<u8>, ExpectedContract) {
    let mut certificate = Certificate {
        version: FORMAT_VERSION,
        hashes: DomainHashes::zero(),
        state_count: 2,
        input_count: 1,
        observer_count: 1,
        state_bound: 2,
        claimed_cost: CostVector::default(),
        observers: vec![ObserverRecord {
            id: 0,
            sees_presence: true,
            sees_payload: true,
            sees_actions: true,
        }],
        outputs: vec![
            OutputRecord {
                id: 0,
                emitted: true,
                payload: vec![0x10, 0x20],
                actions: vec![0x0102_0304],
            },
            OutputRecord {
                id: 1,
                emitted: true,
                payload: vec![0x10, 0x20],
                actions: vec![0x0102_0304],
            },
        ],
        transitions: vec![
            TransitionRecord {
                from: 0,
                input: 0,
                to: 1,
                output: 0,
                authorized_actions: vec![0x0102_0304],
                required_action: Some(0x0102_0304),
                recoverable_fault_action: None,
            },
            TransitionRecord {
                from: 1,
                input: 0,
                to: 1,
                output: 1,
                authorized_actions: vec![0x0102_0304],
                required_action: Some(0x0102_0304),
                recoverable_fault_action: None,
            },
        ],
        relation: vec![RelationPair { left: 0, right: 1 }],
    };
    certificate.seal();
    let expected = ExpectedContract {
        version: FORMAT_VERSION,
        hashes: certificate.hashes,
        state_bound: certificate.state_bound,
        max_cost: certificate.claimed_cost,
    };
    (certificate.encode(), expected)
}

pub fn config() -> CodegenConfig {
    CodegenConfig {
        package_name: "generated-runtime".to_owned(),
        quotient_inputs: 1,
        public_inputs: 1,
        fault_inputs: 1,
        max_payload_bytes: 32,
        max_actions: 8,
    }
}

#[allow(dead_code)]
pub struct TemporaryDirectory(PathBuf);

#[allow(dead_code)]
impl TemporaryDirectory {
    pub fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        Self(std::env::temp_dir().join(format!(
            "quotient-forge-{label}-{}-{nonce}",
            std::process::id()
        )))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
