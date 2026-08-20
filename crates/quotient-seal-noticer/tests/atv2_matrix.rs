use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use noticer_aetp::{
    ActionObligation, ActionSemantics, BucketId, ChannelSchedule, PublicContext, PublicNetworkTape,
    ScheduleRandomTape, ServiceBinding,
};
use noticer_protocol::WireServiceAlias;
use noticer_types::{ActionCode, LogicalSlot, PolicyHash};
use quotient_forge_caqt::{
    Certificate, CertificateLimits, CostVector, DomainHashes, ExpectedContract, ObserverRecord,
    OutputRecord, RelationPair, TransitionRecord, FORMAT_VERSION,
};
use quotient_forge_codegen::{generate_package, CodegenConfig};
use quotient_seal_context::{ContextCommand, ContextFamily};
use quotient_seal_engine::ExecutionLimits;
use quotient_seal_noticer::{
    compile_atv2_p0, verify_atv2_k7, Atv2AdversarialCaseSpec, Atv2AdversarialMatrix,
    Atv2CompileLimits, Atv2CompiledQsm, Atv2HostAxis, Atv2MatrixError, Atv2MatrixLimits,
    Atv2MatrixSeed, Atv2PublicSourceArtifact, Atv2ResourceAxis, Atv2ScenarioAxis, Atv2ServiceCode,
};

const SERVICE: ServiceBinding = ServiceBinding([0x11; 16]);
const SERVICE_ALIAS: WireServiceAlias = WireServiceAlias([0x31; 8]);
const POLICY_HASH: PolicyHash = PolicyHash([0x41; 32]);
const FIRST_CASE_OFFSET: usize = 8 + 2 + (32 * 5) + 4;
const FIRST_COMMAND_FAMILY_OFFSET: usize = FIRST_CASE_OFFSET + 3 + 8 + 4 + 8 + 8 + 32 + 4;

fn compiled(tape_byte: u8) -> Atv2CompiledQsm {
    let semantics = ActionSemantics::new(vec![ActionObligation {
        service: SERVICE,
        action: ActionCode::RenderAmbientPulse,
        public_bucket: BucketId(0),
        admission_cutoff: LogicalSlot(100),
        release_window_start: LogicalSlot(100),
        release_deadline: LogicalSlot(100),
        max_uses: 1,
        policy_hash: POLICY_HASH,
    }])
    .expect("ATV2 semantics");
    let token_plan = noticer_release::TokenPlan::from_action_semantics(&semantics, vec![SERVICE])
        .expect("ATv2 token plan");
    let source = Atv2PublicSourceArtifact::new(
        &token_plan,
        &PublicContext {
            schedule: ChannelSchedule {
                buckets: 1,
                slots_per_bucket: 4,
                frame_interval_ms: 250,
                fixed_plaintext_size: 160,
                fixed_ciphertext_size: 236,
            },
            network: PublicNetworkTape {
                services: vec![SERVICE],
                public_epoch: 9,
                start_slot: LogicalSlot(100),
            },
        },
        ScheduleRandomTape([tape_byte; 32]),
        SERVICE_ALIAS,
        POLICY_HASH,
    )
    .expect("ATV2 source");
    let (certificate, expected) = caqt_certificate();
    let target = TemporaryDirectory::new("atv2-matrix");
    generate_package(
        &certificate,
        expected,
        CertificateLimits::default(),
        &CodegenConfig {
            package_name: "generated-atv2-matrix-source".to_owned(),
            quotient_inputs: 1,
            public_inputs: 1,
            fault_inputs: 1,
            max_payload_bytes: 64,
            max_actions: 8,
        },
        target.path(),
    )
    .expect("K7 package");
    let runtime_manifest =
        fs::read(target.path().join("codegen-manifest.toml")).expect("codegen manifest");
    let k7 = verify_atv2_k7(
        &source,
        &certificate,
        expected,
        CertificateLimits::default(),
        &runtime_manifest,
    )
    .expect("ATV2 K7 binding");
    compile_atv2_p0(
        &source,
        &k7,
        &[Atv2ServiceCode {
            service: SERVICE,
            qsm_alias: 11,
        }],
        Atv2CompileLimits::default(),
    )
    .expect("ATV2 QSM")
}

fn caqt_certificate() -> (Vec<u8>, ExpectedContract) {
    let action = u32::from(ActionCode::RenderAmbientPulse as u16);
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
                payload: b"fixed-slot".to_vec(),
                actions: vec![action],
            },
            OutputRecord {
                id: 1,
                emitted: true,
                payload: b"fixed-slot".to_vec(),
                actions: vec![action],
            },
        ],
        transitions: vec![
            TransitionRecord {
                from: 0,
                input: 0,
                to: 1,
                output: 0,
                authorized_actions: vec![action],
                required_action: Some(action),
                recoverable_fault_action: None,
            },
            TransitionRecord {
                from: 1,
                input: 0,
                to: 1,
                output: 1,
                authorized_actions: vec![action],
                required_action: Some(action),
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

fn limits(host_calls: u64) -> ExecutionLimits {
    ExecutionLimits {
        fuel: 100_000,
        max_memory_pages: 2,
        max_host_calls: host_calls,
        timeout_ms: 5_000,
    }
}

fn command(
    family: ContextFamily,
    service_alias: u32,
    public_slot: u64,
    fault: u8,
) -> ContextCommand {
    ContextCommand {
        family,
        kind: family.command_kind(),
        service_alias,
        public_slot,
        fault,
        payload_tag: 0,
    }
}

fn commands(family: ContextFamily, alias: u32, slot: u64, fault: u8) -> Vec<ContextCommand> {
    vec![
        command(family, alias, slot, fault),
        command(ContextFamily::Stop, 0, 0, 0),
    ]
}

fn specs() -> Vec<Atv2AdversarialCaseSpec> {
    vec![
        Atv2AdversarialCaseSpec::new(
            Atv2ScenarioAxis::Normal,
            Atv2HostAxis::Continue,
            Atv2ResourceAxis::Nominal,
            commands(ContextFamily::Tick, 11, 100, 0),
            limits(4),
        ),
        Atv2AdversarialCaseSpec::new(
            Atv2ScenarioAxis::PublicFaultTimeout,
            Atv2HostAxis::Timeout,
            Atv2ResourceAxis::Nominal,
            commands(ContextFamily::FaultTimeout, 11, 101, 1),
            limits(4),
        ),
        Atv2AdversarialCaseSpec::new(
            Atv2ScenarioAxis::DeadlineAfter,
            Atv2HostAxis::Continue,
            Atv2ResourceAxis::HostCallBoundary,
            commands(ContextFamily::Deadline, 11, 104, 0),
            limits(1),
        ),
        Atv2AdversarialCaseSpec::new(
            Atv2ScenarioAxis::UnknownService,
            Atv2HostAxis::Loss,
            Atv2ResourceAxis::FuelBoundary,
            commands(ContextFamily::ServiceCollusion, 999, 100, 0),
            limits(2),
        ),
    ]
}

#[test]
fn case_order_is_erased_and_round_trip_revalidates_against_compiled_qsm() {
    let compiled = compiled(0x51);
    let seed = Atv2MatrixSeed::new([0x71; 32]);
    let first = Atv2AdversarialMatrix::new(&compiled, seed, specs(), Atv2MatrixLimits::default())
        .expect("first matrix");
    let mut reversed = specs();
    reversed.reverse();
    let second = Atv2AdversarialMatrix::new(&compiled, seed, reversed, Atv2MatrixLimits::default())
        .expect("second matrix");

    assert_eq!(first, second);
    assert_eq!(
        first.canonical_bytes().expect("first bytes"),
        second.canonical_bytes().expect("second bytes")
    );
    assert_eq!(first.matrix_digest(), second.matrix_digest());
    assert!(first
        .cases()
        .windows(2)
        .all(|pair| pair[0].case_id() < pair[1].case_id()));
    let decoded = Atv2AdversarialMatrix::from_bytes(
        &first.canonical_bytes().expect("canonical bytes"),
        Atv2MatrixLimits::default(),
    )
    .expect("strict decode");
    assert_eq!(decoded, first);
    decoded
        .validate_against(&compiled, Atv2MatrixLimits::default())
        .expect("compiled validation");
    assert_eq!(decoded.matrix_digest().to_hex().len(), 64);
    assert!(decoded
        .cases()
        .iter()
        .all(|case| case.case_id().to_hex().len() == 64));
}

#[test]
fn unknown_codes_digest_tamper_and_trailing_bytes_fail_closed() {
    let compiled = compiled(0x51);
    let matrix = Atv2AdversarialMatrix::new(
        &compiled,
        Atv2MatrixSeed::new([0x72; 32]),
        specs(),
        Atv2MatrixLimits::default(),
    )
    .expect("matrix");
    let bytes = matrix.canonical_bytes().expect("canonical bytes");

    let mut unknown_axis = bytes.clone();
    unknown_axis[FIRST_CASE_OFFSET] = 0xff;
    assert!(matches!(
        Atv2AdversarialMatrix::from_bytes(&unknown_axis, Atv2MatrixLimits::default()),
        Err(Atv2MatrixError::UnknownAxis {
            axis: "scenario",
            code: 0xff,
        })
    ));

    let mut unknown_family = bytes.clone();
    unknown_family[FIRST_COMMAND_FAMILY_OFFSET] = 0xff;
    assert!(matches!(
        Atv2AdversarialMatrix::from_bytes(&unknown_family, Atv2MatrixLimits::default()),
        Err(Atv2MatrixError::UnknownContextFamily(0xff))
    ));

    let mut digest_tamper = bytes.clone();
    let last = digest_tamper.len() - 1;
    digest_tamper[last] ^= 1;
    assert!(matches!(
        Atv2AdversarialMatrix::from_bytes(&digest_tamper, Atv2MatrixLimits::default()),
        Err(Atv2MatrixError::MatrixDigestMismatch)
    ));

    let mut trailing = bytes;
    trailing.push(0);
    assert!(matches!(
        Atv2AdversarialMatrix::from_bytes(&trailing, Atv2MatrixLimits::default()),
        Err(Atv2MatrixError::TrailingBytes)
    ));
}

#[test]
fn duplicate_tuple_command_contract_and_compiled_binding_fail_closed() {
    let compiled_qsm = compiled(0x51);
    let duplicate = vec![
        Atv2AdversarialCaseSpec::new(
            Atv2ScenarioAxis::Normal,
            Atv2HostAxis::Continue,
            Atv2ResourceAxis::Nominal,
            commands(ContextFamily::Tick, 11, 100, 0),
            limits(4),
        ),
        Atv2AdversarialCaseSpec::new(
            Atv2ScenarioAxis::Normal,
            Atv2HostAxis::Continue,
            Atv2ResourceAxis::Nominal,
            commands(ContextFamily::Tick, 11, 101, 0),
            limits(4),
        ),
    ];
    assert!(matches!(
        Atv2AdversarialMatrix::new(
            &compiled_qsm,
            Atv2MatrixSeed::new([0x73; 32]),
            duplicate,
            Atv2MatrixLimits::default(),
        ),
        Err(Atv2MatrixError::DuplicateAxisTuple)
    ));

    let after_stop = vec![Atv2AdversarialCaseSpec::new(
        Atv2ScenarioAxis::Normal,
        Atv2HostAxis::Continue,
        Atv2ResourceAxis::Nominal,
        vec![
            command(ContextFamily::Stop, 0, 0, 0),
            command(ContextFamily::Tick, 11, 100, 0),
        ],
        limits(4),
    )];
    assert!(matches!(
        Atv2AdversarialMatrix::new(
            &compiled_qsm,
            Atv2MatrixSeed::new([0x74; 32]),
            after_stop,
            Atv2MatrixLimits::default(),
        ),
        Err(Atv2MatrixError::CommandContract)
    ));

    let matrix = Atv2AdversarialMatrix::new(
        &compiled_qsm,
        Atv2MatrixSeed::new([0x75; 32]),
        specs(),
        Atv2MatrixLimits::default(),
    )
    .expect("matrix");
    let different_compiled = compiled(0x52);
    assert!(matches!(
        matrix.validate_against(&different_compiled, Atv2MatrixLimits::default()),
        Err(Atv2MatrixError::CompiledBindingMismatch)
    ));
}

#[test]
fn frozen_schema_keeps_private_and_hardware_nonclaims_explicit() {
    let config = include_str!("../../../configs/quotient_seal/atv2_adversarial_bundle_v1.yaml");
    let docs = include_str!("../../../docs/quotient_seal_atv2_adversarial_bundle_v1.md");
    assert!(config.contains("unknown_axis_policy: REJECT"));
    assert!(config.contains("duplicate_axis_tuple_policy: REJECT"));
    assert!(config.contains("private_ingress: FORBIDDEN"));
    assert!(config.contains("hardware_status: NOT_VERIFIED"));
    assert!(docs.contains("world-first claim"));
}

struct TemporaryDirectory(PathBuf);

impl TemporaryDirectory {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        Self(std::env::temp_dir().join(format!(
            "quotient-seal-{label}-{}-{nonce}",
            std::process::id()
        )))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
