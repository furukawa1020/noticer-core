use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use quotient_forge_caqt::Digest;
use quotient_seal_abi::{
    provision_for_tcb, quotient_seal_abi_v1_hash, validate_wasm_abi, AbiManifest, AbiVerdict,
    AbiViolation, DeploymentProfile, PrivateInput, PublicFault, PublicRequest, PublicSlot,
    ServiceAlias, WasmAbiSurface, WasmSurfaceLimits, PUBLIC_REQUEST_BYTES,
    QUOTIENT_SEAL_ABI_V1_DESCRIPTOR,
};

#[test]
fn public_wire_round_trips_all_methods() {
    let (_, public) = provision_for_tcb(b"instance-a", DeploymentProfile::P0PublicQuotientOnly)
        .unwrap()
        .into_capabilities();
    let requests = [
        public.tick(
            ServiceAlias::new(7).unwrap(),
            PublicSlot(42),
            PublicFault::Reconnect,
        ),
        public.reset(),
        public.handoff(PublicSlot(99)),
        public.status(),
    ];
    for request in requests {
        let bytes = request.encode();
        assert_eq!(bytes.len(), PUBLIC_REQUEST_BYTES);
        assert_eq!(PublicRequest::decode(&bytes), Ok(request));
    }
}

#[test]
fn malformed_length_unknown_values_and_noncanonical_fields_are_rejected() {
    let (_, public) = provision_for_tcb(b"instance-a", DeploymentProfile::P0PublicQuotientOnly)
        .unwrap()
        .into_capabilities();
    let valid = public.status().encode();
    assert!(PublicRequest::decode(&valid[..23]).is_err());

    let mut unknown_method = valid;
    unknown_method[5] = 0xff;
    assert!(PublicRequest::decode(&unknown_method).is_err());

    let mut unknown_fault = valid;
    unknown_fault[6] = 0xff;
    assert!(PublicRequest::decode(&unknown_fault).is_err());

    let mut reserved = valid;
    reserved[20] = 1;
    assert!(PublicRequest::decode(&reserved).is_err());

    let mut noncanonical_status = valid;
    noncanonical_status[8] = 1;
    assert!(PublicRequest::decode(&noncanonical_status).is_err());
}

#[test]
fn trusted_ingress_is_redacted_and_separate_from_public_context() {
    let (mut trusted, public) =
        provision_for_tcb(b"protected-instance", DeploymentProfile::P1SealedAdmission)
            .unwrap()
            .into_capabilities();
    let private = PrivateInput::new(b"private-biosignal-window", 7).unwrap();
    let _admission = trusted.ingest(private).unwrap();
    assert_eq!(public.profile(), DeploymentProfile::P1SealedAdmission);
    let debug = format!("{trusted:?}");
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains("private-biosignal-window"));
    assert!(!format!("{public:?}").contains("protected-instance"));
}

#[test]
fn canonical_contract_and_hash_are_stable() {
    let config = include_str!("../../../configs/quotient_seal/abi_v1.yaml");
    let schema = include_str!("../../../schemas/quotient_seal_abi_v1.schema.json");
    for symbol in [
        "qseal.private.ingest",
        "qseal.public.tick",
        "qseal.public.reset",
        "qseal.public.handoff",
        "qseal.public.status",
        "qseal.emit_frame",
        "qseal.emit_action",
        "qseal.public_failure",
    ] {
        assert!(config.contains(symbol));
        assert!(QUOTIENT_SEAL_ABI_V1_DESCRIPTOR.contains(symbol));
    }
    assert!(schema.contains("quotient-seal-abi-contract-v1"));
    assert_eq!(quotient_seal_abi_v1_hash(), quotient_seal_abi_v1_hash());
    assert_ne!(quotient_seal_abi_v1_hash(), Digest::zero());
}

#[test]
fn actual_wasm_surface_accepts_both_profiles() {
    let wasm = wasm_module(Mutation::None);
    for profile in [
        DeploymentProfile::P0PublicQuotientOnly,
        DeploymentProfile::P1SealedAdmission,
    ] {
        assert!(matches!(
            validate_wasm_abi(
                &wasm,
                AbiManifest::canonical(profile),
                WasmSurfaceLimits::default()
            ),
            AbiVerdict::Valid(_)
        ));
    }
}

#[test]
fn hidden_private_function_is_not_callable_from_public_surface() {
    let surface =
        WasmAbiSurface::parse(&wasm_module(Mutation::None), WasmSurfaceLimits::default()).unwrap();
    assert!(surface.export("qseal.private.ingest").is_none());
    assert_eq!(surface.defined_functions, 5);
    assert_eq!(surface.exports.len(), 4);
}

#[test]
fn extra_import_export_wrong_signature_and_private_export_fail_closed() {
    for mutation in [
        Mutation::ExtraImport,
        Mutation::ExtraExport,
        Mutation::WrongTickSignature,
        Mutation::PrivateExport,
    ] {
        assert!(matches!(
            validate_wasm_abi(
                &wasm_module(mutation),
                AbiManifest::canonical(DeploymentProfile::P1SealedAdmission),
                WasmSurfaceLimits::default()
            ),
            AbiVerdict::Invalid(_)
        ));
    }
}

#[test]
fn wrong_hash_and_resource_exhaustion_never_validate() {
    let wasm = wasm_module(Mutation::None);
    let mut manifest = AbiManifest::canonical(DeploymentProfile::P0PublicQuotientOnly);
    manifest.abi_hash = Digest::zero();
    assert_eq!(
        validate_wasm_abi(&wasm, manifest, WasmSurfaceLimits::default()),
        AbiVerdict::Invalid(AbiViolation::AbiHashMismatch)
    );
    let limits = WasmSurfaceLimits {
        max_bytes: wasm.len() - 1,
        ..WasmSurfaceLimits::default()
    };
    assert!(matches!(
        validate_wasm_abi(
            &wasm,
            AbiManifest::canonical(DeploymentProfile::P0PublicQuotientOnly),
            limits
        ),
        AbiVerdict::ResourceBound(_)
    ));
}

#[test]
fn trusted_capability_cannot_clone_encode_or_become_public() {
    for source in [
        "use quotient_seal_abi::*; fn main() { let (trusted, _) = provision_for_tcb(b\"x\", DeploymentProfile::P1SealedAdmission).unwrap().into_capabilities(); let _ = trusted.clone(); }",
        "use quotient_seal_abi::*; fn main() { let (trusted, _) = provision_for_tcb(b\"x\", DeploymentProfile::P1SealedAdmission).unwrap().into_capabilities(); let _ = PublicWireEncode::encode(&trusted); }",
        "use quotient_seal_abi::*; fn main() { let (trusted, _) = provision_for_tcb(b\"x\", DeploymentProfile::P1SealedAdmission).unwrap().into_capabilities(); let _: PublicContext = trusted.into(); }",
    ] {
        assert_compile_fails(source);
    }
}

#[derive(Clone, Copy)]
enum Mutation {
    None,
    ExtraImport,
    ExtraExport,
    WrongTickSignature,
    PrivateExport,
}

fn wasm_module(mutation: Mutation) -> Vec<u8> {
    let mut module = b"\0asm\x01\0\0\0".to_vec();
    let mut types = Vec::new();
    push_u32(&mut types, 7);
    push_type(&mut types, &[0x7f, 0x7e], &[0x7f]);
    push_type(&mut types, &[0x7f, 0x7f], &[0x7f]);
    push_type(&mut types, &[0x7f], &[0x7f]);
    push_type(&mut types, &[0x7f, 0x7e, 0x7f], &[0x7f]);
    push_type(&mut types, &[], &[0x7f]);
    push_type(&mut types, &[], &[0x7e]);
    push_type(&mut types, &[0x7e], &[0x7f]);
    push_section(&mut module, 1, &types);

    let extra_imports = usize::from(matches!(mutation, Mutation::ExtraImport));
    let mut imports = Vec::new();
    push_u32(&mut imports, 3 + extra_imports as u32);
    push_import(&mut imports, "qseal", "emit_frame", 0);
    push_import(&mut imports, "qseal", "emit_action", 1);
    push_import(&mut imports, "qseal", "public_failure", 2);
    if extra_imports == 1 {
        push_import(&mut imports, "env", "clock", 2);
    }
    push_section(&mut module, 2, &imports);

    let mut functions = Vec::new();
    push_u32(&mut functions, 5);
    push_u32(
        &mut functions,
        if matches!(mutation, Mutation::WrongTickSignature) {
            4
        } else {
            3
        },
    );
    for index in [4_u32, 5, 4, 6] {
        push_u32(&mut functions, index);
    }
    push_section(&mut module, 3, &functions);

    let first_defined = 3 + extra_imports as u32;
    let extra_exports = usize::from(matches!(
        mutation,
        Mutation::ExtraExport | Mutation::PrivateExport
    ));
    let mut exports = Vec::new();
    push_u32(&mut exports, 4 + extra_exports as u32);
    push_export(&mut exports, "qseal.public.tick", first_defined);
    push_export(&mut exports, "qseal.public.reset", first_defined + 1);
    push_export(&mut exports, "qseal.public.handoff", first_defined + 2);
    push_export(&mut exports, "qseal.public.status", first_defined + 3);
    if matches!(mutation, Mutation::ExtraExport) {
        push_export(&mut exports, "debug", first_defined + 4);
    }
    if matches!(mutation, Mutation::PrivateExport) {
        push_export(&mut exports, "qseal.private.ingest", first_defined + 4);
    }
    push_section(&mut module, 7, &exports);

    let mut code = Vec::new();
    push_u32(&mut code, 5);
    for result_opcode in [0x41_u8, 0x41, 0x42, 0x41, 0x41] {
        let body = [0x00, result_opcode, 0x00, 0x0b];
        push_u32(&mut code, body.len() as u32);
        code.extend_from_slice(&body);
    }
    push_section(&mut module, 10, &code);
    module
}

fn push_type(target: &mut Vec<u8>, params: &[u8], results: &[u8]) {
    target.push(0x60);
    push_u32(target, params.len() as u32);
    target.extend_from_slice(params);
    push_u32(target, results.len() as u32);
    target.extend_from_slice(results);
}

fn push_import(target: &mut Vec<u8>, module: &str, name: &str, type_index: u32) {
    push_name(target, module);
    push_name(target, name);
    target.push(0);
    push_u32(target, type_index);
}

fn push_export(target: &mut Vec<u8>, name: &str, function_index: u32) {
    push_name(target, name);
    target.push(0);
    push_u32(target, function_index);
}

fn push_name(target: &mut Vec<u8>, value: &str) {
    push_u32(target, value.len() as u32);
    target.extend_from_slice(value.as_bytes());
}

fn push_section(module: &mut Vec<u8>, id: u8, payload: &[u8]) {
    module.push(id);
    push_u32(module, payload.len() as u32);
    module.extend_from_slice(payload);
}

fn push_u32(target: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        target.push(byte);
        if value == 0 {
            return;
        }
    }
}

fn assert_compile_fails(source: &str) {
    let temporary = TemporaryDirectory::new("compile-fail");
    fs::create_dir_all(temporary.path().join("src")).unwrap();
    let crate_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .to_string_lossy()
        .replace('\\', "/");
    fs::write(
        temporary.path().join("Cargo.toml"),
        format!(
            "[package]\nname = \"abi-compile-fail\"\nversion = \"0.0.0\"\nedition = \"2021\"\npublish = false\n\n[dependencies]\nquotient-seal-abi = {{ path = \"{crate_path}\" }}\n"
        ),
    )
    .unwrap();
    fs::write(temporary.path().join("src/main.rs"), source).unwrap();
    let output = Command::new(env!("CARGO"))
        .args(["check", "--offline", "--manifest-path"])
        .arg(temporary.path().join("Cargo.toml"))
        .env("CARGO_TARGET_DIR", temporary.path().join("target"))
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "forbidden capability conversion unexpectedly compiled"
    );
}

struct TemporaryDirectory(PathBuf);

impl TemporaryDirectory {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
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
