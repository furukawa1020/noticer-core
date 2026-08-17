#![no_std]
#![forbid(unsafe_code)]

//! Capability-separated ABI types for QuotientSeal.
//!
//! Provisioning creates two object capabilities for one isolated instance.
//! The trusted host retains TrustedIngress and gives only PublicContext to an
//! adversarial context. Creating another instance does not grant access to the
//! protected instance.

extern crate alloc;

mod wasm;
mod wire;

use core::fmt;
use core::marker::PhantomData;

use quotient_forge_caqt::{artifact_digest, Digest};

pub use wasm::{
    validate_wasm_abi, AbiIncompatible, AbiManifest, AbiReport, AbiResourceBound, AbiVerdict,
    AbiViolation, ExternalKind, FuncType, ValueType, WasmAbiSurface, WasmExport, WasmImport,
    WasmSurfaceError, WasmSurfaceLimits,
};
pub use wire::{
    PublicRequest, PublicWireEncode, WireError, PUBLIC_REQUEST_BYTES, WIRE_MAGIC, WIRE_VERSION,
};

pub const ABI_VERSION: u16 = 1;
pub const PRIVATE_INPUT_LIMIT: usize = 64 * 1024;
pub const QUOTIENT_SEAL_ABI_V1_DESCRIPTOR: &str = concat!(
    "quotient-seal-abi-v1\n",
    "private=qseal.private.ingest:host-capability-only:not-import:not-export\n",
    "import=qseal.emit_frame:(i32,i64)->i32\n",
    "import=qseal.emit_action:(i32,i32)->i32\n",
    "import=qseal.public_failure:(i32)->i32\n",
    "export=qseal.public.tick:(i32,i64,i32)->i32\n",
    "export=qseal.public.reset:()->i32\n",
    "export=qseal.public.handoff:()->i64\n",
    "export=qseal.public.status:()->i32\n",
    "wire=QSAB:version-1:fixed-24:little-endian\n",
    "profiles=P0_PUBLIC_QUOTIENT_ONLY,P1_SEALED_ADMISSION\n",
);

#[must_use]
pub fn quotient_seal_abi_v1_hash() -> Digest {
    artifact_digest(
        b"quotient-seal-abi-v1",
        QUOTIENT_SEAL_ABI_V1_DESCRIPTOR.as_bytes(),
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeploymentProfile {
    P0PublicQuotientOnly,
    P1SealedAdmission,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceAlias(u32);

impl ServiceAlias {
    pub fn new(value: u32) -> Result<Self, PublicInputError> {
        if value == 0 {
            Err(PublicInputError::ZeroServiceAlias)
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicSlot(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PublicFault {
    None = 0,
    Timeout = 1,
    Reconnect = 2,
    Loss = 3,
}

impl TryFrom<u8> for PublicFault {
    type Error = PublicInputError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Timeout),
            2 => Ok(Self::Reconnect),
            3 => Ok(Self::Loss),
            _ => Err(PublicInputError::UnknownFault(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicInputError {
    ZeroServiceAlias,
    UnknownFault(u8),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityError {
    EmptyBinding,
    EmptyPrivateInput,
    PrivateInputTooLarge { actual: usize, limit: usize },
    InvalidActionSemantics,
    GenerationOverflow,
}

pub struct PrivateInput<'a> {
    bytes: &'a [u8],
    action_semantics: u32,
}

impl<'a> PrivateInput<'a> {
    pub fn new(bytes: &'a [u8], action_semantics: u32) -> Result<Self, CapabilityError> {
        if bytes.is_empty() {
            return Err(CapabilityError::EmptyPrivateInput);
        }
        if bytes.len() > PRIVATE_INPUT_LIMIT {
            return Err(CapabilityError::PrivateInputTooLarge {
                actual: bytes.len(),
                limit: PRIVATE_INPUT_LIMIT,
            });
        }
        if action_semantics == 0 {
            return Err(CapabilityError::InvalidActionSemantics);
        }
        Ok(Self {
            bytes,
            action_semantics,
        })
    }
}

pub struct SealedAdmission {
    _binding: Digest,
    _generation: u64,
    _action_semantics: u32,
    _private: (),
}

pub struct TrustedIngress {
    binding: Digest,
    generation: u64,
    _last_commitment: Digest,
    _linear: PhantomData<*mut ()>,
}

impl fmt::Debug for TrustedIngress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedIngress")
            .field("binding", &"REDACTED")
            .field("generation", &"REDACTED")
            .field("private_commitment", &"REDACTED")
            .finish()
    }
}

impl TrustedIngress {
    pub fn ingest(&mut self, input: PrivateInput<'_>) -> Result<SealedAdmission, CapabilityError> {
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(CapabilityError::GenerationOverflow)?;
        self._last_commitment = artifact_digest(b"qseal-private-ingest-v1", input.bytes);
        self.generation = generation;
        Ok(SealedAdmission {
            _binding: self.binding,
            _generation: generation,
            _action_semantics: input.action_semantics,
            _private: (),
        })
    }
}

#[derive(Clone)]
pub struct PublicContext {
    _binding: Digest,
    profile: DeploymentProfile,
}

impl fmt::Debug for PublicContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicContext")
            .field("binding", &"REDACTED")
            .field("profile", &self.profile)
            .finish()
    }
}

impl PublicContext {
    #[must_use]
    pub const fn profile(&self) -> DeploymentProfile {
        self.profile
    }

    #[must_use]
    pub const fn tick(
        &self,
        service: ServiceAlias,
        slot: PublicSlot,
        fault: PublicFault,
    ) -> PublicRequest {
        PublicRequest::tick(service, slot, fault)
    }

    #[must_use]
    pub const fn reset(&self) -> PublicRequest {
        PublicRequest::reset()
    }

    #[must_use]
    pub const fn handoff(&self, slot: PublicSlot) -> PublicRequest {
        PublicRequest::handoff(slot)
    }

    #[must_use]
    pub const fn status(&self) -> PublicRequest {
        PublicRequest::status()
    }
}

pub struct ProvisionedInstance {
    trusted: TrustedIngress,
    public: PublicContext,
}

impl ProvisionedInstance {
    #[must_use]
    pub fn into_capabilities(self) -> (TrustedIngress, PublicContext) {
        (self.trusted, self.public)
    }
}

pub fn provision_for_tcb(
    binding_material: &[u8],
    profile: DeploymentProfile,
) -> Result<ProvisionedInstance, CapabilityError> {
    if binding_material.is_empty() {
        return Err(CapabilityError::EmptyBinding);
    }
    let binding = artifact_digest(b"qseal-instance-binding-v1", binding_material);
    Ok(ProvisionedInstance {
        trusted: TrustedIngress {
            binding,
            generation: 0,
            _last_commitment: Digest::zero(),
            _linear: PhantomData,
        },
        public: PublicContext {
            _binding: binding,
            profile,
        },
    })
}
