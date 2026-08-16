use quotient_forge_caqt::{
    verify, CertificateLimits, CertificateVerdict, Digest, ExpectedContract,
};

use crate::{ActionObligation, ActionSemantics, PublicContext, PublicLossTape};

#[derive(Clone, Copy, Debug)]
pub struct ExistingContractRefs<'a, Aplot, AepaRequirement> {
    pub action_semantics: &'a ActionSemantics,
    pub action_obligation: &'a ActionObligation,
    pub public_context: &'a PublicContext,
    pub public_loss_tape: &'a PublicLossTape,
    pub aplot: &'a Aplot,
    pub aepa_requirement: &'a AepaRequirement,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertifiedGeneratedPlan {
    certificate_digest: Digest,
}

impl CertifiedGeneratedPlan {
    pub fn from_certificate(
        certificate: &[u8],
        expected: ExpectedContract,
        limits: CertificateLimits,
    ) -> Result<Self, ConnectionError> {
        match verify(certificate, expected, limits) {
            CertificateVerdict::Valid(report) => Ok(Self {
                certificate_digest: report.certificate_digest,
            }),
            verdict => Err(ConnectionError::Certificate(format!("{verdict:?}"))),
        }
    }

    #[must_use]
    pub const fn certificate_digest(self) -> Digest {
        self.certificate_digest
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ConnectedGeneratedPlan<'a, Atv2FramePlan, MenfuguActionWindow, AepaRequirement> {
    pub certified: CertifiedGeneratedPlan,
    pub atv2_frame_plan: &'a Atv2FramePlan,
    pub menfugu_action_window: &'a MenfuguActionWindow,
    pub aepa_requirement: &'a AepaRequirement,
}

/// Binds existing ATv2/Menfugu/AEPA values by reference to a plan whose CAQT
/// certificate has already passed the independent checker.
#[must_use]
pub const fn connect_generated_plan<'a, Atv2FramePlan, MenfuguActionWindow, AepaRequirement>(
    certified: CertifiedGeneratedPlan,
    atv2_frame_plan: &'a Atv2FramePlan,
    menfugu_action_window: &'a MenfuguActionWindow,
    aepa_requirement: &'a AepaRequirement,
) -> ConnectedGeneratedPlan<'a, Atv2FramePlan, MenfuguActionWindow, AepaRequirement> {
    ConnectedGeneratedPlan {
        certified,
        atv2_frame_plan,
        menfugu_action_window,
        aepa_requirement,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectionError {
    Certificate(String),
}

impl core::fmt::Display for ConnectionError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "Noticer connection error: {self:?}")
    }
}

impl std::error::Error for ConnectionError {}
