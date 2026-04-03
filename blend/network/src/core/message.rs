use core::ops::{Deref, DerefMut};

use lb_blend_message::{
    Error,
    encap::{
        ProofsVerifier,
        decapsulated::{DecapsulatedMessage, DecapsulationOutput},
        encapsulated::EncapsulatedMessage,
        validated::{
            EncapsulatedMessageWithVerifiedPublicHeader, EncapsulatedMessageWithVerifiedSignature,
            RequiredProofOfSelectionVerificationInputs,
        },
    },
    reward::BlendingToken,
};
use lb_key_management_system_keys::keys::X25519PrivateKey;
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub enum SessionBoundDecapsulationOutput {
    Incompleted {
        remaining_encapsulated_message: Box<SessionBoundEncapsulatedMessage>,
        blending_token: BlendingToken,
    },
    Completed {
        fully_decapsulated_message: DecapsulatedMessage,
        blending_token: BlendingToken,
    },
}

impl SessionBoundDecapsulationOutput {
    #[must_use]
    fn from_decapsulation_output(decapsulation_output: DecapsulationOutput, session: u64) -> Self {
        match decapsulation_output {
            DecapsulationOutput::Incompleted {
                remaining_encapsulated_message,
                blending_token,
            } => Self::Incompleted {
                remaining_encapsulated_message: Box::new(SessionBoundEncapsulatedMessage {
                    message: *remaining_encapsulated_message,
                    session,
                }),
                blending_token,
            },
            DecapsulationOutput::Completed {
                fully_decapsulated_message,
                blending_token,
            } => Self::Completed {
                fully_decapsulated_message,
                blending_token,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct SessionBoundEncapsulatedMessage {
    message: EncapsulatedMessage,
    session: u64,
}

impl SessionBoundEncapsulatedMessage {
    pub fn verify_public_header<Verifier>(
        self,
        verifier: &Verifier,
    ) -> Result<SessionBoundEncapsulatedMessageWithVerifiedHeader, Error>
    where
        Verifier: ProofsVerifier,
    {
        Ok(SessionBoundEncapsulatedMessageWithVerifiedHeader {
            message: self.message.verify_public_header(verifier)?,
            session: self.session,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct SessionBoundEncapsulatedMessageWithVerifiedSignature {
    message: EncapsulatedMessageWithVerifiedSignature,
    session: u64,
}

impl SessionBoundEncapsulatedMessageWithVerifiedSignature {
    #[must_use]
    pub(crate) const fn new(
        message: EncapsulatedMessageWithVerifiedSignature,
        session: u64,
    ) -> Self {
        Self { message, session }
    }

    pub fn verify_proof_of_quota<Verifier>(
        self,
        verifier: &Verifier,
    ) -> Result<SessionBoundEncapsulatedMessageWithVerifiedHeader, Error>
    where
        Verifier: ProofsVerifier,
    {
        Ok(SessionBoundEncapsulatedMessageWithVerifiedHeader {
            message: self.message.verify_proof_of_quota(verifier)?,
            session: self.session,
        })
    }

    #[must_use]
    pub const fn session(&self) -> u64 {
        self.session
    }
}

impl AsRef<EncapsulatedMessageWithVerifiedSignature>
    for SessionBoundEncapsulatedMessageWithVerifiedSignature
{
    fn as_ref(&self) -> &EncapsulatedMessageWithVerifiedSignature {
        &self.message
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct SessionBoundEncapsulatedMessageWithVerifiedHeader {
    message: EncapsulatedMessageWithVerifiedPublicHeader,
    session: u64,
}

impl SessionBoundEncapsulatedMessageWithVerifiedHeader {
    #[must_use]
    pub fn into_components(self) -> (EncapsulatedMessageWithVerifiedPublicHeader, u64) {
        (self.message, self.session)
    }

    #[must_use]
    pub const fn session(&self) -> u64 {
        self.session
    }

    pub fn decapsulate<Verifier>(
        self,
        private_key: &X25519PrivateKey,
        posel_verification_inputs: &RequiredProofOfSelectionVerificationInputs,
        verifier: &Verifier,
    ) -> Result<SessionBoundDecapsulationOutput, Error>
    where
        Verifier: ProofsVerifier,
    {
        Ok(SessionBoundDecapsulationOutput::from_decapsulation_output(
            self.message
                .decapsulate(private_key, posel_verification_inputs, verifier)?,
            self.session,
        ))
    }
}

impl Deref for SessionBoundEncapsulatedMessageWithVerifiedHeader {
    type Target = EncapsulatedMessageWithVerifiedPublicHeader;

    fn deref(&self) -> &Self::Target {
        &self.message
    }
}

impl DerefMut for SessionBoundEncapsulatedMessageWithVerifiedHeader {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.message
    }
}

impl From<SessionBoundEncapsulatedMessageWithVerifiedHeader>
    for EncapsulatedMessageWithVerifiedPublicHeader
{
    fn from(value: SessionBoundEncapsulatedMessageWithVerifiedHeader) -> Self {
        value.message
    }
}

impl From<SessionBoundEncapsulatedMessageWithVerifiedHeader>
    for SessionBoundEncapsulatedMessageWithVerifiedSignature
{
    fn from(value: SessionBoundEncapsulatedMessageWithVerifiedHeader) -> Self {
        Self {
            message: value.message.into(),
            session: value.session,
        }
    }
}

impl AsRef<EncapsulatedMessageWithVerifiedPublicHeader>
    for SessionBoundEncapsulatedMessageWithVerifiedHeader
{
    fn as_ref(&self) -> &EncapsulatedMessageWithVerifiedPublicHeader {
        &self.message
    }
}

impl AsMut<EncapsulatedMessageWithVerifiedPublicHeader>
    for SessionBoundEncapsulatedMessageWithVerifiedHeader
{
    fn as_mut(&mut self) -> &mut EncapsulatedMessageWithVerifiedPublicHeader {
        &mut self.message
    }
}
