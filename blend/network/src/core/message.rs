use lb_blend_message::{
    MessageIdentifier,
    encap::validated::{
        EncapsulatedMessageWithVerifiedPublicHeader, EncapsulatedMessageWithVerifiedSignature,
    },
};
use serde::{Deserialize, Serialize};

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

    #[must_use]
    pub const fn session(&self) -> u64 {
        self.session
    }

    #[must_use]
    pub const fn id(&self) -> MessageIdentifier {
        self.message.id()
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
