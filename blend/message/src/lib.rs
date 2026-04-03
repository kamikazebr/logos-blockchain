pub mod crypto;
pub mod encap;
mod error;
pub mod input;
mod message;
pub mod reward;

pub use encap::encapsulated::MessageIdentifier;
pub use error::Error;
use lb_core::codec::{DeserializeOp as _, SerializeOp};
pub use message::payload::{PaddedPayloadBody, PayloadType};

use crate::encap::{
    encapsulated::EncapsulatedMessage,
    validated::{
        EncapsulatedMessageWithVerifiedPublicHeader, EncapsulatedMessageWithVerifiedSignature,
    },
};

#[must_use]
pub fn serialize_encapsulated_message_with_verified_public_header(
    message: &EncapsulatedMessageWithVerifiedPublicHeader,
) -> Vec<u8> {
    serialize_message(message)
}

#[must_use]
pub fn serialize_encapsulated_message_with_verified_signature(
    message: &EncapsulatedMessageWithVerifiedSignature,
) -> Vec<u8> {
    serialize_message(message)
}

fn serialize_message<Message>(message: &Message) -> Vec<u8>
where
    Message: SerializeOp,
{
    message
        .to_bytes()
        .expect("Message should be serializable")
        .to_vec()
}

pub fn deserialize_encapsulated_message(message: &[u8]) -> Result<EncapsulatedMessage, Error> {
    EncapsulatedMessage::from_bytes(message).map_err(|_| Error::MessageDeserializationFailed)
}
