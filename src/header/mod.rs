use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use num_traits::FromPrimitive;
use std::io::{Cursor, Read, Write};

mod errors;
mod message_class;
mod message_method;

use crate::definitions::{StunTransactionId, STUN_MAGIC_COOKIE_U32};
use crate::utils::generate_transaction_id;
pub use errors::{HeaderDecodeError, HeaderEncodeError};
pub use message_class::StunMessageClass;
pub use message_method::StunMessageMethod;

#[derive(Debug, Copy, Clone)]
/// [STUN message header](https://tools.ietf.org/html/rfc5389#section-6)
///
/// All STUN messages MUST start with a 20-byte header followed by zero
/// or more Attributes.  The STUN header contains a STUN message type,
/// magic cookie, transaction ID, and message length.
///
/// The most significant 2 bits of every STUN message MUST be zeroes.
/// This can be used to differentiate STUN packets from other protocols
/// when STUN is multiplexed with other protocols on the same port.
///
/// The message type defines the message class (request, success
/// response, failure response, or indication) and the message method
/// (the primary function) of the STUN message.  Although there are four
/// message classes, there are only two types of transactions in STUN:
/// request/response transactions (which consist of a request message and
/// a response message) and indication transactions (which consist of a
/// single indication message).  Response classes are split into error
/// and success responses to aid in quickly processing the STUN message.

pub struct StunHeader {
    /// STUN message class
    pub message_class: StunMessageClass,
    /// STUN message method
    pub message_method: StunMessageMethod,
    /// STUN transaction id
    pub transaction_id: StunTransactionId,
    /// STUN message length
    /// Only set to a non-zero value when decoding the header
    pub message_len: u16,
}

impl StunHeader {
    /// Creates a new header
    ///
    /// If no `transaction_id` is provided, one is randomly generated and set
    /// The `message_len` is set as zero and left untouched unless a decoder sets it.
    pub(crate) fn new(
        message_method: StunMessageMethod,
        message_class: StunMessageClass,
        transaction_id: Option<StunTransactionId>,
    ) -> Self {
        // Pick a transaction_id
        let transaction_id = match transaction_id {
            Some(id) => id,
            None => generate_transaction_id(),
        };

        Self {
            message_method,
            message_class,
            transaction_id,
            message_len: 0, // Placeholder for the encoder to later fill in
        }
    }

    /// Decodes and returns a STUN message header
    pub(crate) fn decode(cursor: &mut Cursor<&[u8]>) -> Result<Self, HeaderDecodeError> {
        let stun_type_field = cursor.read_u16::<NetworkEndian>()?;
        let msg_len = cursor.read_u16::<NetworkEndian>()?;
        let magic_cookie = cursor.read_u32::<NetworkEndian>()?;

        if magic_cookie != STUN_MAGIC_COOKIE_U32 {
            return Err(HeaderDecodeError::MagicCookieMismatch());
        }

        let mut transaction_id = [0; 12];
        cursor.read_exact(&mut transaction_id)?;

        let stun_class = stun_type_field & 0b0000_0001_0001_0000;
        let stun_method = stun_type_field & 0b1111_1110_1110_1111;

        let message_method: StunMessageMethod = FromPrimitive::from_u16(stun_method)
            .ok_or(HeaderDecodeError::UnrecognizedMessageMethod(stun_method))?;
        let message_class: StunMessageClass = FromPrimitive::from_u16(stun_class)
            .ok_or(HeaderDecodeError::UnrecognizedMessageClass(stun_class))?;

        Ok(Self {
            message_method,
            message_class,
            message_len: msg_len,
            transaction_id,
        })
    }

    /// Encodes itself into the binary representation defined by [RFC5389](https://tools.ietf.org/html/rfc5389)
    pub(crate) fn encode(&self) -> Result<Vec<u8>, HeaderEncodeError> {
        let bytes = Vec::new();
        let mut cursor = Cursor::new(bytes);

        let stun_type_field = self.message_class as u16 | self.message_method as u16;

        cursor.write_u16::<NetworkEndian>(stun_type_field)?;
        cursor.write_u16::<NetworkEndian>(self.message_len)?;
        cursor.write_u32::<NetworkEndian>(STUN_MAGIC_COOKIE_U32)?;
        cursor.write_all(&self.transaction_id)?;

        Ok(cursor.get_ref().to_vec())
    }
}
