use byteorder::{ByteOrder, NetworkEndian};
use crc::{crc32, Hasher32};
use crypto::digest::Digest;
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::md5::Md5;
use crypto::sha1::Sha1;

pub use super::errors::{IntegrityKeyGenerationError, MessageDecodeError, MessageEncodeError};

use super::message::StunMessage;
use crate::definitions::{STUN_HEADER_SIZE, STUN_INTEGRITY_ATTR_SIZE};

impl StunMessage {
    /// Encodes and sets the encoded message length
    ///
    /// Arguments:
    ///
    /// * `encoded_message`: Encoded message buffer
    /// * `len`: length number to be set
    pub(super) fn set_encoded_message_length(encoded_message: &mut [u8], len: u16) {
        NetworkEndian::write_u16(&mut encoded_message[2..4], len);
    }

    /// Sets the correct length into the encoding buffer
    /// Arguments:
    ///
    /// * `encoded_message`: Encoded message buffer
    /// * `placeholder_size`: Adds to the calculated size of the current buffer
    pub(super) fn set_message_length(&self, encoded_message: &mut [u8], placeholder_size: u16) {
        let msg_len = encoded_message.len() as u16 - STUN_HEADER_SIZE as u16 + placeholder_size;

        Self::set_encoded_message_length(encoded_message, msg_len);
    }

    /// Calculates the CRC32 Fingerprint for the message according to [RFC5389](https://tools.ietf.org/html/rfc5389#section-15.5)
    ///
    /// Arguments:
    ///
    /// * `encoded_message`: Encoded message without the Fingerprint attribute section
    pub(super) fn calculate_fingerprint(encoded_message: &[u8]) -> u32 {
        let mut crc = crc32::Digest::new(crc32::IEEE);
        crc.write(encoded_message);
        crc.sum32() ^ 0x5354_554e
    }

    /// Calculates the integrity key used for generating HMAC according to [RFC5389](https://tools.ietf.org/html/rfc5389#section-15.4)
    ///
    /// Arguments:
    ///
    /// * `integrity_password`: Password used for HMAC
    /// * `realm`: Optional argument that contains the "realm". If provided long-term credentials key will be generated
    /// * `username`: Optional argument that contains the "username". Required it the `realm` is provided.
    pub(super) fn calculate_integrity_key(
        integrity_password: &str,
        realm: Option<String>,
        username: Option<String>,
    ) -> Result<Vec<u8>, IntegrityKeyGenerationError> {
        let key = match realm {
            Some(realm) => {
                if let Some(username) = username {
                    let hash_input = format!(
                        "{}:{}:{}",
                        username,
                        realm,
                        stringprep::saslprep(integrity_password)?
                    );

                    let mut hasher = Md5::new();
                    hasher.input_str(&hash_input);

                    let mut res = vec![0u8; 16];
                    hasher.result(&mut res);

                    res
                } else {
                    return Err(IntegrityKeyGenerationError::MissingUsername());
                }
            }
            None => stringprep::saslprep(integrity_password)?
                .as_bytes()
                .to_vec(),
        };

        Ok(key)
    }

    /// Calculates the integrity hash according to [RFC5389](https://tools.ietf.org/html/rfc5389#section-15.4)
    ///
    /// Arguments:
    ///
    /// * `key`: HMAC key to use
    /// * `msg_integrity_buffer`: Encoded message without the Integrity and Fingerprint attribute sections
    pub(super) fn calculate_integrity_hash(key: &[u8], encoded_message: &[u8]) -> Vec<u8> {
        let mut msg_integrity_buffer = encoded_message.to_vec();
        let buffer_len = msg_integrity_buffer.len();

        // Set the message length to a number that includes the MessageIntegrity attribute size but ignores everything after it
        Self::set_encoded_message_length(
            &mut msg_integrity_buffer,
            (buffer_len - STUN_HEADER_SIZE + STUN_INTEGRITY_ATTR_SIZE) as u16,
        );

        // Calculate hash
        let mut mac = Hmac::new(Sha1::new(), key);
        mac.input(&msg_integrity_buffer);
        mac.result().code().to_vec()
    }
}
