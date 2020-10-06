use std::io::Cursor;

use crate::definitions::{STUN_FINGERPRINT_ATTR_SIZE, STUN_INTEGRITY_ATTR_SIZE};
use crate::StunHeader;
use crate::{AttributeDecodeError, StunAttribute};

pub use super::errors::{IntegrityKeyGenerationError, MessageDecodeError, MessageEncodeError};
use super::message::StunMessage;

impl StunMessage {
    /// Decodes and returns the STUN message
    ///
    /// Arguments:
    ///
    /// * `bytes`: binary encoded message to decode from
    /// * `integrity_password`: Optionally set key that will be used for message integrity verification
    pub fn decode(
        bytes: &[u8],
        integrity_password: Option<&str>,
    ) -> Result<Self, MessageDecodeError> {
        let data_len = bytes.len();
        let mut cursor = Cursor::new(bytes);

        // Decode header
        let header = StunHeader::decode(&mut cursor)?;

        // Decode attributes
        let mut attributes = Vec::new();

        let mut integrity_attr_passed = false;

        // Track for username/realm occurrences
        let mut username = None;
        let mut realm = None;

        while cursor.position() < data_len as u64 {
            let decoded = StunAttribute::decode(&mut cursor, header.transaction_id);

            match decoded {
                Ok(decoded) => {
                    // Ignore all attributes after the MESSAGE-INTEGRITY attribute.
                    // As per [RFC5389 Section 15.4](https://tools.ietf.org/html/rfc5389#section-15.4)
                    if !integrity_attr_passed {
                        attributes.push(decoded.clone());
                    }

                    // Handle Fingerprint and MessageIntegrity attributes
                    match decoded {
                        StunAttribute::Username { value } => {
                            username = Some(value);
                        }
                        StunAttribute::Realm { value } => {
                            realm = Some(value);
                        }
                        StunAttribute::Fingerprint { value } => {
                            let attr_pos = cursor.position() as usize - STUN_FINGERPRINT_ATTR_SIZE;

                            // Make sure the Fingerprint attribute is the last one
                            if cursor.position() != bytes.len() as u64 {
                                return Err(
                                    MessageDecodeError::IncorrectFingerprintAttributePosition {
                                        msg_len: bytes.len(),
                                        attr_pos: attr_pos as usize,
                                    },
                                );
                            }

                            // Compute fingerprint for verification
                            let computed_fingerprint =
                                Self::calculate_fingerprint(&cursor.get_ref()[0..attr_pos]);

                            // Make sure the fingerprint matches
                            if computed_fingerprint != value {
                                return Err(MessageDecodeError::FingerprintMismatch {
                                    attr_value: value,
                                    computed_value: computed_fingerprint,
                                });
                            }

                            if integrity_attr_passed {
                                // Push the attribute to the list explicitly since it's after the MessageIntegrity attribute
                                attributes.push(decoded);
                            }
                        }
                        StunAttribute::MessageIntegrity { key } => {
                            // Mark MessageIntegrity attribute as passed so we can ignore attributes that happen after it
                            // With the exception of the Fingerprint attribute
                            integrity_attr_passed = true;

                            // If an `integrity_password` has been supplied, recalculate and verify the HMAC value
                            if let Some(integrity_password) = integrity_password {
                                let integrity_key = Self::calculate_integrity_key(
                                    integrity_password,
                                    realm.clone(),
                                    username.clone(),
                                )?;

                                let hmac = Self::calculate_integrity_hash(
                                    &integrity_key,
                                    &cursor.get_ref()[0..(cursor.position() as usize
                                        - STUN_INTEGRITY_ATTR_SIZE)
                                        as usize],
                                );

                                // Verify message integrity
                                if hmac != key {
                                    return Err(MessageDecodeError::MessageIntegrityFail {
                                        attr_value: key,
                                        computed_value: hmac,
                                    });
                                }
                            }
                        }
                        _ => {}
                    };
                }
                Err(err) => {
                    match err {
                        AttributeDecodeError::UnrecognizedAttributeType { attr_type } => {
                            // Attributes with type values between 0x8000 and 0xFFFF are
                            // comprehension-optional attributes, which means that those attributes
                            // can be ignored by the STUN agent if it does not understand them.
                            // Only return an error when the attribute is comprehension-required
                            if attr_type <= 0x8000 {
                                return Err(MessageDecodeError::from(err));
                            }
                        }
                        // Return an error on any other attribute decoding error
                        _ => return Err(MessageDecodeError::from(err)),
                    }
                }
            }
        }

        Ok(Self { header, attributes })
    }
}
