use std::io::{Cursor, Write};

pub use super::errors::{IntegrityKeyGenerationError, MessageDecodeError, MessageEncodeError};
use super::message::StunMessage;

use crate::attribute::StunAttribute;

impl StunMessage {
    /// Encodes the STUN message into a binary representation
    ///
    /// Arguments:
    ///
    /// * `integrity_password`: Optionally set key that will be used for message integrity generation. Required if a MessageIntegrity attribute is present.
    pub fn encode(&self, integrity_password: Option<&str>) -> Result<Vec<u8>, MessageEncodeError> {
        let attr_count = self.attributes.len();
        let mut cursor = Cursor::new(Vec::new());

        // Encode and write the header
        let encoded_header = &self.header.encode()?;
        cursor.write_all(encoded_header)?;

        // Mark that a message integrity attribute is present
        let mut msg_integrity_present = false;

        // Track for username/realm occurrences
        let mut username = None;
        let mut realm = None;

        // Process each attribute and encode it
        for (idx, attr) in self.attributes.clone().iter().enumerate() {
            let processed_attr = match attr {
                // Track the username attribute being set
                StunAttribute::Username { value } => {
                    username = Some(value.clone());

                    attr.clone()
                }
                // Track the realm attribute being set
                StunAttribute::Realm { value } => {
                    realm = Some(value.clone());

                    attr.clone()
                }
                // Process the Fingerprint attribute
                StunAttribute::Fingerprint { value } => {
                    // Make sure that the Fingerprint attribute is the last one
                    if attr_count - 1 != idx {
                        return Err(MessageEncodeError::IncorrectFingerprintAttributePosition {
                            attr_count,
                            fingerprint_attr_idx: idx,
                        });
                    }
                    // Check if it contains a placeholder value and replace it with the computed fingerprint
                    if *value == 0 {
                        // Update the encoded message length so the correct fingerprint can be calculated
                        self.set_message_length(&mut cursor.get_mut(), 8);

                        // Update the fingerprint value
                        let fingerprint = Self::calculate_fingerprint(cursor.get_ref());

                        StunAttribute::Fingerprint { value: fingerprint }
                    } else {
                        attr.clone()
                    }
                }
                // Process the MessageIntegrity attribute
                StunAttribute::MessageIntegrity { key } => {
                    // Mark it as present
                    msg_integrity_present = true;

                    // In case of placeholder data, replace it with the calculated HMAC value
                    if key.is_empty() {
                        if let Some(integrity_password) = integrity_password {
                            // Calculate the integrity key
                            let integrity_key = Self::calculate_integrity_key(
                                integrity_password,
                                realm.clone(),
                                username.clone(),
                            )?;

                            let hmac =
                                Self::calculate_integrity_hash(&integrity_key, cursor.get_ref());

                            StunAttribute::MessageIntegrity { key: hmac }
                        } else {
                            // Return an error if no `integrity_password` is submitted with placeholder data
                            return Err(MessageEncodeError::MissingIntegrityPassword());
                        }
                    } else {
                        // Return pre-submitted data
                        attr.clone()
                    }
                }
                _ => {
                    // If a MessageIntegrity attribute has been already addded,
                    // no other attributes (except Fingerprint) can be added after it
                    if msg_integrity_present {
                        return Err(MessageEncodeError::AttributeAfterIntegrity());
                    }

                    attr.clone()
                }
            };

            // Encode and write the attribute
            let encoded_attr = processed_attr.encode(self.header.transaction_id)?;
            cursor.write_all(&encoded_attr)?;
        }

        // Update the encoded message length
        self.set_message_length(&mut cursor.get_mut(), 0);

        // Return the encoded data
        Ok(cursor.get_ref().to_vec())
    }
}
