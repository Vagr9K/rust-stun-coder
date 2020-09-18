use crate::{AttributeDecodeError, AttributeEncodeError, HeaderDecodeError, HeaderEncodeError};
use thiserror::Error;

/// Integrity Key Errors
#[derive(Error, Debug)]
pub enum IntegrityKeyGenerationError {
    /// SASLprep failure during key generation
    #[error("Failed to process key section via SASLprep.")]
    SASLPrepFailure(#[from] stringprep::Error),
    /// Fails key generation due to missing `username`. May happen when a STUN message contains the REALM but not the username attribute
    #[error("No username has been provided for long-term credential key generation")]
    MissingUsername(),
}

/// Message encoding errors.
#[derive(Error, Debug)]
pub enum MessageDecodeError {
    /// IO error when reading a field value
    #[error("Error reading field value.")]
    ReadFailure(#[from] std::io::Error),
    /// Failure to decode the STUN header section
    #[error("Error decoding STUN header.")]
    HeaderDecodeFailure(#[from] HeaderDecodeError),
    /// Failure to decode a STUN attribute
    #[error("Error decoding STUN attribute.")]
    AttributeDecodeFailure(#[from] AttributeDecodeError),
    /// Failure to generate an integrity verification key
    #[error("Error decoding STUN attribute.")]
    IntegrityKeyGenerationFailure(#[from] IntegrityKeyGenerationError),
    /// Fingerprint attribute is not the last one.
    /// This can mean that either the provided byte data contains more than only the STUN message, or message integrity has been compromised.
    #[error("Fingerprint attribute is not the last one. Message length: {msg_len}, attribute position: {attr_pos}.")]
    IncorrectFingerprintAttributePosition {
        /// STUN message length
        msg_len: usize,
        /// Fingerprint attribute position in that message
        attr_pos: usize,
    },
    /// Stored and calculated fingerprints mismatch.
    /// Means that the message integrity has been compromised.
    #[error("Fingerprint value mismatch. Attribute value: {attr_value:#X?}, computed value: {computed_value:#X?}.")]
    FingerprintMismatch {
        /// Provided CRC32 value
        attr_value: u32,
        /// Computed CRC32 value
        computed_value: u32,
    },
    /// The calculated HMAC value doesn't match with the provided one.
    /// Either the provided `integrity_key` is incorrect or the message integrity has been compromised.
    #[error("Message integrity is compromised. Attribute HMAC value: {attr_value:#X?}, computed HMAC value: {computed_value:#X?}.")]
    MessageIntegrityFail {
        /// Provided HMAC
        attr_value: Vec<u8>,
        /// Calculated HMAC
        computed_value: Vec<u8>,
    },
}

/// Message decoding errors.
#[derive(Error, Debug)]
pub enum MessageEncodeError {
    /// IO error when writing a field value
    #[error("Error writing field value.")]
    WriteFailure(#[from] std::io::Error),
    /// Failure to encode the STUN header section.
    #[error("Error encoding STUN header.")]
    HeaderEncodeFailure(#[from] HeaderEncodeError),
    /// Failure to encode a STUN attribute
    #[error("Error encoding STUN attribute.")]
    AttributeEncodeFailure(#[from] AttributeEncodeError),
    /// Failure to generate an integrity verification key
    #[error("Error decoding STUN attribute.")]
    IntegrityKeyGenerationFailure(#[from] IntegrityKeyGenerationError),
    /// The Fingerprint attribute is not the last one provided.
    #[error("Fingerprint attribute is not the last one. Attributes count: {attr_count}, fingerprint attribute index: {fingerprint_attr_idx}.")]
    IncorrectFingerprintAttributePosition {
        /// Amount of provided attributes
        attr_count: usize,
        /// Index of the Fingerprint attribute
        fingerprint_attr_idx: usize,
    },
    /// An attribute was added after the MessageIntegrity attribute. Only a single Fingerprint attribute can be added after it.
    #[error("An attribute was added after the MessageIntegrity attribute. Only the Fingerprint attribute can be placed after the MessageIntegrity attribute.")]
    AttributeAfterIntegrity(),
    /// A placeholder MessageIntegrity attribute was set, but no `integrity_key` argument was provided to the `encode` function making the HMAC computation impossible.
    #[error("Missing message integrity password. A placeholder HMAC value is set in MessageIntegrity attribute but no `integrity_password` is provided as an encoding argument.")]
    MissingIntegrityPassword(),
}
