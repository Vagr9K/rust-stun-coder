use thiserror::Error;

/// Attribute encoding errors.
#[derive(Error, Debug)]
pub enum AttributeDecodeError {
    /// Error reading field value.
    #[error("Error reading field value.")]
    ReadFailure(#[from] std::io::Error),
    /// Failed to convert byte sequence into a UTF-8 string.
    #[error("Failed to convert byte sequence into a UTF-8 string.")]
    InvalidString(#[from] std::string::FromUtf8Error),
    /// Not enough data was provided to decode the value.
    #[error("Not enough data.")]
    InsufficientData(),
    /// Unrecognized field value was provided.
    #[error("Invalid field value: {0}.")]
    InvalidValue(u128),
    /// Unrecognized attribute type value was provided.
    #[error("Unrecognized attribute type value: {attr_type:?}.")]
    UnrecognizedAttributeType {
        /// The provided attribute type that was not recognized
        attr_type: u16,
    },
}

/// Attribute decoding errors.
#[derive(Error, Debug)]
pub enum AttributeEncodeError {
    /// Error writing field value.
    #[error("Error writing field value.")]
    WriteFailure(#[from] std::io::Error),
    /// The encoded UTF-8 value crosses the size limit for the field.
    /// The REALM, SERVER, reason phrases, and NONCE are limited to 127 characters (763 bytes). USERNAME to 513 bytes.
    #[error("UTF-8 value too big. Limit: {limit}, current length: {length}.")]
    Utf8ValueTooBig {
        /// The size limit specified in RFC
        limit: usize,
        /// The current length of the encoded value
        length: usize,
    },
}
