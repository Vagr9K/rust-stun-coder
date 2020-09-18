use thiserror::Error;

/// Header encoding errors.
#[derive(Error, Debug)]
pub enum HeaderDecodeError {
    /// Failed to read field value.
    #[error("Failed to read field value.")]
    ReadFailure(#[from] std::io::Error),
    /// The magic cookie field received in STUN header doesn't match with 0x2112a442.
    /// It's possible that the received byte sequence is not a STUN message.
    #[error("Magic cookie mismatch.")]
    MagicCookieMismatch(),
    /// Unrecognized message method type value.
    #[error("Unrecognized message method type value: {0}.")]
    UnrecognizedMessageMethod(u16),
    /// Unrecognized message class type value.
    #[error("Unrecognized message class type value: {0}.")]
    UnrecognizedMessageClass(u16),
}

/// Header decoding errors.
#[derive(Error, Debug)]
pub enum HeaderEncodeError {
    /// Failed to write field value.
    #[error("Failed to write field value.")]
    WriteFailure(#[from] std::io::Error),
}
