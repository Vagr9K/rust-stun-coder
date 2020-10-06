#[derive(Debug, Copy, Clone, FromPrimitive, Ord, PartialOrd, Eq, PartialEq)]
/// [STUN message class](https://tools.ietf.org/html/rfc5389#section-6)
///
/// The message type defines the message class (request, success response, failure response, or indication).
pub enum StunMessageClass {
    /// STUN request
    Request = 0b0000_0000_0000_0000,
    /// STUN indication
    Indication = 0b0000_0000_0001_0000,
    /// STUN success response
    SuccessResponse = 0b0000_0001_0000_0000,
    /// STUN error response
    ErrorResponse = 0b0000_0001_0001_0000,
}
