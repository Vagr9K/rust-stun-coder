#[derive(Debug, Copy, Clone, FromPrimitive)]
/// [STUN message method](https://tools.ietf.org/html/rfc5389#section-18.1)
///
/// A STUN method is a hex number in the range 0x000 - 0xFFF.  The
/// encoding of STUN method into a STUN message is described in
/// Section 6.

/// The initial STUN methods are:

/// 0x000: (Reserved)
/// 0x001: Binding
/// 0x002: (Reserved; was SharedSecret)

/// STUN methods in the range 0x000 - 0x7FF are assigned by IETF Review
/// [RFC5226](https://tools.ietf.org/html/rfc5226).  STUN methods in the range 0x800 - 0xFFF are assigned by
/// Designated Expert [RFC5226](https://tools.ietf.org/html/rfc5226).  The responsibility of the expert is to
/// verify that the selected codepoint(s) are not in use and that the
/// request is not for an abnormally large number of codepoints.
/// Technical review of the extension itself is outside the scope of the
/// designated expert responsibility.
pub enum StunMessageMethod {
    /// STUN binding request method
    BindingRequest = 0b0000_0000_0000_0001,
}
