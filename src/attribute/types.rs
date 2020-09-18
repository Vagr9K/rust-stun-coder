/// Readable representation of STUN attribute type codes.
#[derive(Copy, Clone, FromPrimitive)]
pub enum StunAttributeType {
    MappedAddress = 0x0001,
    Username = 0x0006,
    MessageIntegrity = 0x0008,
    ErrorCode = 0x0009,
    UnknownAttributes = 0x000a,
    Realm = 0x0014,
    Nonce = 0x0015,
    XorMappedAddress = 0x0020,
    UseCandidate = 0x0025,
    IceControlled = 0x8029,
    IceControlling = 0x802A,
    Priority = 0x0024,
    Software = 0x8022,
    AlternateServer = 0x8023,
    Fingerprint = 0x8028,
}
