use std::net::SocketAddr;

/// [STUN message attribute](https://tools.ietf.org/html/rfc5389#section-15)
///
///   After the STUN header are zero or more attributes.  Each attribute
///   MUST be TLV encoded, with a 16-bit type, 16-bit length, and value.
///   Each STUN attribute MUST end on a 32-bit boundary.  As mentioned
///   above, all fields in an attribute are transmitted most significant
///   bit first.
///   The value in the length field MUST contain the length of the Value
///   part of the attribute, prior to padding, measured in bytes.  Since
///   STUN aligns attributes on 32-bit boundaries, attributes whose content
///   is not a multiple of 4 bytes are padded with 1, 2, or 3 bytes of
///   padding so that its value contains a multiple of 4 bytes.  The
///   padding bits are ignored, and may be any value.
///
///   Any attribute type MAY appear more than once in a STUN message.
///   Unless specified otherwise, the order of appearance is significant:
///   only the first occurrence needs to be processed by a receiver, and
///   any duplicates MAY be ignored by a receiver.
///
///   To allow future revisions of this specification to add new attributes
///   if needed, the attribute space is divided into two ranges.
///   Attributes with type values between 0x0000 and 0x7FFF are
///   comprehension-required attributes, which means that the STUN agent
///   cannot successfully process the message unless it understands the
///   attribute. Attributes with type values between 0x8000 and 0xFFFF are
///   comprehension-optional attributes, which means that those attributes
///   can be ignored by the STUN agent if it does not understand them.
///
///   The set of STUN attribute types is maintained by IANA. The initial
///   set defined by this specification is found in [Section 18.2](https://tools.ietf.org/html/rfc5389#section-18.2).
///
///   The rest of this section describes the format of the various
///   attributes defined in this specification.

#[derive(Debug, Clone)]
pub enum StunAttribute {
    /// [RFC5389: MAPPED-ADDRESS](https://tools.ietf.org/html/rfc5389#section-15.1)
    ///
    /// The MAPPED-ADDRESS attribute indicates a reflexive transport address
    /// of the client.  It consists of an 8-bit address family and a 16-bit
    /// port, followed by a fixed-length value representing the IP address.
    /// If the address family is IPv4, the address MUST be 32 bits.  If the
    /// address family is IPv6, the address MUST be 128 bits.  All fields
    /// must be in network byte order.
    ///
    /// This attribute is used only by servers for achieving backwards
    /// compatibility with [RFC3489](https://tools.ietf.org/html/rfc3489) clients.
    MappedAddress {
        /// Reflexive transport address of the client.
        socket_addr: SocketAddr,
    },
    /// [RFC5389: XOR-MAPPED-ADDRESS](https://tools.ietf.org/html/rfc5389#section-15.2)
    ///
    /// The XOR-MAPPED-ADDRESS attribute is identical to the MAPPED-ADDRESS
    /// attribute, except that the reflexive transport address is obfuscated
    /// through the XOR function.
    ///
    /// Note: XOR-MAPPED-ADDRESS and MAPPED-ADDRESS differ only in their
    /// encoding of the transport address. The former encodes the transport
    /// address by exclusive-or'ing it with the magic cookie. The latter
    /// encodes it directly in binary. [RFC 3489](https://tools.ietf.org/html/rfc3489) originally specified only
    /// MAPPED-ADDRESS. However, deployment experience found that some NATs
    /// rewrite the 32-bit binary payloads containing the NAT's public IP
    /// address, such as STUN's MAPPED-ADDRESS attribute, in the well-meaning
    /// but misguided attempt at providing a generic ALG function. Such
    /// behavior interferes with the operation of STUN and also causes
    /// failure of STUN's message-integrity checking.
    XorMappedAddress {
        /// Reflexive transport address of the client.
        socket_addr: SocketAddr,
    },
    /// [RFC5389: USERNAME](https://tools.ietf.org/html/rfc5389#section-15.3)
    ///
    /// The USERNAME attribute is used for message integrity. It identifies
    /// the username and password combination used in the message-integrity
    /// check.
    ///
    /// The value of USERNAME is a variable-length value. It MUST contain a
    /// UTF-8 [RFC3629](https://tools.ietf.org/html/rfc3629) encoded sequence of less than 513 bytes, and MUST
    /// have been processed using SASLprep [RFC4013](https://tools.ietf.org/html/rfc4013).
    Username {
        /// The username and password combination used in the message-integrity check.
        value: String,
    },
    /// [RFC5389: MESSAGE-INTEGRITY](https://tools.ietf.org/html/rfc5389#section-15.4)
    ///
    /// The MESSAGE-INTEGRITY attribute contains an HMAC-SHA1 [RFC2104](https://datatracker.ietf.org/doc/html/rfc2104) of
    /// the STUN message.  The MESSAGE-INTEGRITY attribute can be present in
    /// any STUN message type.  Since it uses the SHA1 hash, the HMAC will be
    /// 20 bytes.  The text used as input to HMAC is the STUN message,
    /// including the header, up to and including the attribute preceding the
    /// MESSAGE-INTEGRITY attribute.  With the exception of the FINGERPRINT
    /// attribute, which appears after MESSAGE-INTEGRITY, agents MUST ignore
    /// all other attributes that follow MESSAGE-INTEGRITY.
    ///
    /// The key for the HMAC depends on whether long-term or short-term
    /// credentials are in use.  For long-term credentials, the key is 16
    /// bytes:
    ///```text
    ///          key = MD5(username ":" realm ":" SASLprep(password))
    ///```
    /// That is, the 16-byte key is formed by taking the MD5 hash of the
    /// result of concatenating the following five fields: (1) the username,
    /// with any quotes and trailing nulls removed, as taken from the
    /// USERNAME attribute (in which case SASLprep has already been applied);
    /// (2) a single colon; (3) the realm, with any quotes and trailing nulls
    /// removed; (4) a single colon; and (5) the password, with any trailing
    /// nulls removed and after processing using SASLprep.  For example, if
    /// the username was 'user', the realm was 'realm', and the password was
    /// 'pass', then the 16-byte HMAC key would be the result of performing
    /// an MD5 hash on the string 'user:realm:pass', the resulting hash being
    /// 0x8493fbc53ba582fb4c044c456bdc40eb.
    ///
    /// For short-term credentials:
    ///```text
    ///                  key = SASLprep(password)
    ///```
    /// where MD5 is defined in [RFC 1321](https://tools.ietf.org/html/rfc1321) and SASLprep() is defined
    /// in [RFC 4013](https://tools.ietf.org/html/rfc4013).
    ///
    /// The structure of the key when used with long-term credentials
    /// facilitates deployment in systems that also utilize SIP.  Typically,
    /// SIP systems utilizing SIP's digest authentication mechanism do not
    /// actually store the password in the database.  Rather, they store a
    /// value called H(A1), which is equal to the key defined above.
    ///
    /// Based on the rules above, the hash used to construct MESSAGE-
    /// INTEGRITY includes the length field from the STUN message header.
    /// Prior to performing the hash, the MESSAGE-INTEGRITY attribute MUST be
    /// inserted into the message (with dummy content).  The length MUST then
    /// be set to point to the length of the message up to, and including,
    /// the MESSAGE-INTEGRITY attribute itself, but excluding any attributes
    /// after it.  Once the computation is performed, the value of the
    /// MESSAGE-INTEGRITY attribute can be filled in, and the value of the
    /// length in the STUN header can be set to its correct value -- the
    /// length of the entire message.  Similarly, when validating the
    /// MESSAGE-INTEGRITY, the length field should be adjusted to point to
    /// the end of the MESSAGE-INTEGRITY attribute prior to calculating the
    /// HMAC.  Such adjustment is necessary when attributes, such as
    /// FINGERPRINT, appear after MESSAGE-INTEGRITY.
    MessageIntegrity {
        /// HMAC-SHA1 ([RFC2104](https://tools.ietf.org/html/rfc2104)) of the STUN message.
        key: Vec<u8>,
    },
    /// [RFC5389: FINGERPRINT](https://tools.ietf.org/html/rfc5389#section-15.5)
    ///
    /// The FINGERPRINT attribute MAY be present in all STUN messages.  The
    /// value of the attribute is computed as the CRC-32 of the STUN message
    /// up to (but excluding) the FINGERPRINT attribute itself, XOR'ed with
    /// the 32-bit value 0x5354554e (the XOR helps in cases where an
    /// application packet is also using CRC-32 in it).  The 32-bit CRC is
    /// the one defined in [ITU V.42](https://tools.ietf.org/html/rfc5389#ref-ITU.V42.2002), which has a generator
    /// polynomial of x32+x26+x23+x22+x16+x12+x11+x10+x8+x7+x5+x4+x2+x+1.
    /// When present, the FINGERPRINT attribute MUST be the last attribute in
    /// the message, and thus will appear after MESSAGE-INTEGRITY.
    ///
    /// The FINGERPRINT attribute can aid in distinguishing STUN packets from
    /// packets of other protocols. See [Section 8](https://tools.ietf.org/html/rfc5389#section-8).
    ///
    /// As with MESSAGE-INTEGRITY, the CRC used in the FINGERPRINT attribute
    /// covers the length field from the STUN message header.  Therefore,
    /// this value must be correct and include the CRC attribute as part of
    /// the message length, prior to computation of the CRC.  When using the
    /// FINGERPRINT attribute in a message, the attribute is first placed
    /// into the message with a dummy value, then the CRC is computed, and
    /// then the value of the attribute is updated.  If the MESSAGE-INTEGRITY
    /// attribute is also present, then it must be present with the correct
    /// message-integrity value before the CRC is computed, since the CRC is
    /// done over the value of the MESSAGE-INTEGRITY attribute as well.
    Fingerprint {
        /// CRC-32 of the STUN message up to (but excluding) the FINGERPRINT attribute itself, XOR'ed with the 32-bit value 0x5354554e
        value: u32,
    },
    /// [RFC5389: ERROR-CODE](https://tools.ietf.org/html/rfc5389#section-15.6)
    ///
    /// The ERROR-CODE attribute is used in error response messages.  It
    /// contains a numeric error code value in the range of 300 to 699 plus a
    /// textual reason phrase encoded in UTF-8 [RFC3629](https://tools.ietf.org/html/rfc3629), and is consistent
    /// in its code assignments and semantics with SIP [RFC3261](https://tools.ietf.org/html/rfc3261) and HTTP
    /// [RFC2616](https://tools.ietf.org/html/rfc2616).  The reason phrase is meant for user consumption, and can
    /// be anything appropriate for the error code.  Recommended reason
    /// phrases for the defined error codes are included in the IANA registry
    /// for error codes.  The reason phrase MUST be a UTF-8 [RFC3629](https://tools.ietf.org/html/rfc3629) encoded
    /// sequence of less than 128 characters (which can be as long as 763
    /// bytes).
    ErrorCode {
        /// Error class
        class: u8,
        /// Error number
        number: u8,
        /// Reason phrase
        reason: String,
    },
    /// [RFC5389: REALM](https://tools.ietf.org/html/rfc5389#section-15.7)
    ///
    /// The REALM attribute may be present in requests and responses.  It
    /// contains text that meets the grammar for "realm-value" as described
    /// in [RFC3261](https://tools.ietf.org/html/rfc3261) but without the double quotes and their
    /// surrounding whitespace.  That is, it is an unquoted realm-value (and
    /// is therefore a sequence of qdtext or quoted-pair).  It MUST be a
    /// UTF-8 [RFC3629](https://tools.ietf.org/html/rfc3629) encoded sequence of less than 128 characters (which
    /// can be as long as 763 bytes), and MUST have been processed using
    /// SASLprep [RFC 4013](https://tools.ietf.org/html/rfc4013).
    ///
    /// Presence of the REALM attribute in a request indicates that long-term
    /// credentials are being used for authentication.  Presence in certain
    /// error responses indicates that the server wishes the client to use a
    /// long-term credential for authentication.
    Realm {
        /// Text that meets the grammar for "realm-value" as described in [RFC 3261](https://tools.ietf.org/html/rfc3261) but without the double quotes and their surrounding whitespace.
        value: String,
    },
    /// [RFC5389: NONCE](https://tools.ietf.org/html/rfc5389#section-15.8)
    /// The NONCE attribute may be present in requests and responses.  It
    /// contains a sequence of qdtext or quoted-pair, which are defined in
    /// [RFC3261](https://tools.ietf.org/html/rfc3261).  Note that this means that the NONCE attribute
    /// will not contain actual quote characters.  See [RFC2617](https://tools.ietf.org/html/rfc2617),
    /// [Section 4.3](https://tools.ietf.org/html/rfc2617#section-4.3), for guidance on selection of nonce values in a server.
    ///
    /// It MUST be less than 128 characters (which can be as long as 763
    /// bytes).
    Nonce {
        /// Sequence of qdtext or quoted-pair, which are defined in [RFC 3261](https://tools.ietf.org/html/rfc3261).
        value: String,
    },
    /// [RFC5389: UNKNOWN-ATTRIBUTES](https://tools.ietf.org/html/rfc5389#section-15.9)
    ///
    /// The UNKNOWN-ATTRIBUTES attribute is present only in an error response
    /// when the response code in the ERROR-CODE attribute is 420.
    ///
    /// The attribute contains a list of 16-bit values, each of which
    /// represents an attribute type that was not understood by the server.
    UnknownAttributes {
        /// List of 16-bit values, each of which represents an attribute type that was not understood by the server.
        types: Vec<u16>,
    },
    /// [RFC5389: SOFTWARE](https://tools.ietf.org/html/rfc5389#section-15.10)
    /// The SOFTWARE attribute contains a textual description of the software
    /// being used by the agent sending the message.  It is used by clients
    /// and servers.  Its value SHOULD include manufacturer and version
    /// number.  The attribute has no impact on operation of the protocol,
    /// and serves only as a tool for diagnostic and debugging purposes.  The
    /// value of SOFTWARE is variable length.  It MUST be a UTF-8 [RFC3629](https://tools.ietf.org/html/rfc3629)
    /// encoded sequence of less than 128 characters (which can be as long as
    /// 763 bytes).
    Software {
        /// Textual description of the software being used by the agent sending the message.
        description: String,
    },
    /// [RFC5389: ALTERNATE-SERVER](https://tools.ietf.org/html/rfc5389#section-15.11)
    ///
    /// The alternate server represents an alternate transport address
    /// identifying a different STUN server that the STUN client should try.
    ///
    /// It is encoded in the same way as MAPPED-ADDRESS, and thus refers to a
    /// single server by IP address.  The IP address family MUST be identical
    /// to that of the source IP address of the request.
    AlternateServer {
        /// Alternate transport address identifying a different STUN server that the STUN client should try.
        socket_addr: SocketAddr,
    },
    /// [RFC8445: PRIORITY](https://tools.ietf.org/html/rfc8445#section-7.1.1)
    ///
    ///    The PRIORITY attribute MUST be included in a Binding request and be
    /// set to the value computed by the algorithm in [Section 5.1.2](https://tools.ietf.org/html/rfc8445#section-5.1.2) for the
    /// local candidate, but with the candidate type preference of peer-
    /// reflexive candidates.
    Priority {
        /// Value computed by the algorithm in [Section 5.1.2 of RFC8445](https://tools.ietf.org/html/rfc8445#section-5.1.2) for the local candidate, but with the candidate type preference of peer-reflexive candidates.
        value: u32,
    },
    /// [RFC8445: USE-CANDIDATE](https://tools.ietf.org/html/rfc8445#section-7.1.2)
    ///
    /// The controlling agent MUST include the USE-CANDIDATE attribute in
    /// order to nominate a candidate pair ([Section 8.1.1](https://tools.ietf.org/html/rfc8445#section-8.1.1)).  The controlled
    /// agent MUST NOT include the USE-CANDIDATE attribute in a Binding
    /// request.
    UseCandidate,
    /// [RFC8445: ICE-CONTROLLED](https://tools.ietf.org/html/rfc8445#section-7.1.3)
    ///
    /// The controlled agent MUST include the ICE-CONTROLLED attribute in a Binding request.
    ///
    /// The content of either attribute is used as tiebreaker values when an
    /// ICE role conflict occurs ([Section 7.3.1.1](https://tools.ietf.org/html/rfc8445#section-7.3.1.1)).
    IceControlled {
        /// Tiebreaker value used for ICE role conflict resolution defined in [Section 7.3.1.1 of RFC8445](https://tools.ietf.org/html/rfc8445#section-7.3.1.1)
        tie_breaker: u64,
    },
    /// [RFC8445: ICE-CONTROLLING](https://tools.ietf.org/html/rfc8445#section-7.1.3)
    ///
    /// The controlling agent MUST include the ICE-CONTROLLING attribute in a
    /// Binding request.
    ///
    /// The content of either attribute is used as tiebreaker values when an
    /// ICE role conflict occurs ([Section 7.3.1.1](https://tools.ietf.org/html/rfc8445#section-7.3.1.1)).
    IceControlling {
        /// Tiebreaker value used for ICE role conflict resolution defined in [Section 7.3.1.1 of RFC8445](https://tools.ietf.org/html/rfc8445#section-7.3.1.1)
        tie_breaker: u64,
    },
}
