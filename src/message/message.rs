pub use super::errors::{IntegrityKeyGenerationError, MessageDecodeError, MessageEncodeError};

use crate::attribute::StunAttribute;
use crate::header::StunHeader;

/// STUN message [RFC5389](https://tools.ietf.org/html/rfc5389#section-6)
///
///   STUN messages are encoded in binary using network-oriented format
///   (most significant byte or octet first, also commonly known as big-
///   endian).  The transmission order is described in detail in Appendix B
///   of [RFC0791](https://tools.ietf.org/html/rfc791). Unless otherwise noted, numeric constants are
///   in decimal (base 10).
///
///   All STUN messages MUST start with a 20-byte header followed by zero
///   or more Attributes.  The STUN header contains a STUN message type,
///   magic cookie, transaction ID, and message length.
///```text
///        0                   1                   2                   3
///        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///       |0 0|     STUN Message Type     |         Message Length        |
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///       |                         Magic Cookie                          |
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///       |                                                               |
///       |                     Transaction ID (96 bits)                  |
///       |                                                               |
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
///                   Figure 2: Format of STUN Message Header
///```
///   The most significant 2 bits of every STUN message MUST be zeroes.
///   This can be used to differentiate STUN packets from other protocols
///   when STUN is multiplexed with other protocols on the same port.
///
///   The message type defines the message class (request, success
///   response, failure response, or indication) and the message method
///   (the primary function) of the STUN message.  Although there are four
///   message classes, there are only two types of transactions in STUN:
///   request/response transactions (which consist of a request message and
///   a response message) and indication transactions (which consist of a
///   single indication message).  Response classes are split into error
///   and success responses to aid in quickly processing the STUN message.
///
///   The message type field is decomposed further into the following
///   structure:
///```text
///                        0                 1
///                        2  3  4 5 6 7 8 9 0 1 2 3 4 5
///
///                       +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
///                       |M |M |M|M|M|C|M|M|M|C|M|M|M|M|
///                       |11|10|9|8|7|1|6|5|4|0|3|2|1|0|
///                       +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
///
///                Figure 3: Format of STUN Message Type Field
///```
///   Here the bits in the message type field are shown as most significant
///   (M11) through least significant (M0).  M11 through M0 represent a 12-
///   bit encoding of the method.  C1 and C0 represent a 2-bit encoding of
///   the class.  A class of 0b00 is a request, a class of 0b01 is an
///   indication, a class of 0b10 is a success response, and a class of
///   0b11 is an error response.  This specification defines a single
///   method, Binding.  The method and class are orthogonal, so that for
///   each method, a request, success response, error response, and
///   indication are possible for that method.  Extensions defining new
///   methods MUST indicate which classes are permitted for that method.
///
///   For example, a Binding request has class=0b00 (request) and
///   method=0b000000000001 (Binding) and is encoded into the first 16 bits
///   as 0x0001.  A Binding response has class=0b10 (success response) and
///   method=0b000000000001, and is encoded into the first 16 bits as
///   0x0101.
///```text
///      Note: This unfortunate encoding is due to assignment of values in
///      [RFC3489](https://tools.ietf.org/html/rfc3489) that did not consider encoding Indications, Success, and
///      Errors using bit fields.
///```
///   The magic cookie field MUST contain the fixed value 0x2112A442 in
///   network byte order.  In [RFC3489](https://tools.ietf.org/html/rfc3489), this field was part of
///   the transaction ID; placing the magic cookie in this location allows
///   a server to detect if the client will understand certain attributes
///   that were added in this revised specification.  In addition, it aids
///   in distinguishing STUN packets from packets of other protocols when
///   STUN is multiplexed with those other protocols on the same port.
///
///   The transaction ID is a 96-bit identifier, used to uniquely identify
///   STUN transactions.  For request/response transactions, the
///   transaction ID is chosen by the STUN client for the request and
///   echoed by the server in the response.  For indications, it is chosen
///   by the agent sending the indication.  It primarily serves to
///   correlate requests with responses, though it also plays a small role
///
///   in helping to prevent certain types of attacks.  The server also uses
///   the transaction ID as a key to identify each transaction uniquely
///   across all clients.  As such, the transaction ID MUST be uniformly
///   and randomly chosen from the interval 0 .. 2**96-1, and SHOULD be
///   cryptographically random.  Resends of the same request reuse the same
///   transaction ID, but the client MUST choose a new transaction ID for
///   new transactions unless the new request is bit-wise identical to the
///   previous request and sent from the same transport address to the same
///   IP address.  Success and error responses MUST carry the same
///   transaction ID as their corresponding request.  When an agent is
///   acting as a STUN server and STUN client on the same port, the
///   transaction IDs in requests sent by the agent have no relationship to
///   the transaction IDs in requests received by the agent.
///
///   The message length MUST contain the size, in bytes, of the message
///   not including the 20-byte STUN header.  Since all STUN attributes are
///   padded to a multiple of 4 bytes, the last 2 bits of this field are
///   always zero.  This provides another way to distinguish STUN packets
///   from packets of other protocols.
///
///   Following the STUN fixed portion of the header are zero or more
///   attributes.  Each attribute is TLV (Type-Length-Value) encoded.  The
///   details of the encoding, and of the attributes themselves are given
///   in [Section 15](https://tools.ietf.org/html/rfc5389#section-15).

#[derive(Debug, Clone)]
pub struct StunMessage {
    /// STUN message header
    pub(super) header: StunHeader,
    /// STUN message attributes
    pub(super) attributes: Vec<StunAttribute>,
}
