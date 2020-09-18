use crate::definitions::StunTransactionId;
use crate::header::StunHeader;
use rand::Rng;
use std::io::Cursor;

/// Checks for a STUN message header
///
/// This function is intended to be used with multiplexed streams in order to separate STUN packets from other protocols
///
/// Arguments:
/// * `data_bytes`: Streaming data bytes that need to be checked. Note that only the first 20 bytes are processed.
pub fn check_for_stun_message_header(data_bytes: &[u8]) -> Option<StunHeader> {
    StunHeader::decode(&mut Cursor::new(data_bytes)).ok()
}

/// Generates a random Transaction Id to be used in a StunMessage
///
/// The [Transaction Id is a randomly selected 96-bit number](https://tools.ietf.org/html/rfc5389#section-3) represented here by StunTransactionId
pub fn generate_transaction_id() -> StunTransactionId {
    let mut rng = rand::thread_rng();
    let buf: StunTransactionId = rng.gen();

    buf
}
