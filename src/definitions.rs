pub const STUN_MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];
pub const STUN_MAGIC_COOKIE_U32: u32 = 0x2112a442;
pub const STUN_FINGERPRINT_ATTR_SIZE: usize = 8;
pub const STUN_INTEGRITY_ATTR_SIZE: usize = 24;
pub const STUN_HEADER_SIZE: usize = 20;
pub const STUN_TRANSACTION_ID_SIZE: usize = 12;
pub type StunTransactionId = [u8; STUN_TRANSACTION_ID_SIZE];
