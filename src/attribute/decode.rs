use byteorder::{ByteOrder, NetworkEndian, ReadBytesExt};
use num_traits::FromPrimitive;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::errors::AttributeDecodeError;
use super::types::StunAttributeType;
use super::utils::xor_byte_range;
use super::StunAttribute;

use crate::definitions::{StunTransactionId, STUN_MAGIC_COOKIE};

impl StunAttribute {
    #[allow(clippy::many_single_char_names)]
    // Decodes MappedAddress/XorMappedAddress/AlternateServer attributes.
    fn decode_address(
        bytes: &[u8],
        is_xored: bool,
        transaction_id: StunTransactionId,
    ) -> Result<SocketAddr, AttributeDecodeError> {
        // Separate IP address family
        let ip_family = (&bytes[1..2]).read_u8()?;

        if bytes.len() < 8 {
            return Err(AttributeDecodeError::InsufficientData());
        }

        let mut port_bytes = bytes[2..4].to_vec();
        let mut addr_bytes = bytes[4..].to_vec();

        // XOR the port number bytes if the attribute type is XorMappedAddress
        if is_xored {
            xor_byte_range(&mut port_bytes, &STUN_MAGIC_COOKIE);
        }

        // Read port number
        let port = NetworkEndian::read_u16(&port_bytes);

        let address = match ip_family {
            0x01 => {
                if addr_bytes.len() < 4 {
                    return Err(AttributeDecodeError::InsufficientData());
                }

                // XOR the ip address bytes if the attribute type is XorMappedAddress
                if is_xored {
                    xor_byte_range(&mut addr_bytes, &STUN_MAGIC_COOKIE);
                }

                let mut cursor = Cursor::new(addr_bytes);

                let a = cursor.read_u8()?;
                let b = cursor.read_u8()?;
                let c = cursor.read_u8()?;
                let d = cursor.read_u8()?;

                Ok(IpAddr::V4(Ipv4Addr::new(a, b, c, d)))
            }
            0x02 => {
                if addr_bytes.len() < 16 {
                    return Err(AttributeDecodeError::InsufficientData());
                }

                // XOR the ip address bytes if the attribute type is XorMappedAddress
                if is_xored {
                    xor_byte_range(&mut addr_bytes[0..4], &STUN_MAGIC_COOKIE);
                    xor_byte_range(&mut addr_bytes[4..16], &transaction_id);
                }

                let mut cursor = Cursor::new(addr_bytes);

                let a = cursor.read_u16::<NetworkEndian>()?;
                let b = cursor.read_u16::<NetworkEndian>()?;
                let c = cursor.read_u16::<NetworkEndian>()?;
                let d = cursor.read_u16::<NetworkEndian>()?;
                let e = cursor.read_u16::<NetworkEndian>()?;
                let f = cursor.read_u16::<NetworkEndian>()?;
                let g = cursor.read_u16::<NetworkEndian>()?;
                let h = cursor.read_u16::<NetworkEndian>()?;

                Ok(IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h)))
            }
            _ => Err(AttributeDecodeError::InvalidValue(ip_family as u128)),
        };

        Ok(SocketAddr::new(address?, port))
    }

    // Decodes attributes containing Unicode values
    fn decode_utf8_val(bytes: &[u8]) -> Result<String, AttributeDecodeError> {
        Ok(String::from_utf8(bytes.to_vec())?)
    }

    // Decodes attributes containing DWORD values.
    fn decode_u32_val(bytes: &[u8]) -> Result<u32, AttributeDecodeError> {
        // Prevent NetworkEndian::read_u32 from panicking if we don't have enough data to read from.
        if bytes.len() < 4 {
            return Err(AttributeDecodeError::InsufficientData());
        }

        Ok(NetworkEndian::read_u32(bytes))
    }

    // Decodes attributes containing QWORD values.
    fn decode_u64_val(bytes: &[u8]) -> Result<u64, AttributeDecodeError> {
        // Prevent NetworkEndian::read_u64 from panicking if we don't have enough data to read from.
        if bytes.len() < 8 {
            return Err(AttributeDecodeError::InsufficientData());
        }

        Ok(NetworkEndian::read_u64(bytes))
    }

    // Decodes the ErrorCode attribute.
    fn decode_error_code(bytes: &[u8]) -> Result<Self, AttributeDecodeError> {
        // Prevent NetworkEndian::read_u32 from panicking if we don't have enough data to read from.
        if bytes.len() < 4 {
            return Err(AttributeDecodeError::InsufficientData());
        }

        let class = bytes[2];
        let number = bytes[3];
        let reason = String::from_utf8(bytes[4..].to_vec())?;

        Ok(Self::ErrorCode {
            class,
            number,
            reason,
        })
    }

    // Decodes the UnknownAttributes attribute.
    fn decode_unknown_attributes(bytes: &[u8]) -> Result<Self, AttributeDecodeError> {
        let mut types = Vec::new();

        let mut cursor = Cursor::new(bytes);

        while cursor.position() < bytes.len() as u64 {
            types.push(cursor.read_u16::<NetworkEndian>()?);
        }

        Ok(Self::UnknownAttributes { types })
    }

    /// Decodes bytes passed via cursor into a STUN attribute.
    /// On each invocation only one attribute is decoded and the cursor position is advanced.
    pub(crate) fn decode(
        cursor: &mut Cursor<&[u8]>,
        transaction_id: StunTransactionId,
    ) -> Result<Self, AttributeDecodeError> {
        // Read attribute type
        let encoded_attr_type = cursor.read_u16::<NetworkEndian>()?;
        // Read attribute data length
        let attr_len = cursor.read_u16::<NetworkEndian>()?;

        // Read attribute data
        let mut attr_data = vec![0u8; attr_len as usize];
        cursor.read_exact(&mut attr_data)?;

        // Calculate the padding and advance the cursor
        let padding = 4 - attr_len % 4;
        if padding != 4 {
            cursor.seek(SeekFrom::Current(padding as i64))?;
        }

        let attr_type = FromPrimitive::from_u16(encoded_attr_type).ok_or(
            AttributeDecodeError::UnrecognizedAttributeType {
                attr_type: encoded_attr_type,
            },
        )?;

        // Decode and return the appropriate variant based on the attribute type.
        match attr_type {
            StunAttributeType::XorMappedAddress => {
                let socket_addr = Self::decode_address(&attr_data, true, transaction_id)?;

                Ok(Self::XorMappedAddress { socket_addr })
            }
            StunAttributeType::MappedAddress => {
                let socket_addr = Self::decode_address(&attr_data, false, transaction_id)?;

                Ok(Self::MappedAddress { socket_addr })
            }
            StunAttributeType::Username => {
                let raw_val = Self::decode_utf8_val(&attr_data)?;

                Ok(Self::Username { value: raw_val })
            }
            StunAttributeType::MessageIntegrity => Ok(Self::MessageIntegrity { key: attr_data }),
            StunAttributeType::Software => {
                let raw_val = Self::decode_utf8_val(&attr_data)?;

                Ok(Self::Software {
                    description: raw_val,
                })
            }
            StunAttributeType::AlternateServer => {
                let socket_addr = Self::decode_address(&attr_data, false, transaction_id)?;

                Ok(Self::AlternateServer { socket_addr })
            }
            StunAttributeType::Realm => {
                let raw_val = Self::decode_utf8_val(&attr_data)?;

                Ok(Self::Realm { value: raw_val })
            }
            StunAttributeType::Nonce => {
                let raw_val = Self::decode_utf8_val(&attr_data)?;

                Ok(Self::Nonce { value: raw_val })
            }
            StunAttributeType::Fingerprint => Ok(Self::Fingerprint {
                value: Self::decode_u32_val(&attr_data)?,
            }),
            StunAttributeType::IceControlled => {
                let raw_val = Self::decode_u64_val(&attr_data)?;

                Ok(Self::IceControlled {
                    tie_breaker: raw_val,
                })
            }
            StunAttributeType::IceControlling => {
                let raw_val = Self::decode_u64_val(&attr_data)?;

                Ok(Self::IceControlling {
                    tie_breaker: raw_val,
                })
            }
            StunAttributeType::Priority => {
                let raw_val = Self::decode_u32_val(&attr_data)?;

                Ok(Self::Priority { value: raw_val })
            }
            StunAttributeType::ErrorCode => Self::decode_error_code(&attr_data),
            StunAttributeType::UnknownAttributes => Self::decode_unknown_attributes(&attr_data),
            StunAttributeType::UseCandidate => Ok(Self::UseCandidate),
        }
    }
}
