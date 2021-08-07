use byteorder::{ByteOrder, NetworkEndian, WriteBytesExt};
use std::io::{Cursor, Write};
use std::net::SocketAddr;

use super::errors::AttributeEncodeError;
use super::types::StunAttributeType;
use super::utils::xor_byte_range;
use super::StunAttribute;

use crate::definitions::{StunTransactionId, STUN_MAGIC_COOKIE};

impl StunAttribute {
    // Wraps the encoded attribute data into TLV
    fn wrap_in_tlv(
        attr_type: StunAttributeType,
        attr_bytes: &[u8],
    ) -> Result<Vec<u8>, AttributeEncodeError> {
        let mut cursor = Cursor::new(Vec::new());

        let data_len = attr_bytes.len();

        // Write the attribute type
        cursor.write_u16::<NetworkEndian>(attr_type as u16)?;
        // Write the attribute data length
        cursor.write_u16::<NetworkEndian>(data_len as u16)?;
        // Write attribute data
        cursor.write_all(attr_bytes)?;

        // Calculate and add attribute padding
        // NOTE: As per [RFC5389 Section 15](https://tools.ietf.org/html/rfc5389#section-15) padding bytes may take any value.
        // In this implementation NULL bytes are used
        let padding = 4 - data_len % 4;
        if padding != 4 {
            cursor.write_all(&vec![0u8; padding])?;
        }

        Ok(cursor.get_ref().to_vec())
    }

    // Encodes MappedAddress/XorMappedAddress/AlternateServer attributes.
    fn encode_address(
        addr: &SocketAddr,
        is_xored: bool,
        transaction_id: StunTransactionId,
    ) -> Result<Vec<u8>, AttributeEncodeError> {
        let family = match addr {
            SocketAddr::V4(_) => 0x01,
            SocketAddr::V6(_) => 0x02,
        };

        // Process the port number
        let port = addr.port();
        let mut port_bytes = [0u8, 2];
        NetworkEndian::write_u16(&mut port_bytes, port);
        // XOR the port number bytes if the attribute type is XorMappedAddress
        if is_xored {
            xor_byte_range(&mut port_bytes, &STUN_MAGIC_COOKIE);
        }

        let ip_addr_bytes = match addr {
            SocketAddr::V4(addr_v4) => {
                let mut ip_data = addr_v4.ip().octets();

                // XOR the ip address bytes if the attribute type is XorMappedAddress
                if is_xored {
                    xor_byte_range(&mut ip_data, &STUN_MAGIC_COOKIE)
                }

                ip_data.to_vec()
            }
            SocketAddr::V6(addr_v6) => {
                let segments = addr_v6.ip().segments();

                let mut ip_cursor = Cursor::new(Vec::new());
                for segment in segments.iter() {
                    ip_cursor.write_u16::<NetworkEndian>(*segment)?;
                }

                let ip_addr_bytes = ip_cursor.get_mut();

                // XOR the ip address bytes if the attribute type is XorMappedAddress
                if is_xored {
                    xor_byte_range(&mut ip_addr_bytes[0..4], &STUN_MAGIC_COOKIE);
                    xor_byte_range(&mut ip_addr_bytes[4..16], &transaction_id);
                }

                ip_addr_bytes.to_vec()
            }
        };

        let mut cursor = Cursor::new(Vec::new());

        // Write leading zeroes
        cursor.write_u8(0)?;
        // Write ip address family
        cursor.write_u8(family)?;
        // Write socket port number
        cursor.write_all(&port_bytes)?;
        // Write (XORed) ip address bytes
        cursor.write_all(&ip_addr_bytes)?;

        Ok(cursor.get_ref().to_vec())
    }

    // Encodes attributes containing Unicode values
    fn encode_utf8_val(data: &str, limit: Option<usize>) -> Result<Vec<u8>, AttributeEncodeError> {
        let encoded_val = data.as_bytes().to_vec();

        // Make sure we don't cross the size limit
        match limit {
            None => Ok(encoded_val),
            Some(size_limit) => {
                if encoded_val.len() > size_limit {
                    Err(AttributeEncodeError::Utf8ValueTooBig {
                        limit: size_limit,
                        length: encoded_val.len(),
                    })
                } else {
                    Ok(encoded_val)
                }
            }
        }
    }

    // Encodes attributes containing DWORD values.
    fn encode_u32_val(value: u32) -> Result<Vec<u8>, AttributeEncodeError> {
        let mut buf: Vec<u8> = vec![0u8; 4];
        NetworkEndian::write_u32(&mut buf, value);

        Ok(buf)
    }

    // Encodes attributes containing QWORD values.
    fn encode_u64_val(value: u64) -> Result<Vec<u8>, AttributeEncodeError> {
        let mut buf: Vec<u8> = vec![0u8; 8];
        NetworkEndian::write_u64(&mut buf, value);

        Ok(buf)
    }

    // Encodes the ErrorCode attribute.
    fn encode_error_code(
        class: u8,
        number: u8,
        reason: &str,
    ) -> Result<Vec<u8>, AttributeEncodeError> {
        let mut cursor = Cursor::new(Vec::new());
        // Write leading zeroes
        cursor.write_u16::<NetworkEndian>(0)?;
        // Write error class
        cursor.write_u8(class)?;
        // Write error number
        cursor.write_u8(number)?;
        // Write readable error reason
        cursor.write_all(&Self::encode_utf8_val(reason, Some(763))?)?;

        Ok(cursor.get_ref().to_vec())
    }

    // Encodes the UnknownAttributes attribute.
    fn encode_unknown_attributes(unknown_attrs: Vec<u16>) -> Result<Vec<u8>, AttributeEncodeError> {
        let mut cursor = Cursor::new(Vec::new());

        // Write each attribute type into the list
        for attr in unknown_attrs.iter() {
            cursor.write_u16::<NetworkEndian>(*attr)?;
        }

        Ok(cursor.get_ref().to_vec())
    }

    /// Encodes StunAttribute into bytes
    pub(crate) fn encode(
        &self,
        transaction_id: StunTransactionId,
    ) -> Result<Vec<u8>, AttributeEncodeError> {
        let (attr_type, encoded_attr) = match self {
            StunAttribute::XorMappedAddress { socket_addr } => (
                StunAttributeType::XorMappedAddress,
                Self::encode_address(socket_addr, true, transaction_id),
            ),
            StunAttribute::MappedAddress { socket_addr } => (
                StunAttributeType::MappedAddress,
                Self::encode_address(socket_addr, false, transaction_id),
            ),
            StunAttribute::Username { value } => (
                StunAttributeType::Username,
                Self::encode_utf8_val(value, Some(513)),
            ),
            StunAttribute::MessageIntegrity { key } => {
                (StunAttributeType::MessageIntegrity, Ok(key.clone()))
            }
            StunAttribute::Software { description } => (
                StunAttributeType::Software,
                Self::encode_utf8_val(description, Some(763)),
            ),
            StunAttribute::AlternateServer { socket_addr } => (
                StunAttributeType::AlternateServer,
                Self::encode_address(socket_addr, false, transaction_id),
            ),
            StunAttribute::Realm { value } => (
                StunAttributeType::Realm,
                Self::encode_utf8_val(value, Some(763)),
            ),
            StunAttribute::Nonce { value } => (
                StunAttributeType::Nonce,
                Self::encode_utf8_val(value, Some(763)),
            ),
            StunAttribute::Fingerprint { value } => {
                (StunAttributeType::Fingerprint, Self::encode_u32_val(*value))
            }
            StunAttribute::IceControlled { tie_breaker } => (
                StunAttributeType::IceControlled,
                Self::encode_u64_val(*tie_breaker),
            ),
            StunAttribute::IceControlling { tie_breaker } => (
                StunAttributeType::IceControlling,
                Self::encode_u64_val(*tie_breaker),
            ),
            StunAttribute::Priority { value } => {
                (StunAttributeType::Priority, Self::encode_u32_val(*value))
            }
            StunAttribute::ErrorCode {
                class,
                number,
                reason,
            } => (
                StunAttributeType::ErrorCode,
                Self::encode_error_code(*class, *number, reason),
            ),
            StunAttribute::UnknownAttributes { types } => (
                StunAttributeType::UnknownAttributes,
                Self::encode_unknown_attributes(types.clone()),
            ),
            StunAttribute::UseCandidate => (StunAttributeType::UseCandidate, Ok(Vec::new())),
        };

        // Wrap the encoded attribute data into TLV
        Self::wrap_in_tlv(attr_type, &encoded_attr?)
    }
}
