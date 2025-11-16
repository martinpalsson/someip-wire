#![allow(non_snake_case)]

#![allow(dead_code)]

/// A byte range within a SOME/IP packet.
pub type Field = ::core::ops::Range<usize>;

/// SOME/IP header field definitions.
///
/// This module contains constants defining the byte ranges for each field
/// in the SOME/IP header.
pub mod header {
    use crate::field::Field;

    /// Message ID field (bytes 0-3): Service ID + Method ID
    pub const MESSAGE_ID: Field = 0..4;
    /// Length field (bytes 4-7): Length of payload + 8 bytes
    pub const LENGTH: Field = 4..8;
    /// Request ID field (bytes 8-11): Client ID + Session ID
    pub const REQUEST_ID: Field = 8..12;
    /// Protocol Version field (byte 12): SOME/IP protocol version
    pub const PROTOCOL_VERSION: Field = 12..13;
    /// Interface Version field (byte 13): Service interface version
    pub const INTERFACE_VERSION: Field = 13..14;
    /// Message Type field (byte 14): Request, Response, Notification, etc.
    pub const MESSAGE_TYPE: Field = 14..15;
    /// Return Code field (byte 15): E_OK, E_NOT_OK, etc.
    pub const RETURN_CODE: Field = 15..16;

    /// Get the payload field range given the length of the payload data
    pub const fn payload(length: usize) -> Field {
        RETURN_CODE.end..(RETURN_CODE.end + length)
    }

    /// Length of the SOME/IP header (16 bytes, excluding payload)
    pub const HEADER_LENGTH: usize = RETURN_CODE.end;
}
