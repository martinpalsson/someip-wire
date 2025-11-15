#![allow(non_snake_case)]

#![allow(dead_code)]

pub type Field = ::core::ops::Range<usize>;
pub mod header {
    use crate::field::Field;

    pub const MESSAGE_ID: Field = 0..4;
    pub const PAYLOAD_LENGTH: Field = 4..8;
    pub const REQUEST_ID: Field = 8..12;
    pub const PROTOCOL_VERSION: Field = 12..13;
    pub const INTERFACE_VERSION: Field = 13..14;
    pub const MESSAGE_TYPE: Field = 14..15;
    pub const RETURN_CODE: Field = 15..16;

    /// Get the payload field range given the length of the payload
    pub const fn PAYLOAD(length: usize) -> Field {
        RETURN_CODE.end..(RETURN_CODE.end + length)
    }

    // Length of Some/IP header excluding payload
    pub const LENGTH: usize = RETURN_CODE.end;
}
