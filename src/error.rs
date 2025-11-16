//! Error types for SOME/IP packet parsing and serialization.

use core::fmt;

/// Errors that can occur during SOME/IP packet parsing or serialization.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Error {
    /// The packet buffer is too short to contain a valid SOME/IP header.
    ///
    /// SOME/IP headers are 16 bytes minimum.
    BufferTooShort,

    /// The packet buffer is truncated and doesn't contain the full payload.
    ///
    /// The length field indicates more payload bytes than are available in the buffer.
    Truncated,

    /// The message type byte is not a valid SOME/IP message type.
    ///
    /// Valid values are defined in the SOME/IP specification.
    InvalidMessageType(u8),

    /// The return code byte is not a valid SOME/IP return code.
    ///
    /// Valid values are defined in the SOME/IP specification.
    InvalidReturnCode(u8),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BufferTooShort => {
                write!(f, "buffer too short for SOME/IP header (minimum 16 bytes)")
            }
            Error::Truncated => {
                write!(f, "packet truncated: buffer shorter than length field indicates")
            }
            Error::InvalidMessageType(byte) => {
                write!(f, "invalid message type: 0x{:02X}", byte)
            }
            Error::InvalidReturnCode(byte) => {
                write!(f, "invalid return code: 0x{:02X}", byte)
            }
        }
    }
}
