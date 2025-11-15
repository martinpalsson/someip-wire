use crate::{error::*, field, packet::*, types::*};
use core::fmt;

/// A high-level representation of a Some/IP message.
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Repr<'a> {
    /// Message ID (32 bits)
    pub message_id: MessageId,
    /// Length field (32 bits)
    pub length: u32,
    /// Request ID (32 bits)
    pub request_id: RequestId,
    /// Protocol version (8 bits)
    pub protocol_version: u8,
    /// Interface version (8 bits)
    pub interface_version: u8,
    /// Message type (8 bits)
    pub message_type: MessageType,
    /// Return code (8 bits)
    pub return_code: crate::types::ReturnCode,
    /// Payload data (variable length)
    pub data: &'a [u8],
}

#[allow(dead_code)]
impl<'a> Repr<'a> {
    pub fn parse<T>(packet: &'a Packet<T>) -> core::result::Result<Repr<'a>, Error>
    where
        T: AsRef<[u8]>,
    {
        let buffer = packet.as_slice();

        if buffer.len() < field::header::HEADER_LENGTH {
            return Err(Error);
        }

        let message_id = MessageId::from_u32(u32::from_be_bytes(
            buffer[field::header::MESSAGE_ID].try_into().unwrap(),
        ));
        let length = u32::from_be_bytes(buffer[field::header::LENGTH].try_into().unwrap());
        let request_id = RequestId::from_u32(u32::from_be_bytes(
            buffer[field::header::REQUEST_ID].try_into().unwrap(),
        ));
        let protocol_version = buffer[field::header::PROTOCOL_VERSION.start];
        let interface_version = buffer[field::header::INTERFACE_VERSION.start];
        let message_type_byte = buffer[field::header::MESSAGE_TYPE.start];
        let message_type = MessageType::from_u8(message_type_byte).ok_or(Error)?;
        let return_code_byte = buffer[field::header::RETURN_CODE.start];
        let return_code = crate::types::ReturnCode::from_u8(return_code_byte).ok_or(Error)?;

        // Length includes Request ID (4) + Protocol Version (1) + Interface Version (1) 
        // + Message Type (1) + Return Code (1) + Payload = 8 bytes + payload
        let payload_start = field::header::RETURN_CODE.end;
        let payload_length = length.saturating_sub(8); // Subtract the 8 header bytes after Message ID
        let payload_end = payload_start + (payload_length as usize);
        if buffer.len() < payload_end {
            return Err(Error);
        }
        let data = &buffer[payload_start..payload_end];

        Ok(Repr {
            message_id,
            length,
            request_id,
            protocol_version,
            interface_version,
            message_type,
            return_code,
            data,
        })
    }

    /// Emits the high-level representation of the Some/IP packet into the provided packet/buffer.
    ///
    /// # Arguments
    ///
    /// * `packet` - A mutable reference to the packet where the high-level representation will be written.
    pub fn emit<T>(&self, packet: &mut Packet<&mut T>)
    where
        T: AsRef<[u8]> + AsMut<[u8]> + ?Sized,
    {
        packet.set_message_id(self.message_id);
        packet.set_payload_length(self.length);
        packet.set_request_id(self.request_id);
        packet.set_protocol_version(self.protocol_version);
        packet.set_interface_version(self.interface_version);
        packet.set_message_type(self.message_type.as_u8());
        packet.set_return_code(self.return_code.as_u8());

        // Copy payload data
        let payload_mut = packet.payload_data_mut();
        payload_mut[..self.data.len()].copy_from_slice(self.data);
    }
}

impl<'a> fmt::Display for Repr<'a> {
    /// Formats the high-level representation as a string.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "SOME/IP Payload: message_id={}, length={}, request_id={}, protocol_version={}, interface_version={}, message_type={}, return_code={}, data_len={}",
            self.message_id,
            self.length,
            self.request_id,
            self.protocol_version,
            self.interface_version,
            self.message_type,
            self.return_code,
            self.data.len()
        )
    }
}
