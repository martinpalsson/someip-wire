//! Packet module
//!
//! This module contains the `Packet` type, which is a read/write wrapper around a Some/IP packet buffer.

use crate::error::Error;
use crate::field;
use crate::types::{MessageId, RequestId};
use byteorder::{ByteOrder, NetworkEndian};
use core::fmt;

#[allow(dead_code)]
pub type Result<T> = core::result::Result<T, Error>;

/// A read/write wrapper around a Some/IP packet buffer.
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T,
}

#[allow(dead_code)]
impl<T: AsRef<[u8]>> Packet<T> {
    /// Creates a new unchecked `Packet`.
    ///
    /// # Arguments
    ///
    /// * `buffer` - A buffer containing the packet data.
    ///
    /// # Returns
    ///
    /// * `Packet` - A new `Packet` instance.
    pub const fn new_unchecked(buffer: T) -> Packet<T> {
        Packet { buffer }
    }

    /// Creates a new checked `Packet`.
    ///
    /// # Arguments
    ///
    /// * `buffer` - A buffer containing the packet data.
    ///
    /// # Returns
    ///
    /// * `Result<Packet>` - A new `Packet` instance if the buffer is valid.
    pub fn new_checked(buffer: T) -> Result<Packet<T>> {
        let packet = Self::new_unchecked(buffer);
        match packet.check_len() {
            Ok(_) => Ok(packet),
            Err(_) => Err(Error),
        }
    }

    /// Checks the length of the packet.
    ///
    /// # Returns
    ///
    /// * `Result<()>` - Ok if the length is valid, otherwise an error.
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < field::header::LENGTH {
            Err(Error)
        } else {
            Ok(())
        }
    }

    /// Returns the inner buffer.
    ///
    /// # Returns
    ///
    /// * `T` - The inner buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Returns a reference to the inner buffer.
    ///
    /// # Returns
    ///
    /// * `&[u8]` - A reference to the buffer.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        self.buffer.as_ref()
    }

    /// Returns the Message ID
    ///
    /// # Returns
    ///
    /// * `MessageId` - The Message ID of the packet
    pub fn message_id(&self) -> MessageId {
        let raw_id = NetworkEndian::read_u32(&self.buffer.as_ref()[field::header::MESSAGE_ID]);
        MessageId::from_u32(raw_id)
    }

    /// Returns the Payload Length
    ///
    /// # Returns
    ///
    /// * `usize` - The Payload Length of the packet
    pub fn payload_length(&self) -> usize {
        NetworkEndian::read_u32(&self.buffer.as_ref()[field::header::PAYLOAD_LENGTH]) as usize
    }

    /// Returns the Request ID
    ///
    /// # Returns
    ///
    /// * `u32` - The Request ID of the packet
    pub fn request_id(&self) -> RequestId {
        RequestId::from_u32(NetworkEndian::read_u32(
            &self.buffer.as_ref()[field::header::REQUEST_ID],
        ))
    }

    /// Returns the Protocol Version
    ///
    /// # Returns
    ///
    /// * `u8` - The Protocol Version of the packet
    pub fn protocol_version(&self) -> u8 {
        self.buffer.as_ref()[field::header::PROTOCOL_VERSION.start]
    }

    /// Returns the Interface Version
    ///
    /// # Returns
    ///
    /// * `u8` - The Interface Version of the packet
    pub fn interface_version(&self) -> u8 {
        self.buffer.as_ref()[field::header::INTERFACE_VERSION.start]
    }

    /// Returns the Message Type (raw u8)
    ///
    /// # Returns
    ///
    /// * `u8` - The raw message type byte from the packet
    pub fn message_type(&self) -> u8 {
        self.buffer.as_ref()[field::header::MESSAGE_TYPE.start]
    }

    /// Returns the Return Code (raw u8)
    ///
    /// # Returns
    ///
    /// * `u8` - The raw return code byte from the packet
    pub fn return_code(&self) -> u8 {
        self.buffer.as_ref()[field::header::RETURN_CODE.start]
    }

    /// Returns the range of the payload data
    ///
    /// # Returns
    ///
    /// * `Range<usize>` - The range of the payload data.
    pub fn payload_data_range(&self) -> core::ops::Range<usize> {
        field::header::RETURN_CODE.end
            ..field::header::RETURN_CODE.end + self.payload_length() as usize
    }

    /// Returns the length of the payload data.
    ///
    /// # Returns
    ///
    /// * `usize` - The length of the payload data.
    pub fn payload_data_length(&self) -> usize {
        self.payload_length() as usize
    }
}

#[allow(dead_code)]
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Sets the Message ID
    ///
    /// # Arguments
    ///
    /// * `message_id` - The new Message ID to set
    pub fn set_message_id(&mut self, message_id: MessageId) {
        let raw_id = message_id.to_u32();
        NetworkEndian::write_u32(&mut self.buffer.as_mut()[field::header::MESSAGE_ID], raw_id);
    }

    /// Sets the Payload Length
    ///
    /// # Arguments
    ///
    /// * `length` - The new Payload Length to set
    pub fn set_payload_length(&mut self, length: u32) {
        NetworkEndian::write_u32(
            &mut self.buffer.as_mut()[field::header::PAYLOAD_LENGTH],
            length,
        );
    }

    /// Sets the Request ID
    ///
    /// # Arguments
    ///
    /// * `request_id` - The new Request ID to set
    pub fn set_request_id(&mut self, request_id: RequestId) {
        let raw_id = request_id.to_u32();
        NetworkEndian::write_u32(&mut self.buffer.as_mut()[field::header::REQUEST_ID], raw_id);
    }

    /// Sets the Protocol Version
    ///
    /// # Arguments
    ///
    /// * `version` - The new Protocol Version to set
    pub fn set_protocol_version(&mut self, version: u8) {
        self.buffer.as_mut()[field::header::PROTOCOL_VERSION.start] = version;
    }

    /// Sets the Interface Version
    ///
    /// # Arguments
    ///
    /// * `version` - The new Interface Version to set
    pub fn set_interface_version(&mut self, version: u8) {
        self.buffer.as_mut()[field::header::INTERFACE_VERSION.start] = version;
    }

    /// Sets the Message Type (raw u8)
    ///
    /// # Arguments
    ///
    /// * `message_type` - The new message type byte to set
    pub fn set_message_type(&mut self, message_type: u8) {
        self.buffer.as_mut()[field::header::MESSAGE_TYPE.start] = message_type;
    }

    /// Sets the Return Code (raw u8)
    ///
    /// # Arguments
    ///
    /// * `return_code` - The new return code byte to set
    pub fn set_return_code(&mut self, return_code: u8) {
        self.buffer.as_mut()[field::header::RETURN_CODE.start] = return_code;
    }
}

#[allow(dead_code)]
impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    /// Returns a reference to the payload data,
    ///
    /// # Returns
    ///
    /// * `&'a [u8]` - A reference to the payload data.
    #[inline]
    pub fn payload_data(&self) -> &'a [u8] {
        let payload_range = self.payload_data_range();
        &self.buffer.as_ref()[payload_range]
    }

    /// Returns a reference to the entire message.
    ///
    /// # Returns
    ///
    /// * `&'a [u8]` - A reference to the entire message.
    #[inline]
    pub fn entire_message(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[..field::header::PAYLOAD_LENGTH.end + self.payload_length()]
    }
}

#[allow(dead_code)]
impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> Packet<&'a mut T> {
    /// Returns a mutable reference to the payload data,
    ///
    /// # Returns
    ///
    /// * `&'a mut [u8]` - A mutable reference to the payload data.
    #[inline]
    pub fn payload_data_mut(&mut self) -> &mut [u8] {
        let payload_range = self.payload_data_range();
        &mut self.buffer.as_mut()[payload_range]
    }

    /// Returns a mutable reference to the entire message.
    ///
    /// # Returns
    ///
    /// * `&'a mut [u8]` - A mutable reference to the entire message.
    #[inline]
    pub fn entire_message_mut(&mut self) -> &mut [u8] {
        let payload_length = self.payload_length();
        let data = self.buffer.as_mut();
        &mut data[..field::header::PAYLOAD_LENGTH.end + payload_length]
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> fmt::Display for Packet<&'a T> {
    /// Formats the packet as a string
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter
    ///
    /// # Returns
    ///
    /// * `fmt::Result` - The result of the formatting
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Some/IP Packet: message_id={}, length={}, request_id={}, protocol_version={}, interface_version={}, message_type=0x{:02X}, return_code=0x{:02X}",
            self.message_id(),
            self.payload_length(),
            self.request_id(),
            self.protocol_version(),
            self.interface_version(),
            self.message_type(),
            self.return_code()
        )?;

        Ok(())
    }
}
