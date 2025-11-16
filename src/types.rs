use core::fmt::{self, Display};

/// Struct representation of MessageID
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct MessageId {
    /// Service ID (upper 16 bits of Message ID)
    pub service_id: u16,
    /// Method ID or Event ID (lower 16 bits of Message ID)
    pub method_id: u16,
}

impl MessageId {
    /// Parses a MessageId from a u32 value
    ///
    /// # Arguments
    ///
    /// * `value` - A u32 value representing the MessageId
    /// # Returns
    ///
    /// * `MessageId` - The parsed MessageId struct
    pub fn from_u32(value: u32) -> MessageId {
        MessageId {
            service_id: (value >> 16) as u16,
            method_id: (value & 0xFFFF) as u16,
        }
    }

    /// Converts the MessageId struct into a u32 value
    ///
    /// # Returns
    ///
    /// * `u32` - The u32 representation of the MessageId
    pub fn to_u32(&self) -> u32 {
        ((self.service_id as u32) << 16) | (self.method_id as u32)
    }
}

impl Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04X}.{:04X}", self.service_id, self.method_id)
    }
}

/// Struct representation of ClientID
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct ClientId {
    /// Client ID prefix (upper 8 bits)
    pub client_id_prefix: u8,
    /// Client ID (lower 8 bits)
    pub client_id: u8,
}

#[allow(dead_code)]
impl ClientId {
    /// Parses a ClientId from a u16 value
    ///
    /// # Arguments
    ///
    /// * `value` - A u16 value representing the ClientId
    /// # Returns
    ///
    /// * `ClientId` - The parsed ClientId struct
    pub fn from_u16(value: u16) -> ClientId {
        ClientId {
            client_id_prefix: ((value >> 8) & 0xFF) as u8,
            client_id: (value & 0xFF) as u8,
        }
    }

    /// Converts the ClientId struct into a u16 value
    ///
    /// # Returns
    ///
    /// * `u16` - The u16 representation of the ClientId
    pub fn to_u16(&self) -> u16 {
        ((self.client_id_prefix as u16) << 8) | (self.client_id as u16)
    }
}

impl Display for ClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02X}.{:02X}", self.client_id_prefix, self.client_id)
    }
}

/// Struct representation of RequestID
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct RequestId {
    /// Client ID (upper 16 bits of Request ID)
    pub client_id: ClientId,
    /// Session ID (lower 16 bits of Request ID)
    pub session_id: u16,
}

#[allow(dead_code)]
impl RequestId {
    /// Parses a RequestId from a u32 value
    ///
    /// # Arguments
    ///
    /// * `value` - A u32 value representing the RequestId
    /// # Returns
    ///
    /// * `RequestId` - The parsed RequestId struct
    pub fn from_u32(value: u32) -> RequestId {
        RequestId {
            client_id: ClientId::from_u16((value >> 16) as u16),
            session_id: (value & 0xFFFF) as u16,
        }
    }

    /// Converts the RequestId struct into a u32 value
    ///
    /// # Returns
    ///
    /// * `u32` - The u32 representation of the RequestId
    pub fn to_u32(&self) -> u32 {
        ((self.client_id.to_u16() as u32) << 16) | (self.session_id as u32)
    }
}

impl Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:04X}", self.client_id, self.session_id)
    }
}

/// Public representation of SOME/IP return codes
///
/// This enum provides a clean, ergonomic API for working with SOME/IP return codes.
/// Named variants represent well-known error codes, while data-carrying variants
/// handle reserved ranges.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
#[allow(non_camel_case_types)]
pub enum ReturnCode {
    /// No error occurred
    E_OK,
    /// An unspecified error occurred
    E_NOT_OK,
    /// The requested service is unknown
    E_UNKNOWN_SERVICE,
    /// The requested method is unknown
    E_UNKNOWN_METHOD,
    /// Service not ready
    E_NOT_READY,
    /// Service not reachable
    E_NOT_REACHABLE,
    /// Timeout occurred
    E_TIMEOUT,
    /// Wrong protocol version
    E_WRONG_PROTOCOL_VERSION,
    /// Wrong interface version
    E_WRONG_INTERFACE_VERSION,
    /// Malformed message
    E_MALFORMED_MESSAGE,
    /// Wrong message type
    E_WRONG_MESSAGE_TYPE,
    /// E2E repeated
    E_E2E_REPEATED,
    /// E2E wrong sequence
    E_E2E_WRONG_SEQUENCE,
    /// E2E error
    E_E2E,
    /// E2E not available
    E_E2E_NOT_AVAILABLE,
    /// E2E no new data
    E_E2E_NO_NEW_DATA,
    /// Reserved for generic SOME/IP errors (range 0x10-0x1F)
    ReservedSomeIP(u8),
    /// Reserved for service/method specific errors (range 0x20-0x5E)
    ReservedServiceMethod(u8),
}

impl ReturnCode {
    /// Create a ReturnCode from a raw u8 value
    ///
    /// Returns None if the value is outside valid SOME/IP ranges (> 0x5E).
    pub fn from_u8(value: u8) -> Option<Self> {
        if value > 0x5E {
            return None;
        }

        Some(match value {
            0x00 => ReturnCode::E_OK,
            0x01 => ReturnCode::E_NOT_OK,
            0x02 => ReturnCode::E_UNKNOWN_SERVICE,
            0x03 => ReturnCode::E_UNKNOWN_METHOD,
            0x04 => ReturnCode::E_NOT_READY,
            0x05 => ReturnCode::E_NOT_REACHABLE,
            0x06 => ReturnCode::E_TIMEOUT,
            0x07 => ReturnCode::E_WRONG_PROTOCOL_VERSION,
            0x08 => ReturnCode::E_WRONG_INTERFACE_VERSION,
            0x09 => ReturnCode::E_MALFORMED_MESSAGE,
            0x0A => ReturnCode::E_WRONG_MESSAGE_TYPE,
            0x0B => ReturnCode::E_E2E_REPEATED,
            0x0C => ReturnCode::E_E2E_WRONG_SEQUENCE,
            0x0D => ReturnCode::E_E2E,
            0x0E => ReturnCode::E_E2E_NOT_AVAILABLE,
            0x0F => ReturnCode::E_E2E_NO_NEW_DATA,
            0x10..=0x1F => ReturnCode::ReservedSomeIP(value),
            0x20..=0x5E => ReturnCode::ReservedServiceMethod(value),
            _ => unreachable!("value validated to be <= 0x5E"),
        })
    }

    /// Get the raw u8 value
    pub fn as_u8(&self) -> u8 {
        match self {
            ReturnCode::E_OK => 0x00,
            ReturnCode::E_NOT_OK => 0x01,
            ReturnCode::E_UNKNOWN_SERVICE => 0x02,
            ReturnCode::E_UNKNOWN_METHOD => 0x03,
            ReturnCode::E_NOT_READY => 0x04,
            ReturnCode::E_NOT_REACHABLE => 0x05,
            ReturnCode::E_TIMEOUT => 0x06,
            ReturnCode::E_WRONG_PROTOCOL_VERSION => 0x07,
            ReturnCode::E_WRONG_INTERFACE_VERSION => 0x08,
            ReturnCode::E_MALFORMED_MESSAGE => 0x09,
            ReturnCode::E_WRONG_MESSAGE_TYPE => 0x0A,
            ReturnCode::E_E2E_REPEATED => 0x0B,
            ReturnCode::E_E2E_WRONG_SEQUENCE => 0x0C,
            ReturnCode::E_E2E => 0x0D,
            ReturnCode::E_E2E_NOT_AVAILABLE => 0x0E,
            ReturnCode::E_E2E_NO_NEW_DATA => 0x0F,
            ReturnCode::ReservedSomeIP(v) => *v,
            ReturnCode::ReservedServiceMethod(v) => *v,
        }
    }

    /// Check if this is an OK status
    pub const fn is_ok(&self) -> bool {
        matches!(self, ReturnCode::E_OK)
    }

    /// Check if this is a reserved SOME/IP error (0x10-0x1F)
    pub const fn is_reserved_someip(&self) -> bool {
        matches!(self, ReturnCode::ReservedSomeIP(_))
    }

    /// Check if this is a service/method specific error (0x20-0x5E)
    pub const fn is_reserved_service_method(&self) -> bool {
        matches!(self, ReturnCode::ReservedServiceMethod(_))
    }
}

// Convenience: convert to u8
impl From<ReturnCode> for u8 {
    fn from(code: ReturnCode) -> Self {
        code.as_u8()
    }
}

impl Display for ReturnCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReturnCode::E_OK => write!(f, "E_OK"),
            ReturnCode::E_NOT_OK => write!(f, "E_NOT_OK"),
            ReturnCode::E_UNKNOWN_SERVICE => write!(f, "E_UNKNOWN_SERVICE"),
            ReturnCode::E_UNKNOWN_METHOD => write!(f, "E_UNKNOWN_METHOD"),
            ReturnCode::E_NOT_READY => write!(f, "E_NOT_READY"),
            ReturnCode::E_NOT_REACHABLE => write!(f, "E_NOT_REACHABLE"),
            ReturnCode::E_TIMEOUT => write!(f, "E_TIMEOUT"),
            ReturnCode::E_WRONG_PROTOCOL_VERSION => write!(f, "E_WRONG_PROTOCOL_VERSION"),
            ReturnCode::E_WRONG_INTERFACE_VERSION => write!(f, "E_WRONG_INTERFACE_VERSION"),
            ReturnCode::E_MALFORMED_MESSAGE => write!(f, "E_MALFORMED_MESSAGE"),
            ReturnCode::E_WRONG_MESSAGE_TYPE => write!(f, "E_WRONG_MESSAGE_TYPE"),
            ReturnCode::E_E2E_REPEATED => write!(f, "E_E2E_REPEATED"),
            ReturnCode::E_E2E_WRONG_SEQUENCE => write!(f, "E_E2E_WRONG_SEQUENCE"),
            ReturnCode::E_E2E => write!(f, "E_E2E"),
            ReturnCode::E_E2E_NOT_AVAILABLE => write!(f, "E_E2E_NOT_AVAILABLE"),
            ReturnCode::E_E2E_NO_NEW_DATA => write!(f, "E_E2E_NO_NEW_DATA"),
            ReturnCode::ReservedSomeIP(v) => write!(f, "Reserved SOME/IP Error (0x{:02X})", v),
            ReturnCode::ReservedServiceMethod(v) => {
                write!(f, "Reserved Service/Method Error (0x{:02X})", v)
            }
        }
    }
}

/// Message Type for SOME/IP protocol
///
/// This enum represents the different types of messages in SOME/IP.
/// It's a clean representation type with named variants for known message types.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum MessageType {
    /// A request expecting a response (even void)
    Request,
    /// A Fire&Forget request   
    RequestNoReturn,
    /// A request of a notification/event callback expecting no response     
    Notification,
    /// The response message
    Response,
    /// The response containing an error
    Error,
    /// A TP request expecting a response (even void)           
    TPRequest,
    /// A TP Fire&Forget request
    TPRequestNoReturn,
    /// A TP notification/event callback expecting no response
    TPNotification,
    /// The TP response message
    TPResponse,
    /// The TP response containing an error
    TPError,
}

impl MessageType {
    /// Convert from wire format (u8) to MessageType
    ///
    /// Returns None if the value doesn't correspond to a known message type
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(MessageType::Request),
            0x01 => Some(MessageType::RequestNoReturn),
            0x02 => Some(MessageType::Notification),
            0x03 => Some(MessageType::Response),
            0x04 => Some(MessageType::Error),
            0x20 => Some(MessageType::TPRequest),
            0x21 => Some(MessageType::TPRequestNoReturn),
            0x22 => Some(MessageType::TPNotification),
            0xA0 => Some(MessageType::TPResponse),
            0xA1 => Some(MessageType::TPError),
            _ => None,
        }
    }

    /// Convert to wire format (u8)
    pub fn as_u8(&self) -> u8 {
        match self {
            MessageType::Request => 0x00,
            MessageType::RequestNoReturn => 0x01,
            MessageType::Notification => 0x02,
            MessageType::Response => 0x03,
            MessageType::Error => 0x04,
            MessageType::TPRequest => 0x20,
            MessageType::TPRequestNoReturn => 0x21,
            MessageType::TPNotification => 0x22,
            MessageType::TPResponse => 0xA0,
            MessageType::TPError => 0xA1,
        }
    }

    /// Check if this is a request type (expects a response)
    pub const fn is_request(&self) -> bool {
        matches!(self, MessageType::Request | MessageType::TPRequest)
    }

    /// Check if this is a fire-and-forget request
    pub const fn is_request_no_return(&self) -> bool {
        matches!(
            self,
            MessageType::RequestNoReturn | MessageType::TPRequestNoReturn
        )
    }

    /// Check if this is a notification
    pub const fn is_notification(&self) -> bool {
        matches!(
            self,
            MessageType::Notification | MessageType::TPNotification
        )
    }

    /// Check if this is a response
    pub const fn is_response(&self) -> bool {
        matches!(self, MessageType::Response | MessageType::TPResponse)
    }

    /// Check if this is an error response
    pub const fn is_error(&self) -> bool {
        matches!(self, MessageType::Error | MessageType::TPError)
    }

    /// Check if this is a TP (TCP) message
    pub const fn is_tp(&self) -> bool {
        matches!(
            self,
            MessageType::TPRequest
                | MessageType::TPRequestNoReturn
                | MessageType::TPNotification
                | MessageType::TPResponse
                | MessageType::TPError
        )
    }
}

// Convenience: convert to u8
impl From<MessageType> for u8 {
    fn from(mt: MessageType) -> Self {
        mt.as_u8()
    }
}

impl Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MessageType::Request => write!(f, "Request"),
            MessageType::RequestNoReturn => write!(f, "Request No Return"),
            MessageType::Notification => write!(f, "Notification"),
            MessageType::Response => write!(f, "Response"),
            MessageType::Error => write!(f, "Error"),
            MessageType::TPRequest => write!(f, "TP Request"),
            MessageType::TPRequestNoReturn => write!(f, "TP Request No Return"),
            MessageType::TPNotification => write!(f, "TP Notification"),
            MessageType::TPResponse => write!(f, "TP Response"),
            MessageType::TPError => write!(f, "TP Error"),
        }
    }
}
