//! # SOME/IP-wire
//!
//! This crate provides the means for parsing byte arrays into higher-level
//! SOME/IP representations, and vice versa. It is designed to be used in embedded
//! environments and is a `no_std` crate by default.
//!
//! ## Scope
//!
//! **This crate focuses solely on SOME/IP header parsing and serialization.**
//!
//! The crate parses the standardized 16-byte SOME/IP header and provides the payload
//! data as a raw byte slice. It does NOT parse the payload content itself, as payload
//! format is entirely application-specific and defined by service interface definitions
//! (e.g., FIDL/Franca IDL).
//!
//! To use this crate in a complete SOME/IP stack, you need to:
//! 1. Use this crate to parse/emit SOME/IP headers
//! 2. Implement your own payload parser/serializer based on your service definitions
//! 3. Connect service/method IDs to their respective payload handlers
//!
//! This separation keeps the crate focused, lightweight, and universally applicable
//! across different SOME/IP service implementations.
//!
//! ## Features
//!
//! - `no_std` compatible by default
//! - Zero-allocation parsing and serialization
//! - Support for all SOME/IP message types
//! - Clean enum-based API for return codes and message types
//! - Wire format using simple u8 for efficiency
//!
//! ## Examples
//!
//! ### Parsing a SOME/IP packet
//!
//! ```rust
//! use someip_wire::packet::Packet;
//! use someip_wire::repr::Repr;
//! use someip_wire::types::{MessageId, RequestId, MessageType, ReturnCode};
//!
//! // Example SOME/IP packet bytes (16-byte header + payload)
//! let buffer = [
//!     0x12, 0x34, 0x00, 0x01, // Message ID (service 0x1234, method 0x0001)
//!     0x00, 0x00, 0x00, 0x10, // Length
//!     0x00, 0x01, 0x00, 0x00, // Request ID (client 0x0001, session 0x0000)
//!     0x01,                   // Protocol version
//!     0x01,                   // Interface version
//!     0x00,                   // Message type (Request)
//!     0x00,                   // Return code (E_OK)
//!     // Payload data follows...
//!     0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
//! ];
//!
//! let packet = Packet::new_unchecked(&buffer);
//! let repr = Repr::parse(&packet).unwrap();
//!
//! assert_eq!(repr.message_type, MessageType::Request);
//! assert_eq!(repr.return_code, ReturnCode::E_OK);
//! assert_eq!(repr.protocol_version, 0x01);
//! assert_eq!(repr.data.len(), 8);
//! ```
//!
//! ### Creating and emitting a SOME/IP packet
//!
//! ```rust
//! use someip_wire::packet::Packet;
//! use someip_wire::repr::Repr;
//! use someip_wire::types::{MessageId, RequestId, ClientId, MessageType, ReturnCode};
//!
//! // Use Repr::new() to automatically calculate the length field
//! let repr = Repr::new(
//!     MessageId { service_id: 0x1234, method_id: 0x0001 },
//!     RequestId {
//!         client_id: ClientId { client_id_prefix: 0x00, client_id: 0x01 },
//!         session_id: 0x0000,
//!     },
//!     0x01, // protocol_version
//!     0x01, // interface_version
//!     MessageType::Response,
//!     ReturnCode::E_OK,
//!     &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
//! );
//!
//! // The length field is automatically set to 16 (8 header + 8 payload)
//! assert_eq!(repr.length, 16);
//!
//! let mut buffer = [0u8; 24]; // 16-byte header + 8-byte payload
//! let mut packet = Packet::new_unchecked(&mut buffer);
//! repr.emit(&mut packet);
//!
//! assert_eq!(packet.message_type(), 0x03); // Response
//! assert_eq!(packet.return_code(), 0x00); // E_OK
//! ```
//!
//! ### Working with return codes
//!
//! ```rust
//! use someip_wire::types::ReturnCode;
//!
//! // Named return codes
//! let ok = ReturnCode::E_OK;
//! let error = ReturnCode::E_NOT_OK;
//! let timeout = ReturnCode::E_TIMEOUT;
//!
//! // Reserved ranges
//! let someip_reserved = ReturnCode::ReservedSomeIP(0x15);
//! let service_reserved = ReturnCode::ReservedServiceMethod(0x30);
//!
//! // Convert to/from u8
//! assert_eq!(ok.as_u8(), 0x00);
//! assert_eq!(ReturnCode::from_u8(0x01), Some(ReturnCode::E_NOT_OK));
//!
//! // Check return code properties
//! assert!(ok.is_ok());
//! assert!(someip_reserved.is_reserved_someip());
//! assert!(service_reserved.is_reserved_service_method());
//! ```
//!
//! ### Using the prelude for convenience
//!
//! ```rust
//! use someip_wire::prelude::*;
//!
//! // All commonly used types are now available
//! let repr = Repr::new(
//!     MessageId { service_id: 0x1234, method_id: 0x0001 },
//!     RequestId {
//!         client_id: ClientId { client_id_prefix: 0x00, client_id: 0x01 },
//!         session_id: 0x0000,
//!     },
//!     0x01, // protocol_version
//!     0x01, // interface_version
//!     MessageType::Request,
//!     ReturnCode::E_OK,
//!     &[0xDE, 0xAD],
//! );
//! ```
//!
//! ## Modules
//!
//! - `error`: Contains the error type for SOME/IP packet parsing
//! - `field`: Contains the field definitions for the SOME/IP header
//! - `packet`: Contains the `Packet` type for low-level packet access (wire format)
//! - `prelude`: Re-exports commonly used types for convenient imports
//! - `repr`: Contains the `Repr` type for high-level SOME/IP representation
//! - `types`: Contains SOME/IP type definitions (MessageId, RequestId, ReturnCode, MessageType)
//!
//! ## Architecture
//!
//! The crate uses a two-layer architecture:
//! - **Wire format layer** (`packet`): Works directly with u8 values for efficiency
//! - **Representation layer** (`repr`, `types`): Provides clean enums and type-safe APIs
//!
//! This design ensures zero-cost abstractions while maintaining a pleasant developer experience.
//!

#![cfg_attr(not(test), no_std)]
#![warn(missing_docs)]

/// Error types for SOME/IP packet parsing and serialization.
pub mod error;
/// Field definitions and byte ranges for the SOME/IP header.
pub mod field;
/// Low-level packet access for wire format operations.
pub mod packet;
/// Commonly used types re-exported for convenience.
pub mod prelude;
/// High-level SOME/IP message representation.
pub mod repr;
/// SOME/IP type definitions (MessageId, RequestId, MessageType, ReturnCode).
pub mod types;

#[cfg(test)]
mod tests {
    use crate::{
        packet::Packet,
        repr::Repr,
        types::{ClientId, MessageId, MessageType, RequestId, ReturnCode},
    };

    #[test]
    fn test_deconstruct_without_payload() {
        let raw_packet: [u8; 16] = [
            0x12, 0x34, 0x00, 0x01, // Message ID
            0x00, 0x00, 0x00, 0x08, // Length (8 header bytes, no payload)
            0x01, 0x02, 0x00, 0x01, // Request ID
            0x01, // Protocol Version
            0x01, // Interface Version
            0x00, // Message Type
            0x00, // Return Code
        ];

        let packet = Packet::new_checked(&raw_packet[..]).unwrap();
        let repr = Repr::parse(&packet).unwrap();

        assert_eq!(
            repr.message_id,
            MessageId {
                service_id: 0x1234,
                method_id: 0x0001,
            }
        );
        assert_eq!(repr.length, 8); // 8 header bytes, no payload

        assert_eq!(
            repr.request_id,
            RequestId {
                client_id: ClientId {
                    client_id_prefix: 0x01,
                    client_id: 0x02,
                },
                session_id: 0x0001,
            }
        );
        assert_eq!(repr.protocol_version, 0x01);
        assert_eq!(repr.interface_version, 0x01);
        assert_eq!(repr.message_type, MessageType::Request);
        assert_eq!(repr.return_code, ReturnCode::E_OK);
        assert_eq!(repr.data, &[]);
    }

    #[test]
    fn test_deconstruct_with_payload() {
        let raw_packet: [u8; 20] = [
            0x12, 0x34, 0x00, 0x01, // Message ID
            0x00, 0x00, 0x00, 0x0C, // Length (8 header bytes + 4 payload bytes)
            0x01, 0x02, 0x00, 0x01, // Request ID
            0x01, // Protocol Version
            0x01, // Interface Version
            0x00, // Message Type
            0x00, // Return Code
            0xDE, 0xAD, 0xBE, 0xEF, // Payload
        ];

        let packet = Packet::new_checked(&raw_packet[..]).unwrap();
        let repr = Repr::parse(&packet).unwrap();

        assert_eq!(
            repr.message_id,
            MessageId {
                service_id: 0x1234,
                method_id: 0x0001,
            }
        );
        assert_eq!(repr.length, 12); // 8 header bytes + 4 payload bytes

        assert_eq!(
            repr.request_id,
            RequestId {
                client_id: ClientId {
                    client_id_prefix: 0x01,
                    client_id: 0x02,
                },
                session_id: 0x0001,
            }
        );
        assert_eq!(repr.protocol_version, 0x01);
        assert_eq!(repr.interface_version, 0x01);
        assert_eq!(repr.message_type, MessageType::Request);
        assert_eq!(repr.return_code, ReturnCode::E_OK);
        assert_eq!(repr.data, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_repr_parse() {
        let raw_packet: [u8; 16] = [
            0x12, 0x34, 0x00, 0x01, // Message ID
            0x00, 0x00, 0x00, 0x08, // Length
            0x01, 0x02, 0x00, 0x01, // Request ID
            0x01, // Protocol Version
            0x01, // Interface Version
            0x00, // Message Type
            0x00, // Return Code
        ];

        let packet = Packet::new_checked(&raw_packet[..]).unwrap();
        let repr = Repr::parse(&packet).unwrap();

        assert_eq!(
            repr,
            Repr::new(
                MessageId {
                    service_id: 0x1234,
                    method_id: 0x0001,
                },
                RequestId {
                    client_id: ClientId {
                        client_id_prefix: 0x01,
                        client_id: 0x02,
                    },
                    session_id: 0x0001,
                },
                0x01,
                0x01,
                MessageType::Request,
                ReturnCode::E_OK,
                &[],
            )
        );
    }

    #[test]
    fn test_repr_emit() {
        let repr = Repr::new(
            MessageId {
                service_id: 0x1234,
                method_id: 0x0001,
            },
            RequestId {
                client_id: ClientId {
                    client_id_prefix: 0x01,
                    client_id: 0x02,
                },
                session_id: 0x0001,
            },
            0x01,
            0x01,
            MessageType::Request,
            ReturnCode::E_OK,
            &[0xDE, 0xAD, 0xBE, 0xEF],
        );
        let mut buffer = [0u8; 20];
        let mut packet = Packet::new_unchecked(&mut buffer);
        repr.emit(&mut packet);
        let expected: [u8; 20] = [
            0x12, 0x34, 0x00, 0x01, // Message ID
            0x00, 0x00, 0x00, 0x0C, // Length
            0x01, 0x02, 0x00, 0x01, // Request ID
            0x01, // Protocol Version
            0x01, // Interface Version
            0x00, // Message Type
            0x00, // Return Code
            0xDE, 0xAD, 0xBE, 0xEF, // Payload
        ];
        assert_eq!(&buffer, &expected);
    }

    fn round_trip_test(repr: Repr) {
        let mut buffer = [0u8; 1024];
        {
            let mut packet = Packet::new_unchecked(&mut buffer);
            repr.emit(&mut packet);
        }
        let packet = Packet::new_checked(&buffer).unwrap();
        let parsed_repr = Repr::parse(&packet).unwrap();
        assert_eq!(parsed_repr, repr);
    }

    fn round_trip_test_with_bytes(repr: Repr, expected_bytes: &[u8]) {
        let mut buffer = [0u8; 1024]; // Use a large enough fixed-size buffer
        {
            let mut packet = Packet::new_unchecked(&mut buffer[..expected_bytes.len()]);
            repr.emit(&mut packet);
        }

        assert_eq!(&buffer[..expected_bytes.len()], expected_bytes);

        let packet = Packet::new_checked(&buffer[..expected_bytes.len()]).unwrap();
        let parsed_repr = Repr::parse(&packet).unwrap();
        assert_eq!(repr, parsed_repr);
    }

    #[test]
    fn test_repr_round_trip_request() {
        let repr = Repr {
            message_id: MessageId {
                service_id: 0x1234,
                method_id: 0x0001,
            },
            length: 12,
            request_id: RequestId {
                client_id: ClientId {
                    client_id_prefix: 0x01,
                    client_id: 0x02,
                },
                session_id: 0x0001,
            },
            protocol_version: 0x01,
            interface_version: 0x01,
            message_type: MessageType::Request,
            return_code: ReturnCode::E_OK,
            data: &[0xDE, 0xAD, 0xBE, 0xEF],
        };
        round_trip_test(repr);
        round_trip_test_with_bytes(
            repr,
            &[
                0x12, 0x34, // Service ID
                0x00, 0x01, // Method ID
                0x00, 0x00, 0x00, 0x0C, // Length
                0x01, 0x02, 0x00, 0x01, // Request ID
                0x01, // Protocol version
                0x01, // Interface version
                0x00, // MessageType
                0x00, // ReturnCode
                0xDE, 0xAD, 0xBE, 0xEF, // Data
            ],
        );
    }

    #[test]
    fn test_repr_round_trip_request_no_return() {
        let repr = Repr {
            message_id: MessageId {
                service_id: 0x1234,
                method_id: 0x0001,
            },
            length: 10,
            request_id: RequestId {
                client_id: ClientId {
                    client_id_prefix: 0x01,
                    client_id: 0x02,
                },
                session_id: 0x0001,
            },
            protocol_version: 0x01,
            interface_version: 0x01,
            message_type: MessageType::RequestNoReturn,
            return_code: ReturnCode::E_OK,
            data: &[0xAA, 0xBB],
        };
        round_trip_test(repr);
    }

    #[test]
    fn test_repr_round_trip_notification() {
        let repr = Repr {
            message_id: MessageId {
                service_id: 0x5678,
                method_id: 0x8001,
            },
            length: 0,
            request_id: RequestId {
                client_id: ClientId {
                    client_id_prefix: 0xFF,
                    client_id: 0xFF,
                },
                session_id: 0x0001,
            },
            protocol_version: 0x01,
            interface_version: 0x01,
            message_type: MessageType::Notification,
            return_code: ReturnCode::E_OK,
            data: &[],
        };
        round_trip_test(repr);
    }

    #[test]
    fn test_repr_round_trip_response() {
        let repr = Repr {
            message_id: MessageId {
                service_id: 0x1234,
                method_id: 0x0001,
            },
            length: 16,
            request_id: RequestId {
                client_id: ClientId {
                    client_id_prefix: 0x01,
                    client_id: 0x02,
                },
                session_id: 0x0001,
            },
            protocol_version: 0x01,
            interface_version: 0x01,
            message_type: MessageType::Response,
            return_code: ReturnCode::E_OK,
            data: &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77],
        };
        round_trip_test(repr);
    }

    #[test]
    fn test_repr_round_trip_error() {
        let repr = Repr {
            message_id: MessageId {
                service_id: 0x1234,
                method_id: 0x0001,
            },
            length: 0,
            request_id: RequestId {
                client_id: ClientId {
                    client_id_prefix: 0x01,
                    client_id: 0x02,
                },
                session_id: 0x0001,
            },
            protocol_version: 0x01,
            interface_version: 0x01,
            message_type: MessageType::Error,
            return_code: ReturnCode::E_NOT_OK,
            data: &[],
        };
        round_trip_test(repr);
    }

    #[test]
    fn test_repr_round_trip_tp_request() {
        let repr = Repr {
            message_id: MessageId {
                service_id: 0xABCD,
                method_id: 0x0042,
            },
            length: 9, 
            request_id: RequestId {
                client_id: ClientId {
                    client_id_prefix: 0x10,
                    client_id: 0x20,
                },
                session_id: 0x1234,
            },
            protocol_version: 0x01,
            interface_version: 0x02,
            message_type: MessageType::TPRequest,
            return_code: ReturnCode::E_OK,
            data: &[0xFF],
        };
        round_trip_test(repr);
    }

    #[test]
    fn test_repr_round_trip_tp_request_no_return() {
        let repr = Repr {
            message_id: MessageId {
                service_id: 0x0001,
                method_id: 0x0002,
            },
            length: 11, 
            request_id: RequestId {
                client_id: ClientId {
                    client_id_prefix: 0x00,
                    client_id: 0x01,
                },
                session_id: 0x0002,
            },
            protocol_version: 0x01,
            interface_version: 0x01,
            message_type: MessageType::TPRequestNoReturn,
            return_code: ReturnCode::E_OK,
            data: &[0x01, 0x02, 0x03],
        };
        round_trip_test(repr);
    }

    #[test]
    fn test_repr_round_trip_tp_notification() {
        let repr = Repr {
            message_id: MessageId {
                service_id: 0x9999,
                method_id: 0x8888,
            },
            length: 10, 
            request_id: RequestId {
                client_id: ClientId {
                    client_id_prefix: 0x00,
                    client_id: 0x00,
                },
                session_id: 0x0000,
            },
            protocol_version: 0x01,
            interface_version: 0x01,
            message_type: MessageType::TPNotification,
            return_code: ReturnCode::E_OK,
            data: &[0xCA, 0xFE],
        };
        round_trip_test(repr);
    }

    #[test]
    fn test_repr_round_trip_tp_response() {
        let repr = Repr {
            message_id: MessageId {
                service_id: 0x4321,
                method_id: 0x8765,
            },
            length: 13,
            request_id: RequestId {
                client_id: ClientId {
                    client_id_prefix: 0xAA,
                    client_id: 0xBB,
                },
                session_id: 0xCCDD,
            },
            protocol_version: 0x01,
            interface_version: 0x05,
            message_type: MessageType::TPResponse,
            return_code: ReturnCode::E_OK,
            data: &[0x10, 0x20, 0x30, 0x40, 0x50],
        };
        round_trip_test(repr);
    }

    #[test]
    fn test_repr_round_trip_tp_error() {
        let repr = Repr {
            message_id: MessageId {
                service_id: 0xFFFF,
                method_id: 0xFFFF,
            },
            length: 0,
            request_id: RequestId {
                client_id: ClientId {
                    client_id_prefix: 0xFF,
                    client_id: 0xFE,
                },
                session_id: 0xFFFE,
            },
            protocol_version: 0x01,
            interface_version: 0x01,
            message_type: MessageType::TPError,
            return_code: ReturnCode::E_TIMEOUT,
            data: &[],
        };
        round_trip_test(repr);
    }

    // Return code tests
    #[test]
    fn test_repr_round_trip_unknown_service() {
        let repr = Repr {
            message_id: MessageId {
                service_id: 0x1234,
                method_id: 0x0001,
            },
            length: 0,
            request_id: RequestId {
                client_id: ClientId {
                    client_id_prefix: 0x01,
                    client_id: 0x02,
                },
                session_id: 0x0001,
            },
            protocol_version: 0x01,
            interface_version: 0x01,
            message_type: MessageType::Error,
            return_code: ReturnCode::E_UNKNOWN_SERVICE,
            data: &[],
        };
        round_trip_test(repr);
    }

    #[test]
    fn test_repr_round_trip_unknown_method() {
        let repr = Repr {
            message_id: MessageId {
                service_id: 0x1234,
                method_id: 0x9999,
            },
            length: 0,
            request_id: RequestId {
                client_id: ClientId {
                    client_id_prefix: 0x01,
                    client_id: 0x02,
                },
                session_id: 0x0001,
            },
            protocol_version: 0x01,
            interface_version: 0x01,
            message_type: MessageType::Error,
            return_code: ReturnCode::E_UNKNOWN_METHOD,
            data: &[],
        };
        round_trip_test(repr);
    }

    #[test]
    fn test_repr_round_trip_not_ready() {
        let repr = Repr {
            message_id: MessageId {
                service_id: 0x1234,
                method_id: 0x0001,
            },
            length: 0,
            request_id: RequestId {
                client_id: ClientId {
                    client_id_prefix: 0x01,
                    client_id: 0x02,
                },
                session_id: 0x0001,
            },
            protocol_version: 0x01,
            interface_version: 0x01,
            message_type: MessageType::Error,
            return_code: ReturnCode::E_NOT_READY,
            data: &[],
        };
        round_trip_test(repr);
    }

    #[test]
    fn test_repr_round_trip_wrong_protocol_version() {
        let repr = Repr {
            message_id: MessageId {
                service_id: 0x1234,
                method_id: 0x0001,
            },
            length: 0,
            request_id: RequestId {
                client_id: ClientId {
                    client_id_prefix: 0x01,
                    client_id: 0x02,
                },
                session_id: 0x0001,
            },
            protocol_version: 0x01,
            interface_version: 0x01,
            message_type: MessageType::Error,
            return_code: ReturnCode::E_WRONG_PROTOCOL_VERSION,
            data: &[],
        };
        round_trip_test(repr);
    }

    #[test]
    fn test_repr_round_trip_wrong_interface_version() {
        let repr = Repr {
            message_id: MessageId {
                service_id: 0x1234,
                method_id: 0x0001,
            },
            length: 0,
            request_id: RequestId {
                client_id: ClientId {
                    client_id_prefix: 0x01,
                    client_id: 0x02,
                },
                session_id: 0x0001,
            },
            protocol_version: 0x01,
            interface_version: 0x01,
            message_type: MessageType::Error,
            return_code: ReturnCode::E_WRONG_INTERFACE_VERSION,
            data: &[],
        };
        round_trip_test(repr);
    }

    #[test]
    fn test_repr_round_trip_malformed_message() {
        let repr = Repr {
            message_id: MessageId {
                service_id: 0x1234,
                method_id: 0x0001,
            },
            length: 0,
            request_id: RequestId {
                client_id: ClientId {
                    client_id_prefix: 0x01,
                    client_id: 0x02,
                },
                session_id: 0x0001,
            },
            protocol_version: 0x01,
            interface_version: 0x01,
            message_type: MessageType::Error,
            return_code: ReturnCode::E_MALFORMED_MESSAGE,
            data: &[],
        };
        round_trip_test(repr);
    }

    #[test]
    fn test_repr_round_trip_wrong_message_type() {
        let repr = Repr {
            message_id: MessageId {
                service_id: 0x1234,
                method_id: 0x0001,
            },
            length: 0,
            request_id: RequestId {
                client_id: ClientId {
                    client_id_prefix: 0x01,
                    client_id: 0x02,
                },
                session_id: 0x0001,
            },
            protocol_version: 0x01,
            interface_version: 0x01,
            message_type: MessageType::Error,
            return_code: ReturnCode::E_WRONG_MESSAGE_TYPE,
            data: &[],
        };
        round_trip_test(repr);
    }

    #[test]
    fn test_repr_round_trip_e2e_errors() {
        // Test E2E_REPEATED
        let repr = Repr {
            message_id: MessageId {
                service_id: 0x1234,
                method_id: 0x0001,
            },
            length: 0,
            request_id: RequestId {
                client_id: ClientId {
                    client_id_prefix: 0x01,
                    client_id: 0x02,
                },
                session_id: 0x0001,
            },
            protocol_version: 0x01,
            interface_version: 0x01,
            message_type: MessageType::Error,
            return_code: ReturnCode::E_E2E_REPEATED,
            data: &[],
        };
        round_trip_test(repr);

        // Test E2E_WRONG_SEQUENCE
        let repr = Repr {
            return_code: ReturnCode::E_E2E_WRONG_SEQUENCE,
            ..repr
        };
        round_trip_test(repr);

        // Test E2E
        let repr = Repr {
            return_code: ReturnCode::E_E2E,
            ..repr
        };
        round_trip_test(repr);

        // Test E2E_NOT_AVAILABLE
        let repr = Repr {
            return_code: ReturnCode::E_E2E_NOT_AVAILABLE,
            ..repr
        };
        round_trip_test(repr);

        // Test E2E_NO_NEW_DATA
        let repr = Repr {
            return_code: ReturnCode::E_E2E_NO_NEW_DATA,
            ..repr
        };
        round_trip_test(repr);
    }

    #[test]
    fn test_repr_round_trip_reserved_someip_error() {
        // Test reserved SOME/IP error range (0x10-0x1F)
        let repr = Repr {
            message_id: MessageId {
                service_id: 0x1234,
                method_id: 0x0001,
            },
            length: 0,
            request_id: RequestId {
                client_id: ClientId {
                    client_id_prefix: 0x01,
                    client_id: 0x02,
                },
                session_id: 0x0001,
            },
            protocol_version: 0x01,
            interface_version: 0x01,
            message_type: MessageType::Error,
            return_code: ReturnCode::from_u8(0x10).unwrap(),
            data: &[],
        };
        round_trip_test(repr);

        let repr = Repr {
            return_code: ReturnCode::from_u8(0x1F).unwrap(),
            ..repr
        };
        round_trip_test(repr);
    }

    #[test]
    fn test_repr_round_trip_service_method_error() {
        // Test service/method specific error range (0x20-0x5E)
        let repr = Repr {
            message_id: MessageId {
                service_id: 0x1234,
                method_id: 0x0001,
            },
            length: 0,
            request_id: RequestId {
                client_id: ClientId {
                    client_id_prefix: 0x01,
                    client_id: 0x02,
                },
                session_id: 0x0001,
            },
            protocol_version: 0x01,
            interface_version: 0x01,
            message_type: MessageType::Error,
            return_code: ReturnCode::from_u8(0x20).unwrap(),
            data: &[],
        };
        round_trip_test(repr);

        let repr = Repr {
            return_code: ReturnCode::from_u8(0x42).unwrap(),
            ..repr
        };
        round_trip_test(repr);

        let repr = Repr {
            return_code: ReturnCode::from_u8(0x5E).unwrap(),
            ..repr
        };
        round_trip_test(repr);
    }

    #[test]
    fn test_return_code_public_api() {
        // Test named variants
        let ok = ReturnCode::E_OK;
        assert!(ok.is_ok());
        assert!(!ok.is_reserved_someip());
        assert!(!ok.is_reserved_service_method());
        assert_eq!(ok.as_u8(), 0x00);

        // Test reserved SOME/IP range
        let reserved_someip = ReturnCode::ReservedSomeIP(0x15);
        assert!(!reserved_someip.is_ok());
        assert!(reserved_someip.is_reserved_someip());
        assert!(!reserved_someip.is_reserved_service_method());
        assert_eq!(reserved_someip.as_u8(), 0x15);

        // Test reserved service/method range
        let reserved_service = ReturnCode::ReservedServiceMethod(0x42);
        assert!(!reserved_service.is_ok());
        assert!(!reserved_service.is_reserved_someip());
        assert!(reserved_service.is_reserved_service_method());
        assert_eq!(reserved_service.as_u8(), 0x42);

        // Test pattern matching
        match ReturnCode::from_u8(0x10).unwrap() {
            ReturnCode::ReservedSomeIP(code) => assert_eq!(code, 0x10),
            _ => panic!("Expected ReservedSomeIP variant"),
        }

        match ReturnCode::from_u8(0x20).unwrap() {
            ReturnCode::ReservedServiceMethod(code) => assert_eq!(code, 0x20),
            _ => panic!("Expected ReservedServiceMethod variant"),
        }

        // Test conversions - Display trait exists but we're in no_std so skip format! tests
        // The Display impl is tested implicitly when used with Repr
    }

    #[test]
    fn test_error_buffer_too_short() {
        // Buffer with less than 16 bytes
        let buffer = [0u8; 10];
        let packet = Packet::new_unchecked(&buffer);
        let result = Repr::parse(&packet);
        
        assert_eq!(result, Err(crate::error::Error::BufferTooShort));
    }

    #[test]
    fn test_error_truncated() {
        // Header claims 20 bytes payload but buffer only has 16 bytes total
        let buffer = [
            0x12, 0x34, 0x00, 0x01, // Message ID
            0x00, 0x00, 0x00, 0x1C, // Length (28 = 8 header + 20 payload)
            0x00, 0x01, 0x00, 0x00, // Request ID
            0x01,                   // Protocol version
            0x01,                   // Interface version
            0x00,                   // Message type
            0x00,                   // Return code
            // No payload bytes, but header claims 20 bytes
        ];
        
        let packet = Packet::new_unchecked(&buffer);
        let result = Repr::parse(&packet);
        
        assert_eq!(result, Err(crate::error::Error::Truncated));
    }

    #[test]
    fn test_error_invalid_message_type() {
        let buffer = [
            0x12, 0x34, 0x00, 0x01, // Message ID
            0x00, 0x00, 0x00, 0x08, // Length
            0x00, 0x01, 0x00, 0x00, // Request ID
            0x01,                   // Protocol version
            0x01,                   // Interface version
            0xFF,                   // Invalid message type
            0x00,                   // Return code
        ];
        
        let packet = Packet::new_unchecked(&buffer);
        let result = Repr::parse(&packet);
        
        assert_eq!(result, Err(crate::error::Error::InvalidMessageType(0xFF)));
    }

    #[test]
    fn test_error_invalid_return_code() {
        let buffer = [
            0x12, 0x34, 0x00, 0x01, // Message ID
            0x00, 0x00, 0x00, 0x08, // Length
            0x00, 0x01, 0x00, 0x00, // Request ID
            0x01,                   // Protocol version
            0x01,                   // Interface version
            0x00,                   // Message type (Request)
            0xFF,                   // Invalid return code (0xFF > 0x5E)
        ];
        
        let packet = Packet::new_unchecked(&buffer);
        let result = Repr::parse(&packet);
        
        assert_eq!(result, Err(crate::error::Error::InvalidReturnCode(0xFF)));
    }

    #[test]
    fn test_packet_new_checked_too_short() {
        let buffer = [0u8; 10];
        let result = Packet::new_checked(&buffer);
        
        assert_eq!(result, Err(crate::error::Error::BufferTooShort));
    }
}
