# someip-wire

[![Crates.io](https://img.shields.io/crates/v/someip-wire.svg)](https://crates.io/crates/someip-wire)
[![Documentation](https://docs.rs/someip-wire/badge.svg)](https://docs.rs/someip-wire)
[![License](https://img.shields.io/crates/l/someip-wire.svg)](https://github.com/martinpalsson/someip-wire#license)

A `no_std` Rust crate for parsing and serializing SOME/IP (Scalable service-Oriented MiddlewarE over IP) wire protocol packets. This crate is shamelessly inspired by the smoltcp crate.

Based on the [AUTOSAR SOME/IP Protocol Specification](https://www.autosar.org/fileadmin/standards/R22-11/FO/AUTOSAR_PRS_SOMEIPProtocol.pdf).

## Disclaimer

**This crate is intended for educational and research purposes to study the SOME/IP protocol.**

The SOME/IP protocol is an AUTOSAR standard. AUTOSAR claims intellectual property rights over their specifications.

## Scope

**This crate focuses solely on SOME/IP header parsing and serialization.**

The crate parses the standardized 16-byte SOME/IP header and provides the payload data as a raw byte slice. It does NOT parse the payload content itself, as payload format is entirely application-specific and defined by service interface definitions (e.g., FIDL/Franca IDL).

### Architecture

To build a complete SOME/IP stack using this crate:

1. **Use `someip-wire`** to parse/emit SOME/IP headers (this crate)
2. **Implement payload parsers** based on your service interface definitions
3. **Route messages** by connecting service/method IDs to their respective payload handlers

## Features

- **`no_std` compatible** - Works in embedded environments
- **Zero-allocation** - All operations work on borrowed data
- **Type-safe API** - Clean enums for message types and return codes
- **Efficient wire format** - Direct u8 operations at the packet level
- **Two-layer architecture** - Low-level packet access + high-level representation

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
someip-wire = "0.1.1"
```

## Examples

### Parsing a SOME/IP packet

```rust
use someip_wire::prelude::*;

let buffer = [
    0x12, 0x34, 0x00, 0x01, // Message ID
    0x00, 0x00, 0x00, 0x08, // Length
    0x00, 0x01, 0x00, 0x00, // Request ID
    0x01,                   // Protocol version
    0x01,                   // Interface version
    0x00,                   // Message type (Request)
    0x00,                   // Return code (E_OK)
    // Payload data
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
];

let packet = Packet::new_unchecked(&buffer);
let repr = Repr::parse(&packet).unwrap();

assert_eq!(repr.protocol_version, 0x01);
assert_eq!(repr.data.len(), 8);
// repr.data contains the raw payload bytes - parse based on your service definition
```

### Creating a SOME/IP packet

```rust
use someip_wire::prelude::*;

let repr = Repr {
    message_id: MessageId {
        service_id: 0x1234,
        method_id: 0x0001,
    },
    length: 8,
    request_id: RequestId {
        client_id: ClientId {
            client_id_prefix: 0x00,
            client_id: 0x01,
        },
        session_id: 0x0000,
    },
    protocol_version: 0x01,
    interface_version: 0x01,
    message_type: MessageType::Response,
    return_code: ReturnCode::E_OK,
    data: &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08], // Your serialized payload
};

let mut buffer = [0u8; 24];
let mut packet = Packet::new_unchecked(&mut buffer);
repr.emit(&mut packet);
```

**Note:** The `data` field contains your service-specific payload. You are responsible for serializing/deserializing this based on your service interface definitions.

### Working with return codes

```rust
use someip_wire::prelude::*;

// Named return codes
let ok = ReturnCode::E_OK;
let timeout = ReturnCode::E_TIMEOUT;

// Reserved ranges
let someip_reserved = ReturnCode::ReservedSomeIP(0x15);
let service_reserved = ReturnCode::ReservedServiceMethod(0x30);

// Check properties
assert!(ok.is_ok());
assert!(someip_reserved.is_reserved_someip());
```

## Architecture

The crate uses a two-layer architecture:

- **Wire format layer** (`packet` module) - Works directly with raw bytes using u8 values for maximum efficiency
- **Representation layer** (`repr`, `types` modules) - Provides type-safe enums and structs for ergonomic API

This ensures zero-cost abstractions while maintaining a pleasant developer experience.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
