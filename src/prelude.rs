//! Prelude module for convenient imports.
//!
//! This module re-exports the most commonly used types and traits.
//!
//! # Examples
//!
//! ```rust
//! use someip_wire::prelude::*;
//!
//! // Now you have access to:
//! // - Packet
//! // - Repr
//! // - MessageId, RequestId, ClientId
//! // - MessageType, ReturnCode
//! // - Error
//! ```

pub use crate::error::Error;
pub use crate::packet::Packet;
pub use crate::repr::Repr;
pub use crate::types::{ClientId, MessageId, MessageType, RequestId, ReturnCode};
