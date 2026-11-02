// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The gRPC transport: gRPC calls over HTTP/2, dialled and accepted, as a sans-IO framer.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod claims;
mod door;
mod meta;
mod msg;
mod stream;
mod transport;

/// The door: the one entry, linked here and exported by the dropped-in build alike.
pub use door::door;

/// The transport axis entry the composition root folds for this transport: its key, the layers it

pub mod linked {
    /// The row's registry key.
    pub const KEY: &str = crate::meta::KEY;
    /// The layers this transport declares it can be built over: none (no transport names another).
    pub const COMPOSES_OVER: &[&str] = &[];
    /// Whether this transport carries sessions: a connection multiplexes calls, each a session.
    pub const SESSION: bool = crate::meta::SESSION;
    pub use crate::door::{door, MACRO_DOOR};
}

busbar_contract::hyper_io!(::bytes::Bytes);
