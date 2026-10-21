// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The gRPC transport: gRPC calls over HTTP/2, dialled and accepted, as a sans-IO framer.
//!
//! A transport-kind plugin on the memory ABI (`busbar_contract::abi::transport`): the one door
//! ([`door`]) is the same table compiled in and dropped in. It frames whatever bytes the connector
//! hands it (it names no carrier): the host owns the socket, connection security and the protocol
//! offer. HTTP/2 is `hyper`'s, run over the host's bytes by the contract's sans-IO drive
//! (`busbar_contract::hyper_io!`). The gRPC layer is this crate's ([`msg`], `transport`): the head
//! block, the length-prefixed message, `te: trailers`, a dialled call's deadline, and `grpc-status` read from
//! the trailers (or a trailers-only head).
//!
//! It carries no protocol meaning above gRPC: no service, no method, no message schema. That
//! belongs to whichever plane rides this transport.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

// THE KIND'S SHAPE (`BUSBAR-1.6.0.md` THE DESIGN, §2): what it declares (`meta`), what it claims
// (`claims`), the entry (`transport`: the sans-IO gRPC framer), and the door that states them.
mod claims;
mod door;
mod meta;
mod msg;
mod stream;
mod transport;

/// THE DOOR: this plugin's one public item (BUSBAR-1.6.0.md l.3567, Crate shape), and the
/// `MACRO_DOOR` its `plugin_door!` mints beside it (the door a linked table names).
pub use door::{door, MACRO_DOOR};

// The sans-IO `hyper` drive (pipe, executor, host-clock timer, sink fill), from the contract's SDK.
busbar_contract::hyper_io!(::bytes::Bytes);
