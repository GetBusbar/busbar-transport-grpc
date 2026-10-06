// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE STREAM (`SIDE_ACCEPT_STREAM`, ARCHITECT 4l, 2026-10-05): a gRPC call whose HTTP/2 connection
//! and head the host's own framer carries (one listener port carries every claim's streams), framed
//! here alone. The gRPC layer is still this door's:
//!
//! * `begin` takes the call's head fields: a call that is not gRPC (its `content-type`) is refused
//!   before it is one;
//! * `ingest` takes the call's body and yields each length-prefixed message's PAYLOAD as one piece
//!   on stream `1` that ends its frame (no piece ends the stream: the host's framer knows where the
//!   body ended);
//! * `emit` takes one reply message's payload and yields it length-prefixed, as body bytes;
//! * `finish` closes the call with the final status the unit stated: `grpc-status`, `grpc-message`
//!   (the unit's message) and `grpc-status-details-bin` (the unit's value, verbatim), in 1.5.5's
//!   bytes and order ([`msg::status_lines`]), the host's trailers;
//! * `refuse` closes it refused: the trailer block the refusal's bytes state, or its neutral status
//!   mapped ([`msg::status_of_refusal`], predev's words); before any message went out the block is
//!   the whole answer (trailers-only: `:status: 200`, `content-type`, then the status lines).
//!
//! Every block is field lines (`name: value` CRLF each) in `wire`, which the host sends verbatim.

use std::collections::VecDeque;

use crate::hyper_io::{Owed, Piece};
use crate::msg::{self, Messages, PREFIX};
use crate::transport::Failure;

/// The one stream a `SIDE_ACCEPT_STREAM` framing carries.
pub const STREAM: u64 = 1;

/// One call's framing.
pub struct StreamCall {
    messages: Messages,
    writing: Vec<u8>,
    wire: VecDeque<u8>,
    out: VecDeque<Piece>,
    /// A reply message went out: a close is trailers, not the whole answer.
    answered: bool,
    closed: bool,
}

impl StreamCall {
    /// The call that arrived with `fields`, its messages at most `max` payload bytes.
    ///
    /// # Errors
    ///
    /// The call is not gRPC: its `content-type` is none of gRPC's.
    pub fn open<'f>(
        mut fields: impl Iterator<Item = (&'f [u8], &'f [u8])>,
        max: usize,
    ) -> Result<Self, Failure> {
        let grpc = fields
            .any(|(n, v)| n.eq_ignore_ascii_case(b"content-type") && msg::is_grpc_content_type(v));
        if !grpc {
            return Err(Failure(
                "begin: the stream is not a gRPC call (its content-type)".into(),
            ));
        }
        Ok(Self {
            messages: Messages::new(max),
            writing: Vec::new(),
            wire: VecDeque::new(),
            out: VecDeque::new(),
            answered: false,
            closed: false,
        })
    }

    /// The call's body bytes (`end` = its last): each message they complete is a piece.
    ///
    /// # Errors
    ///
    /// A message is compressed or over the ceiling, or the body ended inside one.
    pub fn ingest(&mut self, bytes: &[u8], end: bool) -> Result<(), Failure> {
        let bad = |e: msg::Bad| Failure(e.to_string());
        for m in self.messages.push(bytes).map_err(bad)? {
            self.out.push_back(Piece::data(STREAM, m.slice(PREFIX..)));
        }
        if end {
            self.messages.end().map_err(bad)?;
        }
        Ok(())
    }

    /// One reply message's payload bytes (`ends` = they complete it).
    pub fn emit(&mut self, bytes: &[u8], ends: bool) {
        self.writing.extend_from_slice(bytes);
        if ends {
            self.wire
                .extend(msg::frame(&std::mem::take(&mut self.writing)));
            self.answered = true;
        }
    }

    /// Close the call refused: the block `bytes` state when they state a `grpc-status`, else the
    /// neutral `status` mapped.
    ///
    /// # Errors
    ///
    /// The block cannot be written as field lines.
    pub fn refuse(&mut self, bytes: &[u8], status: u32) -> Result<(), Failure> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let mut block = bytes.to_vec();
        if !block.ends_with(b"\r\n\r\n") {
            if !block.is_empty() && !block.ends_with(b"\r\n") {
                block.extend_from_slice(b"\r\n");
            }
            block.extend_from_slice(b"\r\n");
        }
        let lines = match msg::read_head(&block, usize::MAX) {
            Ok(Some((h, _))) if h.get(msg::GRPC_STATUS).is_some() => {
                let pairs: Vec<(&str, &[u8])> = h
                    .fields
                    .iter()
                    .map(|(n, v)| (n.as_str(), v.as_slice()))
                    .collect();
                let mut lines = msg::render_head(&pairs, None).map_err(|e| Failure(e.into()))?;
                lines.truncate(lines.len() - 2);
                lines
            }
            _ => msg::status_lines(
                u32::from(msg::status_of_refusal(status)),
                msg::refusal_message(status).as_bytes(),
                &[],
            )
            .map_err(|e| Failure(e.into()))?,
        };
        if !self.answered {
            self.wire.extend(b":status: 200\r\n");
            self.wire
                .extend(format!("content-type: {}\r\n", msg::CONTENT_TYPE).as_bytes());
        }
        self.wire.extend(lines);
        Ok(())
    }

    /// Close the call with the unit's final status (`status` in gRPC's numbering, its message and
    /// its details value).
    ///
    /// # Errors
    ///
    /// The details are not one field value.
    pub fn finish(&mut self, status: u32, message: &[u8], details: &[u8]) -> Result<(), Failure> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let lines = msg::status_lines(status, message, details).map_err(|e| Failure(e.into()))?;
        self.wire.extend(lines);
        Ok(())
    }
}

impl Owed for StreamCall {
    fn take_wire(&mut self, cap: usize) -> Vec<u8> {
        let n = cap.min(self.wire.len());
        self.wire.drain(..n).collect()
    }
    fn wire_pending(&self) -> bool {
        !self.wire.is_empty()
    }
    fn pieces(&mut self) -> &mut VecDeque<Piece> {
        &mut self.out
    }
    fn next_deadline(&self) -> Option<u64> {
        None
    }
    fn ended(&self) -> bool {
        self.closed && self.wire.is_empty()
    }
}

#[cfg(test)]
#[path = "tests/stream_tests.rs"]
mod tests;
