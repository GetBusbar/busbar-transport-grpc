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
//!   mapped ([`msg::status_of_refusal`], predev's words); a body whose message was over the ceiling
//!   closes `OUT_OF_RANGE` in predev's words for it, whatever the refusal; before any message went
//!   out the block is the whole answer (trailers-only: `:status: 200`, `content-type`, then the
//!   status lines).
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
    /// The body's message was over the ceiling: the call closes with predev's status and words
    /// for it (`OUT_OF_RANGE`), whatever refusal the host then closes it with.
    oversize: Option<msg::Bad>,
    /// The instant (host monotonic ns) the caller's `grpc-timeout` runs out, when it stated one.
    deadline: Option<u64>,
}

impl StreamCall {
    /// The call that arrived with `fields` at host monotonic `now_ns`, its messages at most `max`
    /// payload bytes; a `grpc-timeout` it states runs from `now_ns`, as the dedicated listener's
    /// accept path runs it.
    ///
    /// # Errors
    ///
    /// The call is not gRPC: its `content-type` is none of gRPC's.
    pub fn open<'f>(
        fields: impl Iterator<Item = (&'f [u8], &'f [u8])>,
        max: usize,
        now_ns: u64,
    ) -> Result<Self, Failure> {
        let (mut grpc, mut deadline) = (false, None);
        for (n, v) in fields {
            if n.eq_ignore_ascii_case(b"content-type") && msg::is_grpc_content_type(v) {
                grpc = true;
            } else if n.eq_ignore_ascii_case(msg::GRPC_TIMEOUT.as_bytes()) {
                deadline = msg::parse_timeout(v).map(|d| {
                    now_ns.saturating_add(u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
                });
            }
        }
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
            oversize: None,
            deadline,
        })
    }

    /// The host's timer at monotonic `now_ns`: a call past its `grpc-timeout` closes
    /// `DEADLINE_EXCEEDED`, and the host learns the stream failed.
    pub fn expire(&mut self, now_ns: u64) {
        if self.closed || self.deadline.is_none_or(|d| now_ns < d) {
            return;
        }
        self.deadline = None;
        let code = u32::from(msg::DEADLINE_EXCEEDED);
        if let Ok(lines) = msg::status_lines(code, b"deadline exceeded", &[]) {
            if !self.answered {
                self.wire.extend(b":status: 200\r\n");
                self.wire
                    .extend(format!("content-type: {}\r\n", msg::CONTENT_TYPE).as_bytes());
            }
            self.closed = true;
            self.wire.extend(lines);
        }
        self.out.push_back(Piece {
            status: Some(msg::DEADLINE_EXCEEDED),
            ..Piece::failure(STREAM, "deadline exceeded")
        });
    }

    /// The call's body bytes (`end` = its last): each message they complete is a piece.
    ///
    /// # Errors
    ///
    /// A message is compressed or over the ceiling, or the body ended inside one.
    pub fn ingest(&mut self, bytes: &[u8], end: bool) -> Result<(), Failure> {
        let bad = |e: msg::Bad| Failure(e.to_string());
        let got = self.messages.push(bytes).inspect_err(|e| {
            if matches!(e, msg::Bad::TooLarge(..)) {
                self.oversize = Some(e.clone());
            }
        });
        for m in got.map_err(bad)? {
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
    /// neutral `status` mapped. `head_sent`: the host already sent the call's response head
    /// (`RefuseIn::head_sent`), so the refusal is its closing lines only.
    ///
    /// # Errors
    ///
    /// The block cannot be written as field lines.
    pub fn refuse(&mut self, bytes: &[u8], status: u32, head_sent: bool) -> Result<(), Failure> {
        if self.closed {
            return Ok(());
        }
        let mut block = bytes.to_vec();
        if !block.ends_with(b"\r\n\r\n") {
            if !block.is_empty() && !block.ends_with(b"\r\n") {
                block.extend_from_slice(b"\r\n");
            }
            block.extend_from_slice(b"\r\n");
        }
        let lines = if let Some(e) = &self.oversize {
            msg::status_lines(u32::from(e.status()), e.to_string().as_bytes(), &[])
                .map_err(|e| Failure(e.into()))?
        } else {
            match msg::read_head(&block, usize::MAX) {
                Ok(Some((h, _))) if h.get(msg::GRPC_STATUS).is_some() => {
                    let pairs: Vec<(&str, &[u8])> = h
                        .fields
                        .iter()
                        .map(|(n, v)| (n.as_str(), v.as_slice()))
                        .collect();
                    let mut lines =
                        msg::render_head(&pairs, None).map_err(|e| Failure(e.into()))?;
                    lines.truncate(lines.len() - 2);
                    lines
                }
                _ => msg::status_lines(
                    u32::from(msg::status_of_refusal(status)),
                    msg::refusal_message(status).as_bytes(),
                    &[],
                )
                .map_err(|e| Failure(e.into()))?,
            }
        };
        // Closed only once the lines are rendered: a refusal that cannot be written leaves the call
        // open for the host's fallback close.
        self.closed = true;
        if !self.answered && !head_sent {
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
        // Rendered first, closed after: a final status that cannot be written leaves the call
        // open, so the host's fallback refusal can still close it with a `grpc-status`.
        let lines = msg::status_lines(status, message, details).map_err(|e| Failure(e.into()))?;
        self.closed = true;
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
        self.deadline.filter(|_| !self.closed)
    }
    fn ended(&self) -> bool {
        self.closed && self.wire.is_empty()
    }
}

#[cfg(test)]
#[path = "tests/stream_tests.rs"]
mod tests;
