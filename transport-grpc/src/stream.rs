// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One stream (`SIDE_ACCEPT_STREAM`): a gRPC call whose HTTP/2 connection
//! and head the host's own framer carries (one listener port carries every claim's streams), framed
//! here alone. The gRPC layer is still this door's:
//!
//! * `begin` takes the call's head fields: a call that is not gRPC (its `content-type`) is refused
//!   before it is one; a call whose `grpc-encoding` names a compression this door does not take
//!   fails its first `ingest`, and its close is `UNIMPLEMENTED` with `grpc-accept-encoding` (gRPC's
//!   compression rules); the first `grpc-encoding` field is the call's, a repeat is not read;
//!   a `grpc-timeout` it states is a fact for the plane in the head the host keeps: this framing
//!   enforces no deadline and never closes a call `DEADLINE_EXCEEDED`;
//! * `ingest` takes the call's body and yields each length-prefixed message's PAYLOAD as one piece
//!   on stream `1` that ends its frame (no piece ends the stream: the host's framer knows where the
//!   body ended);
//! * `emit` takes one reply message's payload and yields it length-prefixed, as body bytes; once
//!   the call is closed an `emit` writes nothing. The reply has a stream's own backpressure: an
//!   `emit` that leaves its queue at the high-water mark is answered `YIELD_STREAM_FULL`, a
//!   writable piece follows the drain, and a host that emits past the bound has the reply cut (the
//!   call then closes `RESOURCE_EXHAUSTED`, whatever close it states);
//! * `finish` closes the call with the final status the unit stated: `grpc-status`, `grpc-message`
//!   (the unit's message) and `grpc-status-details-bin` (the unit's value, verbatim), in tonic
//!   0.14's bytes and order ([`msg::status_lines`]), the host's trailers;
//! * `refuse` closes it refused: the trailer block the refusal's bytes state, or its neutral status
//!   mapped ([`msg::status_of_refusal`]); a body whose message was over the ceiling closes
//!   `RESOURCE_EXHAUSTED` in this framer's words, naming the configured limit, whatever the
//!   refusal; before any message went out the block is the whole answer (trailers-only:
//!   `:status: 200`, `content-type`, then the status lines).
//!
//! Every block is field lines (`name: value` CRLF each) in `wire`, which the host sends verbatim.

use std::collections::VecDeque;

use crate::hyper_io::{Owed, Piece};
use crate::msg::{self, Messages, PREFIX};
use crate::transport::{
    stream_bound, Failure, OVER_BOUND, STREAM_HIGH_WATER, STREAM_LOW_WATER,
};

/// The one stream a `SIDE_ACCEPT_STREAM` framing carries.
pub const STREAM: u64 = 1;

/// One call's framing.
pub struct StreamCall {
    messages: Messages,
    /// The largest message payload carried, either way.
    max: usize,
    writing: Vec<u8>,
    /// The bytes owed the host's wire, taken from the front ([`Owed::take_wire`]): a deque, so a
    /// partial take copies only what it takes, never the rest.
    wire: VecDeque<u8>,
    out: VecDeque<Piece>,
    /// A reply message went out: a close is trailers, not the whole answer.
    answered: bool,
    closed: bool,
    /// The body was refused for what it is (a message over the ceiling, a compression the door
    /// does not take): the call closes with its status and words for it (`RESOURCE_EXHAUSTED`,
    /// `UNIMPLEMENTED`), whatever refusal the host then closes it with.
    oversize: Option<msg::Bad>,
    /// The reply was cut ([`StreamCall::cut_reply`]), for these words.
    cut: Option<String>,
    /// An `emit` was answered `YIELD_STREAM_FULL`, and no writable piece has followed yet.
    announced: bool,
}

impl StreamCall {
    /// The call that arrived with `fields`, its messages at most `max` payload bytes.
    ///
    /// A `grpc-encoding` naming a compression the door does not take opens the call already
    /// refused: its first `ingest` fails, and its close is `UNIMPLEMENTED`. The FIRST
    /// `grpc-encoding` field is the call's encoding; a repeat is not read.
    ///
    /// # Errors
    ///
    /// The call is not gRPC: its `content-type` is none of gRPC's.
    pub fn open<'f>(
        fields: impl Iterator<Item = (&'f [u8], &'f [u8])>,
        max: usize,
    ) -> Result<Self, Failure> {
        let (mut grpc, mut encoding) = (false, None);
        for (n, v) in fields {
            if n.eq_ignore_ascii_case(b"content-type") && msg::is_grpc_content_type(v) {
                grpc = true;
            } else if encoding.is_none() && n.eq_ignore_ascii_case(msg::GRPC_ENCODING.as_bytes()) {
                encoding = Some(v);
            }
        }
        let refused = encoding.and_then(msg::unsupported_encoding);
        if !grpc {
            return Err(Failure(
                "begin: the stream is not a gRPC call (its content-type)".into(),
            ));
        }
        Ok(Self {
            messages: Messages::new(max),
            max,
            writing: Vec::new(),
            wire: VecDeque::new(),
            out: VecDeque::new(),
            answered: false,
            closed: false,
            oversize: refused,
            cut: None,
            announced: false,
        })
    }

    /// The call's body bytes (`end` = its last): each message they complete is a piece.
    ///
    /// # Errors
    ///
    /// A message is compressed or over the ceiling, or the body ended inside one.
    pub fn ingest(&mut self, bytes: &[u8], end: bool) -> Result<(), Failure> {
        let bad = |e: msg::Bad| Failure(e.to_string());
        if let Some(e @ msg::Bad::Encoding(_)) = &self.oversize {
            return Err(bad(e.clone()));
        }
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

    /// One reply message's payload bytes (`ends` = they complete it). A call already closed takes
    /// none: body bytes after the closing lines would follow the trailers. Nor does a reply that
    /// was cut ([`StreamCall::cut`]).
    ///
    /// # Errors
    ///
    /// The reply is cut here: its queue went past its bound (a host that kept emitting to a far
    /// end not reading, [`stream_bound`]), or its message is longer than a length prefix states.
    pub fn emit(&mut self, bytes: &[u8], ends: bool) -> Result<(), Failure> {
        if self.closed || self.cut.is_some() {
            return Ok(());
        }
        if self.queued().saturating_add(bytes.len()) > stream_bound(self.max) {
            return Err(self.cut_reply(OVER_BOUND.into()));
        }
        if !ends {
            self.writing.extend_from_slice(bytes);
            return Ok(());
        }
        let len = self.writing.len().saturating_add(bytes.len());
        let Some(prefix) = msg::prefix(len) else {
            return Err(self.cut_reply(format!(
                "the reply message is {len} bytes, longer than a gRPC length prefix states"
            )));
        };
        self.wire.extend(prefix);
        self.wire.extend(self.writing.drain(..));
        self.wire.extend(bytes);
        self.answered = true;
        Ok(())
    }

    /// The reply bytes queued and not yet taken by the host: the wire, and the message being
    /// written.
    fn queued(&self) -> usize {
        self.wire.len().saturating_add(self.writing.len())
    }

    /// Whether the reply's queue stands at its high-water mark after an `emit`: the answer is then
    /// `YIELD_STREAM_FULL`, and the stream hands a writable piece once the host has taken it down
    /// to its low-water mark (the transport ABI's "A STREAM'S OWN BACKPRESSURE").
    pub fn announce_full(&mut self) -> bool {
        let full = !self.closed && self.cut.is_none() && self.queued() >= STREAM_HIGH_WATER;
        self.announced |= full;
        full
    }

    /// Cut the reply for `why`: the message being written is dropped, no reply byte more is taken,
    /// and the call closes `RESOURCE_EXHAUSTED` in these words, whatever close the host states (the
    /// far end never takes a reply missing a message for a whole one).
    fn cut_reply(&mut self, why: String) -> Failure {
        self.writing = Vec::new();
        self.cut = Some(why.clone());
        Failure(why)
    }

    /// Close the call refused: the block `bytes` state when they state a `grpc-status`, else the
    /// neutral `status` mapped, else (no status stated either way) `UNKNOWN` with the bytes as its
    /// message. `head_sent`: the host already sent the call's response head
    /// (`RefuseIn::head_sent`), so the refusal is its closing lines only.
    ///
    /// # Errors
    ///
    /// The block cannot be written as field lines.
    pub fn refuse(&mut self, bytes: &[u8], status: u32, head_sent: bool) -> Result<(), Failure> {
        if self.closed {
            return Ok(());
        }
        let lines = if let Some(e) = &self.oversize {
            e.close_lines().map_err(|e| Failure(e.into()))?
        } else if let Some(why) = &self.cut {
            cut_lines(why)?
        } else {
            match msg::refusal_block(bytes).map_err(Failure)? {
                Some(h) => {
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
                None if status != 0 => msg::status_lines(
                    u32::from(msg::status_of_refusal(status)),
                    msg::refusal_message(status).as_bytes(),
                    &[],
                )
                .map_err(|e| Failure(e.into()))?,
                // No status stated either way: `UNKNOWN`, the refusal's bytes its message, as the
                // connection side ends the same refusal.
                None => msg::status_lines(u32::from(msg::UNKNOWN), bytes, &[])
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
        let lines = match &self.cut {
            Some(why) => cut_lines(why)?,
            None => msg::status_lines(status, message, details).map_err(|e| Failure(e.into()))?,
        };
        self.closed = true;
        self.wire.extend(lines);
        Ok(())
    }
}

/// The closing lines of a call whose reply was cut for `why`.
fn cut_lines(why: &str) -> Result<Vec<u8>, Failure> {
    msg::status_lines(u32::from(msg::RESOURCE_EXHAUSTED), why.as_bytes(), &[])
        .map_err(|e| Failure(e.into()))
}

impl Owed for StreamCall {
    fn take_wire(&mut self, cap: usize) -> Vec<u8> {
        let n = cap.min(self.wire.len());
        let taken = self.wire.drain(..n).collect();
        // Taken ahead of the pieces (`fill`), so the writable piece goes out in this same answer.
        if self.announced && !self.closed && self.queued() <= STREAM_LOW_WATER {
            self.announced = false;
            self.out.push_back(Piece::writable(STREAM));
        }
        taken
    }
    fn wire_pending(&self) -> bool {
        !self.wire.is_empty()
    }
    fn pieces(&mut self) -> &mut VecDeque<Piece> {
        &mut self.out
    }
    /// No deadline: this framing asks the host for no timer.
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
