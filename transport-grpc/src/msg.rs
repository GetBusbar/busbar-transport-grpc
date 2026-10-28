// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE gRPC LAYER'S BYTES (gRPC over HTTP/2, `PROTOCOL-HTTP2.md`): the length-prefixed message,
//! `grpc-status` and its classes, the percent-encoded `grpc-message`, and the head block this
//! door's host speaks in.
//!
//! THE HEAD BLOCK. What the host hands this door on `emit` (and what `encode` renders) is a head
//! block, then messages:
//!
//! ```text
//! name: value\r\n        one line per field (the dial side's `path` names the method)
//! content-length: N\r\n  optional: the N bytes after the block are the whole message stream
//! \r\n
//! <messages, each in its length-prefixed form>
//! ```
//!
//! A message on this wire, both ways, is its LENGTH-PREFIXED FORM: one flag byte (`0` = not
//! compressed; this door negotiates no compression, and a call whose `grpc-encoding` names one is
//! answered `UNIMPLEMENTED` with the `grpc-accept-encoding` it takes, [`unsupported_encoding`]), a
//! four-byte big-endian length, the payload.
//! A frame this door answers is one whole message in that form, so it is never empty — an empty
//! payload is still five bytes; the stream's end is its own piece (`PIECE_END`), never an empty
//! frame.

use bytes::{Bytes, BytesMut};

/// The prefix of a length-prefixed message.
pub const PREFIX: usize = 5;

/// The one content type every gRPC answer and request carries (its `+proto`/`+json` forms extend
/// it).
pub const CONTENT_TYPE: &str = "application/grpc";

/// Whether `v` is a gRPC content type: `application/grpc`, or it followed by `+` or `;`.
#[must_use]
pub fn is_grpc_content_type(v: &[u8]) -> bool {
    let base = CONTENT_TYPE.as_bytes();
    v.len() >= base.len()
        && v[..base.len()].eq_ignore_ascii_case(base)
        && matches!(v.get(base.len()), None | Some(b'+' | b';'))
}

/// The prefix of a message whose payload is `len` bytes.
#[must_use]
pub fn prefix(len: usize) -> [u8; PREFIX] {
    let n = u32::try_from(len).unwrap_or(u32::MAX).to_be_bytes();
    [0, n[0], n[1], n[2], n[3]]
}

/// `payload` in its length-prefixed form.
#[must_use]
pub fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PREFIX + payload.len());
    out.extend_from_slice(&prefix(payload.len()));
    out.extend_from_slice(payload);
    out
}

/// Why a message stream is not one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bad {
    /// A message is compressed, and no compression was agreed.
    Compressed,
    /// The call's `grpc-encoding` names a compression this door does not take: the name, as text.
    Encoding(String),
    /// A message is larger than the ceiling: its stated length, and the ceiling.
    TooLarge(usize, usize),
    /// The stream ended inside a message.
    Truncated,
}

impl Bad {
    /// The `grpc-status` a call fails with for it: `RESOURCE_EXHAUSTED` for an oversize message, on
    /// the dial and both accept paths (gRPC's status codes: "received message larger than max");
    /// `UNIMPLEMENTED` for
    /// a compression the door does not take (gRPC's compression rules, `compression.md`);
    /// `INTERNAL` else.
    #[must_use]
    pub fn status(&self) -> u16 {
        match self {
            Self::TooLarge(..) => RESOURCE_EXHAUSTED,
            Self::Encoding(_) => UNIMPLEMENTED,
            Self::Compressed | Self::Truncated => INTERNAL,
        }
    }

    /// The closing status lines a call this failed closes with ([`status_lines`]): for a compression
    /// the door does not take, `grpc-accept-encoding` (the encodings it takes, `compression.md`)
    /// first, then the status.
    ///
    /// # Errors
    ///
    /// Never for these texts: [`status_lines`] refuses only details, and these state none.
    pub fn close_lines(&self) -> Result<Vec<u8>, &'static str> {
        let mut out = Vec::new();
        if matches!(self, Self::Encoding(_)) {
            out.extend_from_slice(
                format!("{GRPC_ACCEPT_ENCODING}: {ACCEPT_ENCODING}\r\n").as_bytes(),
            );
        }
        out.extend(status_lines(
            u32::from(self.status()),
            self.to_string().as_bytes(),
            &[],
        )?);
        Ok(out)
    }
}

/// The compression a call's `grpc-encoding` value `v` names, where this door does not take it:
/// every value but `identity`, the one encoding it takes. `None` = the call is not compressed.
#[must_use]
pub fn unsupported_encoding(v: &[u8]) -> Option<Bad> {
    if v == b"identity" {
        return None;
    }
    // Text where it is text; else the bytes, each as its number.
    Some(Bad::Encoding(
        std::str::from_utf8(v).map_or_else(|_| format!("{v:?}"), str::to_owned),
    ))
}

impl std::fmt::Display for Bad {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Compressed => {
                f.write_str("a message is compressed and no compression was agreed")
            }
            Self::Encoding(name) => write!(
                f,
                "the message encoding `{name}` is not supported: this server takes identity"
            ),
            // This framer's own words, naming the configured ceiling: the
            // same `limits.request_body_max_bytes` that bounds every inbound body.
            Self::TooLarge(n, limit) => write!(
                f,
                "the message is {n} bytes, over the limit of {limit} bytes \
                 (limits.request_body_max_bytes)"
            ),
            Self::Truncated => f.write_str("the stream ended inside a message"),
        }
    }
}

/// Cuts a byte stream into whole length-prefixed messages.
#[derive(Debug)]
pub struct Messages {
    buf: BytesMut,
    max: usize,
}

impl Messages {
    /// A cutter whose messages are at most `max` payload bytes.
    #[must_use]
    pub fn new(max: usize) -> Self {
        Self {
            buf: BytesMut::new(),
            max,
        }
    }

    /// Take `bytes`, and answer every message they complete (each in its length-prefixed form).
    ///
    /// # Errors
    ///
    /// A message is compressed or over the ceiling.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Bytes>, Bad> {
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        while self.buf.len() >= PREFIX {
            if self.buf[0] != 0 {
                return Err(Bad::Compressed);
            }
            let n =
                u32::from_be_bytes([self.buf[1], self.buf[2], self.buf[3], self.buf[4]]) as usize;
            if n > self.max {
                return Err(Bad::TooLarge(n, self.max));
            }
            if self.buf.len() < PREFIX + n {
                break;
            }
            out.push(self.buf.split_to(PREFIX + n).freeze());
        }
        Ok(out)
    }

    /// [`Messages::push`] for bytes already shared: with nothing held back, each whole message in
    /// `data` is a slice of it (no copy), and only a cut tail is held.
    ///
    /// # Errors
    ///
    /// A message is compressed or over the ceiling.
    pub fn push_bytes(&mut self, mut data: Bytes) -> Result<Vec<Bytes>, Bad> {
        if !self.buf.is_empty() {
            return self.push(&data);
        }
        let mut out = Vec::new();
        while data.len() >= PREFIX {
            if data[0] != 0 {
                return Err(Bad::Compressed);
            }
            let n = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
            if n > self.max {
                return Err(Bad::TooLarge(n, self.max));
            }
            if data.len() < PREFIX + n {
                break;
            }
            out.push(data.split_to(PREFIX + n));
        }
        self.buf.extend_from_slice(&data);
        Ok(out)
    }

    /// The stream ended.
    ///
    /// # Errors
    ///
    /// It ended inside a message.
    pub fn end(&self) -> Result<(), Bad> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(Bad::Truncated)
        }
    }
}

/// The field the call's status travels in (the trailers, or a trailers-only head).
pub const GRPC_STATUS: &str = "grpc-status";
/// The field the status's text travels in, percent-encoded.
pub const GRPC_MESSAGE: &str = "grpc-message";
/// The field a call's deadline travels in.
pub const GRPC_TIMEOUT: &str = "grpc-timeout";
/// The field naming the compression a call's messages are in.
pub const GRPC_ENCODING: &str = "grpc-encoding";
/// The field naming the compressions a server takes, on an answer refusing another.
pub const GRPC_ACCEPT_ENCODING: &str = "grpc-accept-encoding";
/// The one compression this door takes: none.
pub const ACCEPT_ENCODING: &str = "identity";

/// `OK`.
pub const OK: u16 = 0;
/// `CANCELLED`.
pub const CANCELLED: u16 = 1;
/// `UNKNOWN`.
pub const UNKNOWN: u16 = 2;
/// `DEADLINE_EXCEEDED`.
pub const DEADLINE_EXCEEDED: u16 = 4;
/// `PERMISSION_DENIED`.
pub const PERMISSION_DENIED: u16 = 7;
/// `RESOURCE_EXHAUSTED`.
pub const RESOURCE_EXHAUSTED: u16 = 8;
/// `UNIMPLEMENTED`.
pub const UNIMPLEMENTED: u16 = 12;
/// `INTERNAL`.
pub const INTERNAL: u16 = 13;
/// `UNAVAILABLE`.
pub const UNAVAILABLE: u16 = 14;
/// `UNAUTHENTICATED`.
pub const UNAUTHENTICATED: u16 = 16;

/// The `grpc-status` an answer that is not gRPC stands for, by its HTTP status
/// (`http-grpc-status-mapping.md`).
#[must_use]
pub fn status_of_http(code: u16) -> u16 {
    match code {
        400 => INTERNAL,
        401 => UNAUTHENTICATED,
        403 => PERMISSION_DENIED,
        404 => UNIMPLEMENTED,
        429 | 502 | 503 | 504 => UNAVAILABLE,
        _ => UNKNOWN,
    }
}

/// The `grpc-status` an HTTP/2 error `code` stands for on a dialled stream it ended (a reset or a
/// GOAWAY, either end's), before or after the answer's head alike: gRPC over HTTP/2
/// (PROTOCOL-HTTP2.md, "Errors"). `REFUSED_STREAM` is `UNAVAILABLE` (nothing was processed: safe
/// to retry), `CANCEL` is `CANCELLED`, `ENHANCE_YOUR_CALM` is `RESOURCE_EXHAUSTED`,
/// `INADEQUATE_SECURITY` is `PERMISSION_DENIED`, and every other code is `INTERNAL`: the ones the
/// table lists so (`NO_ERROR`, `PROTOCOL_ERROR`, `INTERNAL_ERROR`, `FLOW_CONTROL_ERROR`,
/// `SETTINGS_TIMEOUT`, `FRAME_SIZE_ERROR`, `COMPRESSION_ERROR`, `CONNECT_ERROR`,
/// `HTTP_1_1_REQUIRED`), `STREAM_CLOSED`, which it does not list, and a code HTTP/2 does not
/// define. RFC 9113 §7 permits this, saying an unknown code MAY be treated as `INTERNAL_ERROR`, and
/// nothing about such a stream says the far end processed nothing, so it is never read as safe to
/// retry.
#[must_use]
pub fn status_of_reset(code: u32) -> u16 {
    match code {
        0x7 => UNAVAILABLE,
        0x8 => CANCELLED,
        0xb => RESOURCE_EXHAUSTED,
        0xc => PERMISSION_DENIED,
        _ => INTERNAL,
    }
}

/// An HTTP/2 error `code`'s name (RFC 9113 §7), or its number where HTTP/2 defines none.
#[must_use]
pub fn reset_name(code: u32) -> String {
    const NAMES: [&str; 14] = [
        "NO_ERROR",
        "PROTOCOL_ERROR",
        "INTERNAL_ERROR",
        "FLOW_CONTROL_ERROR",
        "SETTINGS_TIMEOUT",
        "STREAM_CLOSED",
        "FRAME_SIZE_ERROR",
        "REFUSED_STREAM",
        "CANCEL",
        "COMPRESSION_ERROR",
        "CONNECT_ERROR",
        "ENHANCE_YOUR_CALM",
        "INADEQUATE_SECURITY",
        "HTTP_1_1_REQUIRED",
    ];
    usize::try_from(code)
        .ok()
        .and_then(|i| NAMES.get(i))
        .map_or_else(|| format!("error code {code:#x}"), |n| (*n).to_owned())
}

/// The `grpc-status` a refusal's neutral status ([`RefuseIn::status`]) stands for on a call's
/// end: the HTTP-to-status table, and `413` as `RESOURCE_EXHAUSTED`.
///
/// [`RefuseIn::status`]: busbar_contract::abi::transport::RefuseIn::status
#[must_use]
pub fn status_of_refusal(status: u32) -> u16 {
    match status {
        413 => RESOURCE_EXHAUSTED,
        s => u16::try_from(s).map_or(UNKNOWN, status_of_http),
    }
}

/// The `grpc-message` a refusal's neutral status ends a call with when its trailer block states
/// no `grpc-status`.
#[must_use]
pub fn refusal_message(status: u32) -> String {
    format!("busbar answered HTTP {status}")
}

/// A `grpc-status` value, read: the canonical codes are `0..=16`; anything else is `UNKNOWN`.
#[must_use]
pub fn parse_status(v: &[u8]) -> u16 {
    std::str::from_utf8(v)
        .ok()
        .and_then(|s| s.trim().parse::<u16>().ok())
        .filter(|c| *c <= 16)
        .unwrap_or(UNKNOWN)
}

/// `grpc-message`, percent-decoded (a malformed escape stays as it was sent).
#[must_use]
pub fn decode_message(v: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len());
    let mut i = 0;
    while i < v.len() {
        // Two ASCII hex digits, nothing else (`from_str_radix` alone also takes a sign).
        if v[i] == b'%'
            && i + 2 < v.len()
            && v[i + 1].is_ascii_hexdigit()
            && v[i + 2].is_ascii_hexdigit()
        {
            let hex = std::str::from_utf8(&v[i + 1..i + 3]).ok();
            if let Some(b) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(v[i]);
        i += 1;
    }
    out
}

/// `text` as a `grpc-message` value, for every `grpc-message` this door writes, on either accept
/// side. The encoding is tonic 0.14's `Status`: every control byte, every byte past ASCII, and each of
/// `` "#%<>`?{}`` and the space percent-encoded, upper-case hex; every other byte as it is.
#[must_use]
pub fn encode_status_message(text: &[u8]) -> String {
    let mut out = String::with_capacity(text.len());
    for &b in text {
        if (0x21..=0x7e).contains(&b) && !b"\"#%<>`?{}".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// A trailer block ended as a block: its last line closed, then the blank line.
pub fn terminate_block(bytes: &[u8]) -> Vec<u8> {
    let mut block = bytes.to_vec();
    if !block.ends_with(b"\r\n\r\n") {
        if !block.is_empty() && !block.ends_with(b"\r\n") {
            block.extend_from_slice(b"\r\n");
        }
        block.extend_from_slice(b"\r\n");
    }
    block
}

/// A stream's closing status lines in tonic 0.14's bytes and order (`Status::add_header`):
/// `grpc-status`, then `grpc-message` where there is a message, then `grpc-status-details-bin`
/// where there are details, the value the plane wrote, verbatim. A refusal's words and its neutral
/// status's mapping are this door's own ([`refusal_message`], [`status_of_refusal`]; tonic has no
/// refusal), and the details go out as the value the plane wrote (already the unpadded base64
/// tonic wrote of the raw bytes).
///
/// # Errors
///
/// The details are not one field value (a byte outside visible ASCII and the space).
pub fn status_lines(code: u32, message: &[u8], details: &[u8]) -> Result<Vec<u8>, &'static str> {
    if !details.iter().all(|b| (0x20..=0x7e).contains(b)) {
        return Err("the status details are not one field value");
    }
    let mut out = format!("{GRPC_STATUS}: {code}\r\n").into_bytes();
    if !message.is_empty() {
        out.extend_from_slice(
            format!("grpc-message: {}\r\n", encode_status_message(message)).as_bytes(),
        );
    }
    if !details.is_empty() {
        out.extend_from_slice(b"grpc-status-details-bin: ");
        out.extend_from_slice(details);
        out.extend_from_slice(b"\r\n");
    }
    Ok(out)
}

/// A head block, read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Head {
    /// Every field line but `content-length`, in order.
    pub fields: Vec<(String, Vec<u8>)>,
    /// The message stream's length, when the block states it.
    pub content_length: Option<usize>,
}

impl Head {
    /// The value of the first field named `name` (any case).
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.fields
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_slice())
    }
}

/// Read a head block off the front of `buf`: `Ok(None)` while it is incomplete, else the head and
/// how many bytes of `buf` it took.
///
/// # Errors
///
/// A line is not `name: value`, or `content-length` is not a number.
pub fn read_head(buf: &[u8], max: usize) -> Result<Option<(Head, usize)>, String> {
    // An empty block is the blank line alone; otherwise the block ends at the first blank line.
    let (lines, took) = if buf.starts_with(b"\r\n") {
        (&buf[..0], 2)
    } else if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        (&buf[..p], p + 4)
    } else {
        if buf.len() > max {
            return Err("the head block is over the ceiling".into());
        }
        return Ok(None);
    };
    let mut head = Head::default();
    for line in lines.split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let colon = line
            .iter()
            .position(|b| *b == b':')
            .ok_or("a head line is not a field")?;
        let name = std::str::from_utf8(&line[..colon])
            .map_err(|_| "a field name is not text")?
            .trim()
            .to_ascii_lowercase();
        let value = line[colon + 1..].trim_ascii().to_vec();
        if name.is_empty() {
            return Err("a field has no name".into());
        }
        if name == "content-length" {
            let n = std::str::from_utf8(&value)
                .ok()
                .and_then(|s| s.parse().ok())
                .ok_or("content-length is not a number")?;
            head.content_length = Some(n);
        } else {
            head.fields.push((name, value));
        }
    }
    Ok(Some((head, took)))
}

/// Render a head block: `fields`, then `content-length` when given, then the blank line.
///
/// # Errors
///
/// A name or value carries a CR, an LF or a NUL (it would end a line the caller does not own).
pub fn render_head(
    fields: &[(&str, &[u8])],
    content_length: Option<usize>,
) -> Result<Vec<u8>, &'static str> {
    let clean = |v: &[u8]| !v.iter().any(|b| matches!(b, b'\r' | b'\n' | 0));
    let mut out = Vec::new();
    for (name, value) in fields {
        if name.is_empty() || name.contains(':') || !clean(name.as_bytes()) || !clean(value) {
            return Err("a field cannot be written as one head line");
        }
        if name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value);
        out.extend_from_slice(b"\r\n");
    }
    if let Some(n) = content_length {
        out.extend_from_slice(format!("content-length: {n}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    Ok(out)
}

#[cfg(test)]
#[path = "tests/msg_tests.rs"]
mod tests;
