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
pub const CONTENT_TYPE: &str = "application/grpc";

/// Whether `v` is a gRPC content type: `application/grpc`, or it followed by `+` or `;`.
#[must_use]
pub fn is_grpc_content_type(v: &[u8]) -> bool {
    let base = CONTENT_TYPE.as_bytes();
    v.len() >= base.len()
        && v[..base.len()].eq_ignore_ascii_case(base)
        && matches!(v.get(base.len()), None | Some(b'+' | b';'))
}

/// The prefix of a message whose payload is `len` bytes; `None` past `u32::MAX`, a length no
#[must_use]
pub fn prefix(len: usize) -> Option<[u8; PREFIX]> {
    let n = u32::try_from(len).ok()?.to_be_bytes();
    Some([0, n[0], n[1], n[2], n[3]])
}

/// `payload` in its length-prefixed form.
#[cfg(test)]
pub fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PREFIX + payload.len());
    out.extend_from_slice(&prefix(payload.len()).expect("a test payload is short"));
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
    #[must_use]
    pub fn status(&self) -> u16 {
        match self {
            Self::TooLarge(..) => RESOURCE_EXHAUSTED,
            Self::Encoding(_) => UNIMPLEMENTED,
            Self::Compressed | Self::Truncated => INTERNAL,
        }
    }

    /// The closing status lines a call this failed closes with ([`status_lines`]): for a compression
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
#[must_use]
pub fn unsupported_encoding(v: &[u8]) -> Option<Bad> {
    if v == b"identity" {
        return None;
    }

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
    /// The stream is not one: every later push answers this, and nothing more is held.
    failed: Option<Bad>,
}

impl Messages {
    /// A cutter whose messages are at most `max` payload bytes.
    #[must_use]
    pub fn new(max: usize) -> Self {
        Self {
            buf: BytesMut::new(),
            max,
            failed: None,
        }
    }

    /// Take `bytes`, and answer every message they complete (each in its length-prefixed form).
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Bytes>, Bad> {
        self.push_bytes(Bytes::copy_from_slice(bytes))
    }

    /// [`Messages::push`] for bytes already shared: with nothing held back, each whole message in
    pub fn push_bytes(&mut self, mut data: Bytes) -> Result<Vec<Bytes>, Bad> {
        if let Some(e) = &self.failed {
            return Err(e.clone());
        }
        let cut = if self.buf.is_empty() {
            self.whole(&data).map(|lens| {
                let out = lens.into_iter().map(|n| data.split_to(n)).collect();
                self.buf.extend_from_slice(&data);
                out
            })
        } else {
            self.buf.extend_from_slice(&data);
            self.whole(&self.buf).map(|lens| {
                lens.into_iter()
                    .map(|n| self.buf.split_to(n).freeze())
                    .collect()
            })
        };
        cut.inspect_err(|e| {
            self.failed = Some(e.clone());
            self.buf = BytesMut::new();
        })
    }

    /// THE ONE CUT: the length (prefix and payload) of each whole message off the front of `data`,
    fn whole(&self, data: &[u8]) -> Result<Vec<usize>, Bad> {
        let mut lens = Vec::new();
        let mut rest = data;
        while rest.len() >= PREFIX {
            if rest[0] != 0 {
                return Err(Bad::Compressed);
            }
            let n = u32::from_be_bytes([rest[1], rest[2], rest[3], rest[4]]) as usize;

            let Some(len) = PREFIX.checked_add(n).filter(|_| n <= self.max) else {
                return Err(Bad::TooLarge(n, self.max));
            };
            if rest.len() < len {
                break;
            }
            lens.push(len);
            rest = &rest[len..];
        }
        Ok(lens)
    }

    /// The stream ended.
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
#[must_use]
pub fn status_of_http(code: u16) -> u16 {
    use http::StatusCode;

    match code {
        c if c == StatusCode::BAD_REQUEST.as_u16() => INTERNAL,
        c if c == StatusCode::UNAUTHORIZED.as_u16() => UNAUTHENTICATED,
        c if c == StatusCode::FORBIDDEN.as_u16() => PERMISSION_DENIED,
        c if c == StatusCode::NOT_FOUND.as_u16() => UNIMPLEMENTED,
        c if c == StatusCode::TOO_MANY_REQUESTS.as_u16()
            || c == StatusCode::BAD_GATEWAY.as_u16()
            || c == StatusCode::SERVICE_UNAVAILABLE.as_u16()
            || c == StatusCode::GATEWAY_TIMEOUT.as_u16() =>
        {
            UNAVAILABLE
        }
        _ => UNKNOWN,
    }
}

/// The `grpc-status` an HTTP/2 error `code` stands for on a dialled stream it ended (a reset or a
#[must_use]
pub fn status_of_reset(code: u32) -> u16 {
    match h2::Reason::from(code) {
        reason if reason == h2::Reason::REFUSED_STREAM => UNAVAILABLE,
        reason if reason == h2::Reason::CANCEL => CANCELLED,
        reason if reason == h2::Reason::ENHANCE_YOUR_CALM => RESOURCE_EXHAUSTED,
        reason if reason == h2::Reason::INADEQUATE_SECURITY => PERMISSION_DENIED,
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
#[must_use]
pub fn status_of_refusal(status: u32) -> u16 {
    match status {
        s if s == u32::from(http::StatusCode::PAYLOAD_TOO_LARGE.as_u16()) => RESOURCE_EXHAUSTED,
        s => u16::try_from(s).map_or(UNKNOWN, status_of_http),
    }
}

/// The `grpc-message` a refusal's neutral status ends a call with when its trailer block states
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
        .filter(|c| *c <= UNAUTHENTICATED)
        .unwrap_or(UNKNOWN)
}

/// The most bytes of a far end's `grpc-message` handed to the host as a failure's text.
pub const MESSAGE_TEXT_MAX: usize = 4096;

/// `grpc-message`, percent-decoded (a malformed escape stays as it was sent).
#[must_use]
pub fn decode_message(v: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len());
    let mut i = 0;
    while i < v.len() {
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

/// A far end's `grpc-message` value as the text the host is handed for the call's failure:
#[must_use]
pub fn message_text(v: &[u8]) -> Vec<u8> {
    let decoded = decode_message(v);
    let mut out = String::with_capacity(decoded.len().min(MESSAGE_TEXT_MAX));
    for c in String::from_utf8_lossy(&decoded).chars() {
        let before = out.len();
        if c.is_control() {
            out.extend(c.escape_debug());
        } else {
            out.push(c);
        }
        if out.len() > MESSAGE_TEXT_MAX {
            out.truncate(before);
            break;
        }
    }
    out.into_bytes()
}

/// `text` as a `grpc-message` value, for every `grpc-message` this door writes, on either accept
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

/// A refusal's bytes read as a trailer block: the block, where it states a `grpc-status`; `None`
pub fn refusal_block(bytes: &[u8]) -> Result<Option<Head>, String> {
    match read_head(&terminate_block(bytes), usize::MAX) {
        Ok(Some((h, _))) => Ok(h.get(GRPC_STATUS).is_some().then_some(h)),
        Ok(None) => Ok(None),
        Err(why) => {
            let status_line = |line: &[u8]| {
                let line = line.trim_ascii_start();
                line.len() > GRPC_STATUS.len()
                    && line[..GRPC_STATUS.len()].eq_ignore_ascii_case(GRPC_STATUS.as_bytes())
                    && line[GRPC_STATUS.len()..]
                        .trim_ascii_start()
                        .starts_with(b":")
            };
            if bytes.split(|b| *b == b'\n').any(status_line) {
                Err(format!(
                    "the trailer block names grpc-status but is not a field block: {why}"
                ))
            } else {
                Ok(None)
            }
        }
    }
}

/// A stream's closing status lines in tonic 0.14's bytes and order (`Status::add_header`):
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

/// A head's values are wiped when it drops: a dialled head carries the auth's credential lines.
impl Drop for Head {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for (_, value) in &mut self.fields {
            value.zeroize();
        }
    }
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
pub fn read_head(buf: &[u8], max: usize) -> Result<Option<(Head, usize)>, String> {
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
