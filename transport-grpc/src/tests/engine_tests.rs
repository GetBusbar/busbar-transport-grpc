// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The engine, both sides at once: a dialled [`Conn`] and an accepted one wired back to back, the
//! test carrying each one's wire bytes to the other and holding the clock.

use std::time::Duration;

use crate::hyper_io::{Owed, Piece};

use super::{Conn, Posture};
use crate::msg;

const SEC: u64 = 1_000_000_000;

#[test]
fn credential_flags_reach_the_final_grpc_header_values_after_partial_head_reparse() {
    let mut c = Conn::dial("http://peer.test:50051", posture(), 0).unwrap();
    let bytes = call(
        "/svc/Method",
        &[
            ("X-Api-Key", b"dummy-one"),
            ("x-api-key", b"dummy-two"),
            ("x-public", b"visible"),
            ("content-type", b"application/grpc+json"),
        ],
        &[b"body"],
    );
    let fields =
        super::SensitiveFields::new(vec!["x-api-key".into(), "content-type".into()]).unwrap();
    c.emit_sensitive(1, &bytes[..7], false, 0, 0, fields)
        .unwrap();
    c.emit(
        3,
        &call("/public/Method", &[("x-api-key", b"public")], &[]),
        true,
        0,
        0,
    )
    .unwrap();
    c.emit(1, &bytes[7..], true, 0, 0).unwrap();
    let super::Side::Dial(dial) = &c.side else {
        panic!("a dialled connection")
    };
    let super::DStage::Queued(request) = &dial
        .calls
        .iter()
        .find(|(stream, _)| *stream == 1)
        .unwrap()
        .1
        .stage
    else {
        panic!("the real gRPC request was not built")
    };
    let values: Vec<_> = request.headers().get_all("x-api-key").iter().collect();
    assert_eq!(values.len(), 2);
    assert!(values.iter().all(|value| value.is_sensitive()));
    assert!(request.headers()["content-type"].is_sensitive());
    assert!(!request.headers()["x-public"].is_sensitive());
    let super::DStage::Queued(public) = &dial
        .calls
        .iter()
        .find(|(stream, _)| *stream == 3)
        .unwrap()
        .1
        .stage
    else {
        panic!("the public request was not built")
    };
    assert!(!public.headers()["x-api-key"].is_sensitive());
}

fn posture() -> Posture {
    Posture {
        keep_alive_interval: None,
        keep_alive_timeout: Duration::from_secs(10),
        adaptive_window: false,
        timeout: Duration::from_secs(300),
        max_message_bytes: 1 << 20,
    }
}

/// A call as `encode` renders it: the head block (its fields and the message stream's length),
/// then the messages.
fn call(path: &str, extra: &[(&str, &[u8])], messages: &[&[u8]]) -> Vec<u8> {
    let body: Vec<u8> = messages.iter().flat_map(|m| msg::frame(m)).collect();
    let mut fields: Vec<(&str, &[u8])> = vec![("path", path.as_bytes())];
    fields.extend_from_slice(extra);
    let mut out = msg::render_head(&fields, Some(body.len())).expect("a head");
    out.extend_from_slice(&body);
    out
}

struct Pair {
    d: Conn,
    a: Conn,
    now: u64,
    got_d: Vec<Piece>,
    got_a: Vec<Piece>,
}

impl Pair {
    fn new() -> Self {
        let now = 5 * SEC;
        Self {
            d: Conn::dial("http://peer.test:50051", posture(), now).expect("dial"),
            a: Conn::accept(posture(), now),
            now,
            got_d: Vec::new(),
            got_a: Vec::new(),
        }
    }

    /// Drive both ends and carry bytes between them until neither has anything to move.
    fn settle(&mut self) {
        for _ in 0..200 {
            self.d.drive(self.now);
            self.a.drive(self.now);
            let to_a = self.d.take_wire(usize::MAX);
            let to_d = self.a.take_wire(usize::MAX);
            self.got_d.extend(self.d.pieces().drain(..));
            self.got_a.extend(self.a.pieces().drain(..));
            if to_a.is_empty() && to_d.is_empty() {
                return;
            }
            self.a.ingest(&to_a, false);
            self.d.ingest(&to_d, false);
        }
        panic!("the pair never settled");
    }

    fn at(&mut self, t: u64) {
        self.now = t;
        self.settle();
    }
}

/// A stream's pieces, in order.
fn of(got: &[Piece], stream: u64) -> Vec<&Piece> {
    got.iter().filter(|p| p.stream == stream).collect()
}

/// The stream's head: its FIRST piece, a field block with no status code.
fn head(got: &[Piece], stream: u64) -> &Piece {
    let h = of(got, stream)[0];
    assert!(
        h.fields && h.status.is_none(),
        "the head comes first: {h:?}"
    );
    h
}

/// The stream's messages, then its empty end piece when the frames are over.
fn frames(got: &[Piece], stream: u64) -> Vec<&[u8]> {
    of(got, stream)
        .into_iter()
        .filter(|p| !p.fields && p.status.is_none() && !p.failed)
        .map(|p| p.bytes.as_ref())
        .collect()
}

/// The piece that states the stream's status: the trailers, or a failure no trailers came with.
fn terminal(got: &[Piece], stream: u64) -> Option<&Piece> {
    got.iter()
        .find(|p| p.stream == stream && p.status.is_some())
}

/// The stream's terminal piece after its trailers: empty on `OK`, else the failure.
fn last(got: &[Piece], stream: u64) -> Option<&Piece> {
    of(got, stream).last().copied()
}

/// A field block's value for `name`.
fn field(block: &[u8], name: &str) -> Option<Vec<u8>> {
    busbar_contract::abi::transport::fields::lines(block)
        .find(|(n, _)| n == &name.as_bytes())
        .map(|(_, v)| v.to_vec())
}

#[test]
fn a_unary_call_half_closes_and_its_answer_ends_with_status_ok() {
    let mut p = Pair::new();
    let c = call("/pkg.Svc/Say", &[("x-meta", b"one")], &[b"hello"]);
    p.d.emit(1, &c, true, 0, p.now).expect("emit");
    p.settle();

    let h = head(&p.got_a, 1);
    let words = h.head.as_ref().expect("an accepted head states its words");
    assert_eq!(words.method.as_ref(), b"POST");
    assert_eq!(words.target.as_ref(), b"/pkg.Svc/Say");
    assert_eq!(words.authority.as_ref(), b"peer.test:50051");
    assert_eq!(field(&h.bytes, "path"), None, "no pseudo-field");
    assert_eq!(
        field(&h.bytes, "content-type").as_deref(),
        Some(&b"application/grpc"[..])
    );
    assert_eq!(field(&h.bytes, "te"), None, "te is checked, then dropped");
    assert_eq!(field(&h.bytes, "x-meta").as_deref(), Some(&b"one"[..]));
    let a = frames(&p.got_a, 1);
    assert_eq!(a.len(), 2, "message, end: {a:?}");
    assert_eq!(a[0], msg::frame(b"hello").as_slice());
    assert!(a[1].is_empty(), "the far end's last");
    assert!(
        last(&p.got_a, 1).expect("the end").end,
        "said as the stream's end"
    );

    p.a.emit(1, b"\r\n", false, 0, p.now).expect("answer head");
    p.a.emit(1, &msg::frame(b"hi"), false, 0, p.now)
        .expect("answer message");
    p.a.end_call(1, b"grpc-status: 0\r\n", 0).expect("end");
    p.settle();

    let h = head(&p.got_d, 1);
    assert!(h.head.is_none(), "an h2 answer has no reason phrase");
    let d = frames(&p.got_d, 1);
    assert_eq!(d, vec![msg::frame(b"hi").as_slice(), &b""[..]]);
    let t = terminal(&p.got_d, 1).expect("the trailers");
    assert!(t.fields && !t.failed);
    assert_eq!(t.status, Some(0));
    assert_eq!(
        field(&t.bytes, "grpc-status"),
        None,
        "the status is the code"
    );
    let end = last(&p.got_d, 1).expect("a terminal piece");
    assert!(!end.fields && !end.failed && end.bytes.is_empty() && end.status.is_none());
    assert!(
        end.end,
        "the terminal piece is the stream's end (PIECE_END)"
    );
}

#[test]
fn without_the_half_close_a_unary_peer_never_sees_the_calls_end() {
    let mut p = Pair::new();
    let mut c = msg::render_head(&[("path", b"/pkg.Svc/Say")], None).expect("head");
    c.extend_from_slice(&msg::frame(b"hello"));
    p.d.emit(1, &c, false, 0, p.now).expect("emit");
    p.settle();
    let a = frames(&p.got_a, 1);
    assert_eq!(a.len(), 1, "the message only: {a:?}");
    assert!(
        !a.iter().any(|f| f.is_empty()),
        "no end without the half-close"
    );

    p.d.emit(1, b"", true, 0, p.now).expect("end");
    p.settle();
    assert!(frames(&p.got_a, 1).last().is_some_and(|f| f.is_empty()));
}

#[test]
fn a_server_stream_carries_each_message_as_its_own_frame() {
    let mut p = Pair::new();
    p.d.emit(1, &call("/pkg.Svc/List", &[], &[b"q"]), true, 0, p.now)
        .expect("emit");
    p.settle();
    p.a.emit(1, b"x-answer: yes\r\n\r\n", false, 0, p.now)
        .expect("head");
    for m in [&b"a"[..], b"bb", b""] {
        p.a.emit(1, &msg::frame(m), false, 0, p.now)
            .expect("message");
        p.settle();
    }
    p.a.end_call(1, b"grpc-status: 0\r\n", 0).expect("end");
    p.settle();
    assert_eq!(
        field(&head(&p.got_d, 1).bytes, "x-answer").as_deref(),
        Some(&b"yes"[..])
    );
    let d = frames(&p.got_d, 1);
    assert_eq!(
        d,
        vec![
            msg::frame(b"a").as_slice(),
            msg::frame(b"bb").as_slice(),
            msg::frame(b"").as_slice(),
            &b""[..],
        ]
    );
    assert_eq!(terminal(&p.got_d, 1).and_then(|t| t.status), Some(0));
}

#[test]
fn a_non_zero_status_fails_the_stream_with_the_decoded_message() {
    let mut p = Pair::new();
    p.d.emit(1, &call("/pkg.Svc/Get", &[], &[b"k"]), true, 0, p.now)
        .expect("emit");
    p.settle();
    p.a.emit(1, b"\r\n", false, 0, p.now).expect("head");
    p.a.end_call(1, b"grpc-status: 5\r\ngrpc-message: no%20such%20key\r\n", 0)
        .expect("end");
    p.settle();
    let t = terminal(&p.got_d, 1).expect("the trailers");
    assert_eq!((t.status, t.fields), (Some(5), true));
    let end = last(&p.got_d, 1).expect("terminal");
    assert!(end.failed);
    assert_eq!(end.bytes.as_ref(), b"no such key");
}

#[test]
fn a_trailers_only_answer_carries_its_status_in_the_head() {
    let mut p = Pair::new();
    p.d.emit(1, &call("/pkg.Svc/Get", &[], &[b"k"]), true, 0, p.now)
        .expect("emit");
    p.settle();

    p.a.end_call(1, b"grpc-status: 7\r\ngrpc-message: denied\r\n", 0)
        .expect("end");
    p.settle();
    assert!(frames(&p.got_d, 1).is_empty(), "no message");
    assert!(
        field(&head(&p.got_d, 1).bytes, "grpc-status").is_none(),
        "the status is the trailers' code"
    );
    let t = terminal(&p.got_d, 1).expect("the trailers");
    assert_eq!((t.status, t.fields), (Some(7), true));
    let end = last(&p.got_d, 1).expect("terminal");
    assert_eq!((end.failed, end.bytes.as_ref()), (true, &b"denied"[..]));
}

#[test]
fn a_refusal_without_a_status_is_unknown_with_its_text() {
    let mut p = Pair::new();
    p.d.emit(1, &call("/pkg.Svc/Get", &[], &[b"k"]), true, 0, p.now)
        .expect("emit");
    p.settle();
    p.a.end_call(1, b"it broke", 0).expect("end");
    p.settle();
    let t = terminal(&p.got_d, 1).expect("the trailers");
    assert_eq!(t.status, Some(msg::UNKNOWN));
    let end = last(&p.got_d, 1).expect("terminal");
    assert_eq!(end.bytes.as_ref(), b"it broke");
}

#[test]
fn a_refusal_naming_no_grpc_status_ends_with_its_neutral_status_mapped_as_predev() {
    for (status, code) in [
        (401, msg::UNAUTHENTICATED),
        (403, msg::PERMISSION_DENIED),
        (413, msg::RESOURCE_EXHAUSTED),
        (429, msg::UNAVAILABLE),
    ] {
        let mut p = Pair::new();
        p.d.emit(1, &call("/pkg.Svc/Get", &[], &[b"k"]), true, 0, p.now)
            .expect("emit");
        p.settle();
        p.a.end_call(1, b"", status).expect("end");
        p.settle();
        let t = terminal(&p.got_d, 1).expect("the trailers");
        assert_eq!(t.status, Some(code), "{status}");
        let end = last(&p.got_d, 1).expect("terminal");
        let words = format!("busbar answered HTTP {status}");
        assert_eq!(end.bytes.as_ref(), words.as_bytes());
    }
}

#[test]
fn a_trailer_block_stating_grpc_status_wins_over_the_neutral_status() {
    let mut p = Pair::new();
    p.d.emit(1, &call("/pkg.Svc/Get", &[], &[b"k"]), true, 0, p.now)
        .expect("emit");
    p.settle();
    p.a.end_call(1, b"grpc-status: 5\r\ngrpc-message: gone\r\n", 401)
        .expect("end");
    p.settle();
    let t = terminal(&p.got_d, 1).expect("the trailers");
    assert_eq!(t.status, Some(5));
    let end = last(&p.got_d, 1).expect("terminal");
    assert_eq!(end.bytes.as_ref(), b"gone");
}

#[test]
fn the_callers_deadline_fails_the_call_when_it_passes_and_never_goes_upstream() {
    let mut p = Pair::new();
    let t0 = p.now;
    p.d.emit(
        1,
        &call("/pkg.Svc/Slow", &[], &[b"q"]),
        true,
        t0 + 2 * SEC,
        t0,
    )
    .expect("emit");
    p.settle();
    assert_eq!(
        field(&head(&p.got_a, 1).bytes, "grpc-timeout"),
        None,
        "the deadline is held here, never sent upstream"
    );
    assert_eq!(
        p.d.next_deadline(),
        Some(t0 + 2 * SEC),
        "the host is asked back at the deadline"
    );
    p.at(t0 + 2 * SEC - 1);
    assert!(terminal(&p.got_d, 1).is_none(), "not before the deadline");
    p.at(t0 + 2 * SEC);
    let t = terminal(&p.got_d, 1).expect("terminal");
    assert_eq!(t.status, Some(msg::DEADLINE_EXCEEDED));
    assert!(t.failed);
    assert!(p.d.failure().is_none(), "the connection lives on");
}

/// AN ACCEPTED CALL'S `grpc-timeout` IS A FACT FOR THE PLANE, NEVER ENFORCED HERE, as predev's
/// server enforced none: it is handed up among the head's fields, and long past it the call is
/// still open, with no `DEADLINE_EXCEEDED` from this side.
#[test]
fn an_accepted_calls_grpc_timeout_is_handed_up_and_never_enforced() {
    let mut a = Conn::accept(posture(), 5 * SEC);
    a.ingest(
        &opening_with(Some("trailers"), &[("grpc-timeout", "1m")]),
        false,
    );
    a.drive(5 * SEC);
    let got: Vec<Piece> = a.pieces().drain(..).collect();
    assert_eq!(
        field(&head(&got, 1).bytes, "grpc-timeout").as_deref(),
        Some(&b"1m"[..]),
        "the caller's deadline reaches the plane"
    );
    assert_eq!(a.next_deadline(), None, "no timer is asked for");
    a.drive(60 * SEC);
    assert!(
        a.pieces().drain(..).all(|p| !p.failed),
        "nothing fails the call"
    );
    assert_eq!(held(&a), 1, "the call is still open");
}

#[test]
fn two_calls_share_one_connection() {
    let mut p = Pair::new();
    p.d.emit(1, &call("/pkg.Svc/A", &[], &[b"1"]), true, 0, p.now)
        .expect("emit");
    p.d.emit(3, &call("/pkg.Svc/B", &[], &[b"3"]), true, 0, p.now)
        .expect("emit");
    p.settle();

    let paths: Vec<_> = [1, 2]
        .iter()
        .map(|s| head(&p.got_a, *s).head.as_ref().map(|w| w.target.to_vec()))
        .collect();
    assert_eq!(
        paths,
        vec![Some(b"/pkg.Svc/A".to_vec()), Some(b"/pkg.Svc/B".to_vec())]
    );
    p.a.end_call(2, b"grpc-status: 0\r\n", 0).expect("end 2");
    p.a.end_call(1, b"grpc-status: 0\r\n", 0).expect("end 1");
    p.settle();
    assert_eq!(terminal(&p.got_d, 1).and_then(|t| t.status), Some(0));
    assert_eq!(terminal(&p.got_d, 3).and_then(|t| t.status), Some(0));
}

#[test]
fn a_bad_call_fails_its_own_stream_internal() {
    let mut p = Pair::new();
    let c = msg::render_head(&[("path", b"no-slash")], Some(0)).expect("head");
    p.d.emit(1, &c, true, 0, p.now).expect("emit");
    let t = terminal(&p.d.pieces().drain(..).collect::<Vec<_>>(), 1).cloned();
    let t = t.expect("terminal");
    assert_eq!(t.status, Some(msg::INTERNAL));
    assert!(t.failed);
}

#[test]
fn a_compressed_message_from_the_far_end_fails_the_call() {
    let mut p = Pair::new();
    let mut c = msg::render_head(&[("path", b"/pkg.Svc/Z")], Some(6)).expect("head");
    c.extend_from_slice(&[1, 0, 0, 0, 1, b'z']);
    p.d.emit(1, &c, true, 0, p.now).expect("emit");
    p.settle();
    let a = terminal(&p.got_a, 1).expect("the accepted side fails it");
    assert_eq!(a.status, Some(msg::INTERNAL));
    let d = terminal(&p.got_d, 1).expect("and answers the dialled side");
    assert_eq!(d.status, Some(msg::INTERNAL));
}

/// One HTTP/2 frame.
fn h2(ty: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let n = payload.len();
    let mut v = vec![(n >> 16) as u8, (n >> 8) as u8, n as u8, ty, flags];
    v.extend_from_slice(&stream.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// A client's preface and one HEADERS frame opening stream 1 with a gRPC call, `te` as given:
/// HPACK by hand (indexed and literal-without-indexing fields, no Huffman), so a field hyper's own
/// client would never send can be.
fn opening(te: Option<&str>) -> Vec<u8> {
    opening_with(te, &[])
}

/// [`opening`], with `extra` fields after `te`.
fn opening_with(te: Option<&str>, extra: &[(&str, &str)]) -> Vec<u8> {
    let lit = |out: &mut Vec<u8>, s: &str| {
        out.push(u8::try_from(s.len()).expect("short"));
        out.extend_from_slice(s.as_bytes());
    };
    let mut block = vec![0x83, 0x86];
    block.push(0x04);
    lit(&mut block, "/pkg.Svc/Say");
    block.push(0x01);
    lit(&mut block, "peer.test");
    block.extend_from_slice(&[0x0f, 0x10]);
    lit(&mut block, "application/grpc");
    if let Some(te) = te {
        block.push(0x00);
        lit(&mut block, "te");
        lit(&mut block, te);
    }
    for (name, value) in extra {
        block.push(0x00);
        lit(&mut block, name);
        lit(&mut block, value);
    }
    let mut out = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    out.extend(h2(4, 0, 0, &[]));

    out.extend(h2(1, 0x4, 1, &block));
    out
}

/// Every RST_STREAM (stream, error code) in `wire`, a server's frames.
fn resets(wire: &[u8]) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 9 <= wire.len() {
        let len =
            usize::from(wire[i]) << 16 | usize::from(wire[i + 1]) << 8 | usize::from(wire[i + 2]);
        let stream =
            u32::from_be_bytes([wire[i + 5], wire[i + 6], wire[i + 7], wire[i + 8]]) & 0x7fff_ffff;
        if wire[i + 3] == 3 && len == 4 && i + 13 <= wire.len() {
            out.push((
                stream,
                u32::from_be_bytes([wire[i + 9], wire[i + 10], wire[i + 11], wire[i + 12]]),
            ));
        }
        i += 9 + len;
    }
    out
}

/// A `te` value other than `trailers` is reset with HTTP/2 `PROTOCOL_ERROR` before admission.
#[test]
fn a_wrong_te_is_reset_protocol_error_and_never_handed_up() {
    let mut a = Conn::accept(posture(), 5 * SEC);
    a.ingest(&opening(Some("gzip")), false);
    a.drive(5 * SEC);
    let wire = a.take_wire(usize::MAX);
    assert_eq!(
        resets(&wire),
        vec![(1, 1)],
        "RST_STREAM PROTOCOL_ERROR on stream 1"
    );
    assert!(a.pieces().is_empty(), "no call reached the host");
}

/// A missing `te` is served, as predev's server served it: the call is handed up.
#[test]
fn a_missing_te_is_served() {
    let mut a = Conn::accept(posture(), 5 * SEC);
    a.ingest(&opening(None), false);
    a.drive(5 * SEC);
    let wire = a.take_wire(usize::MAX);
    assert!(resets(&wire).is_empty(), "no reset");
    let got: Vec<Piece> = a.pieces().drain(..).collect();
    let h = head(&got, 1);
    assert_eq!(
        h.head.as_ref().map(|w| w.target.as_ref()),
        Some(&b"/pkg.Svc/Say"[..])
    );

    let mut a = Conn::accept(posture(), 5 * SEC);
    a.ingest(&opening(Some("trailers")), false);
    a.drive(5 * SEC);
    let got: Vec<Piece> = a.pieces().drain(..).collect();
    assert_eq!(field(&head(&got, 1).bytes, "te"), None);
}

/// AN ANSWER THAT IS NOT gRPC IS STILL AN ANSWER. A member that answers a call with a bare HTTP
/// status (no `grpc-status`, as a proxy or an auth wall in front of the service does) has
/// answered: its status reaches the host as the gRPC status that HTTP status stands for
/// (`http-grpc-status-mapping.md`: 401 -> UNAUTHENTICATED, 403 -> PERMISSION_DENIED, 503 ->
/// UNAVAILABLE), on a head and its status block, exactly as a trailers-only answer arrives.
#[test]
fn a_bare_http_status_answer_is_an_answer_with_the_status_it_stands_for() {
    use busbar_contract::abi::transport::{FAULT_CALLER, FAULT_HARD, FAULT_TRANSIENT};

    for (http, grpc, fault) in [
        (401u16, msg::UNAUTHENTICATED, FAULT_HARD),
        (403, msg::PERMISSION_DENIED, FAULT_HARD),
        (503, msg::UNAVAILABLE, FAULT_TRANSIENT),
        (400, msg::INTERNAL, FAULT_CALLER),
        (409, msg::UNKNOWN, FAULT_CALLER),
        (500, msg::UNKNOWN, FAULT_TRANSIENT),
        (408, msg::UNKNOWN, FAULT_TRANSIENT),
        (
            429,
            msg::UNAVAILABLE,
            busbar_contract::abi::transport::FAULT_RATE_LIMIT,
        ),
        (599, msg::UNKNOWN, FAULT_TRANSIENT),
        (404, msg::UNIMPLEMENTED, FAULT_CALLER),
    ] {
        let now = 5 * SEC;
        let mut d = Conn::dial("http://peer.test:50051", posture(), now).expect("dial");
        d.emit(1, &call("/pkg.Svc/Get", &[], &[b"k"]), true, 0, now)
            .expect("emit");
        let mut got: Vec<Piece> = Vec::new();
        let turn = |d: &mut Conn, got: &mut Vec<Piece>| {
            for _ in 0..20 {
                d.drive(now);
                let _ = d.take_wire(usize::MAX);
                got.extend(d.pieces().drain(..));
            }
        };

        turn(&mut d, &mut got);
        let mut wire = h2(4, 0, 0, &[]);
        wire.extend(h2(4, 1, 0, &[]));
        d.ingest(&wire, false);
        turn(&mut d, &mut got);
        let code = http.to_string();
        let mut block = vec![0x08, 3];
        block.extend_from_slice(code.as_bytes());
        d.ingest(&h2(1, 0x05, 1, &block), false);
        turn(&mut d, &mut got);
        head(&got, 1);
        let t = terminal(&got, 1).expect("the answer's status");
        assert_eq!(
            (t.status, t.fields),
            (Some(grpc), true),
            "HTTP {http}: {got:?}"
        );
        assert_eq!(t.fault, Some(fault), "HTTP {http}: the HTTP band's reading");
        let end = last(&got, 1).expect("terminal");
        assert_eq!(
            (end.failed, end.bytes.as_ref()),
            (true, format!("HTTP status {http}").as_bytes()),
            "HTTP {http}"
        );
    }
}

/// AN EARLY ANSWER RESETS THE REQUEST STILL BEING SENT: a far end that answers a bare HTTP status
/// (or trailers-only) before the host has finished its request sends no RST_STREAM, so the dialler
/// must reset the stream itself rather than hold the request body, the send half and the
/// concurrency slot until the connection closes.
#[test]
fn an_early_answer_resets_the_request_still_being_sent() {
    let now = 5 * SEC;
    let mut d = Conn::dial("http://peer.test:50051", posture(), now).expect("dial");
    // A head stating 1000 bytes of messages, and one message of them: the request is not whole.
    let mut bytes = msg::render_head(&[("path", b"/pkg.Svc/Get")], Some(1000)).expect("a head");
    bytes.extend_from_slice(&msg::frame(b"k"));
    d.emit(1, &bytes, false, 0, now).expect("emit");
    // The client connection preface (24 bytes) leads the wire, ahead of its frames.
    const PREFACE: usize = 24;
    let mut sent: Vec<u8> = Vec::new();
    let turn = |d: &mut Conn, sent: &mut Vec<u8>| {
        for _ in 0..20 {
            d.drive(now);
            sent.extend(d.take_wire(usize::MAX));
            d.pieces().clear();
        }
    };
    turn(&mut d, &mut sent);
    let mut wire = h2(4, 0, 0, &[]);
    wire.extend(h2(4, 1, 0, &[]));
    d.ingest(&wire, false);
    turn(&mut d, &mut sent);
    assert!(
        !frame_types(&sent[PREFACE..]).contains(&3),
        "no RST_STREAM while the call is open"
    );
    // The far end answers a bare 503 ending the stream, without resetting ours.
    d.ingest(&h2(1, 0x05, 1, &[0x08, 3, b'5', b'0', b'3']), false);
    turn(&mut d, &mut sent);
    assert!(
        frame_types(&sent[PREFACE..]).contains(&3),
        "the unfinished request is reset: {:?}",
        frame_types(&sent[PREFACE..])
    );
}

/// A DIALLED CALL THE FRAMER CANNOT BUILD IS THE CALLER'S FAULT, NOT THE FAR END'S: a head stating
/// a non-gRPC content type builds no request, nothing was sent, and the far end's breaker must not
/// be charged a transient fault for it.
#[test]
fn a_dialled_call_that_cannot_be_built_is_the_callers_fault() {
    use busbar_contract::abi::transport::FAULT_CALLER;
    let now = 5 * SEC;
    let mut d = Conn::dial("http://peer.test:50051", posture(), now).expect("dial");
    d.emit(
        1,
        &call("/pkg.Svc/Get", &[("content-type", b"text/plain")], &[b"k"]),
        true,
        0,
        now,
    )
    .expect("emit");
    let got: Vec<Piece> = d.pieces().drain(..).collect();
    let t = terminal(&got, 1).expect("the stream fails");
    assert!(t.failed, "{t:?}");
    assert_eq!(t.fault, Some(FAULT_CALLER), "{t:?}");
}

/// The calls an accepted connection still holds.
fn held(c: &Conn) -> usize {
    match &c.side {
        super::Side::Accept(a) => a.calls.len(),
        super::Side::Dial(d) => d.calls.len(),
    }
}

/// A client that opened stream 1, sent its one message and half-closed (END_STREAM on the DATA).
fn half_closed() -> Conn {
    let mut a = Conn::accept(posture(), 5 * SEC);
    let mut wire = opening(Some("trailers"));
    wire.extend(h2(0, 0x1, 1, &msg::frame(b"q")));
    a.ingest(&wire, false);
    a.drive(5 * SEC);
    let got: Vec<Piece> = a.pieces().drain(..).collect();
    assert!(
        last(&got, 1).is_some_and(|p| p.end && p.bytes.is_empty() && !p.failed),
        "the far end's last: {got:?}"
    );
    a
}

/// The client cancels stream 1 (RST_STREAM CANCEL); what the accepted side hands up.
fn cancel(a: &mut Conn) -> Vec<Piece> {
    drop(a.take_wire(usize::MAX));
    a.ingest(&h2(3, 0, 1, &8u32.to_be_bytes()), false);
    a.drive(5 * SEC);
    a.pieces().drain(..).collect()
}

/// A CLIENT'S CANCEL AFTER ITS HALF-CLOSE IS TOLD TO THE HOST. The client sent its last message,
/// the host is streaming the answer, and the client resets the call: the host hears it as the
/// stream failing `CANCELLED`, the call is let go of, and an answer emitted after it (or a refusal
/// racing the cancel) is dropped, as a STREAM ENDS ONCE says: the op is answered, nothing is queued.
#[test]
fn a_cancel_after_the_half_close_fails_the_stream_cancelled() {
    let mut a = half_closed();
    a.emit(1, b"\r\n", false, 0, 5 * SEC).expect("answer head");
    a.emit(1, &msg::frame(b"one"), false, 0, 5 * SEC)
        .expect("a message");
    a.drive(5 * SEC);
    let got = cancel(&mut a);
    let t = terminal(&got, 1).expect("the host hears the cancel");
    assert!(t.failed, "the stream failed: {t:?}");
    assert_eq!(t.status, Some(msg::CANCELLED));
    assert_eq!(held(&a), 0, "the call is let go of");
    assert_eq!(
        a.emit(1, &msg::frame(b"two"), false, 0, 5 * SEC),
        Ok(()),
        "a late emit is dropped"
    );
    assert_eq!(
        a.end_call(1, b"grpc-status: 0\r\n", 0),
        Ok(()),
        "a late refusal is dropped"
    );
    a.drive(5 * SEC);
    assert!(a.pieces().is_empty(), "one terminal piece, once");
    assert_eq!(held(&a), 0, "nothing reopened");
    assert!(
        a.emit(9, b"\r\n", false, 0, 5 * SEC).is_err(),
        "a stream that never was is still no stream"
    );
}

/// The same cancel, before the host stated the answer's head: the connection drops the call's
/// pending answer, and the host hears `CANCELLED` all the same.
#[test]
fn a_cancel_before_the_answer_fails_the_stream_cancelled() {
    let mut a = half_closed();
    let got = cancel(&mut a);
    let t = terminal(&got, 1).expect("the host hears the cancel");
    assert!(t.failed);
    assert_eq!(t.status, Some(msg::CANCELLED));
    assert_eq!(held(&a), 0);
}

/// A call answered in full is not a cancel: its body is let go of only after its end.
#[test]
fn an_answered_call_is_never_reported_cancelled() {
    let mut a = half_closed();
    a.emit(1, b"\r\n", false, 0, 5 * SEC).expect("answer head");
    a.emit(1, &msg::frame(b"one"), false, 0, 5 * SEC)
        .expect("a message");
    a.end_call(1, b"grpc-status: 0\r\n", 0).expect("end");
    a.drive(5 * SEC);
    drop(a.take_wire(usize::MAX));
    a.drive(5 * SEC);
    let got: Vec<Piece> = a.pieces().drain(..).collect();
    assert!(
        got.iter().all(|p| !p.failed),
        "no failure for an answered call: {got:?}"
    );
    assert_eq!(held(&a), 0);
}

/// A LATE EMIT ON A DIALLED STREAM THAT ENDED IS DROPPED. The far end answers a client-streaming
/// call early (trailers-only, before the upload is done); the host's next message and its end
/// arrive after the stream's terminal piece.
#[test]
fn a_late_emit_on_an_ended_dialled_stream_opens_nothing() {
    let mut p = Pair::new();
    let mut c = msg::render_head(&[("path", b"/pkg.Svc/Upload")], None).expect("head");
    c.extend_from_slice(&msg::frame(b"part one"));
    p.d.emit(1, &c, false, 0, p.now).expect("emit");
    p.settle();
    p.a.end_call(1, b"grpc-status: 7\r\ngrpc-message: no\r\n", 0)
        .expect("refuse early");
    p.settle();
    let before = of(&p.got_d, 1).len();
    assert_eq!(
        terminal(&p.got_d, 1).and_then(|t| t.status),
        Some(7),
        "the early answer"
    );
    assert_eq!(held(&p.d), 0, "the stream ended");

    p.d.emit(1, &msg::frame(b"part two"), false, 0, p.now)
        .expect("a late message is taken and dropped");
    p.d.emit(1, b"", true, 0, p.now).expect("a late end too");
    p.settle();
    let t = p.now;
    p.at(t + 301 * SEC);
    assert_eq!(
        of(&p.got_d, 1).len(),
        before,
        "nothing more on the ended stream: {:?}",
        of(&p.got_d, 1)
    );
    assert_eq!(held(&p.d), 0, "no call was opened");
}

/// Ended ids are kept as runs, and every id is judged exactly.
#[test]
fn ended_streams_are_remembered_as_runs() {
    let mut e = super::Ended::default();
    for id in [1, 2, 3, 5, 4, 9] {
        e.insert(id);
    }
    assert_eq!(e.0.len(), 2, "1..=5 and 9: {:?}", e.0);
    for id in [1, 3, 5, 9] {
        assert!(e.contains(id), "{id}");
    }
    for id in [0, 6, 8, 10] {
        assert!(!e.contains(id), "{id}");
    }
    e.insert(u64::MAX);
    assert!(e.contains(u64::MAX) && !e.contains(u64::MAX - 1));
}

/// The answer bytes an accepted call still queues for the far end, framer-side (not yet taken by
/// the HTTP/2 connection, which takes them only as the far end grants room).
fn queued_answer(c: &Conn, stream: u64) -> usize {
    let super::Side::Accept(a) = &c.side else {
        panic!("an accepted connection");
    };
    a.calls
        .iter()
        .find(|(id, _)| *id == stream)
        .map_or(0, |(_, s)| {
            s.reply
                .chan
                .0
                .lock()
                .expect("chan")
                .frames
                .iter()
                .filter_map(|f| f.data_ref().map(bytes::Bytes::len))
                .sum()
        })
}

/// AN ANSWER THE FAR END NEVER READS IS BOUNDED. The client half-closed its call and then grants
/// no room (no WINDOW_UPDATE), while the host keeps emitting the answer: the framer holds at most
/// its bound for the stream, and a host that emits past it hears the stream fail
/// `RESOURCE_EXHAUSTED` (the transport ABI's "A STREAM'S OWN BACKPRESSURE": "A host that keeps
/// emitting past the mark is the framer's to bound: it may fail the stream").
#[test]
fn an_answer_the_far_end_never_reads_is_bounded_and_fails_resource_exhausted() {
    let mut a = half_closed();
    a.emit(1, b"\r\n", false, 0, 5 * SEC).expect("answer head");
    let m = msg::frame(&[7u8; 60_000]);
    let (mut most, mut got) = (0, Vec::new());
    for _ in 0..200 {
        let _ = a.emit(1, &m, false, 0, 5 * SEC);
        a.drive(5 * SEC);
        drop(a.take_wire(usize::MAX));
        got.extend(a.pieces().drain(..));
        most = most.max(queued_answer(&a, 1));
    }
    assert!(
        most <= 3 << 20,
        "the framer held {most} bytes for a stream nobody reads"
    );
    let t = terminal(&got, 1).expect("the host hears the stream fail");
    assert!(t.failed, "the stream failed: {t:?}");
    assert_eq!(t.status, Some(msg::RESOURCE_EXHAUSTED));
}

/// A FULL STREAM IS SAID, AND SO IS ITS DRAIN. The host emits an answer the far end grants no room
/// for, until an emit leaves the queue at its high-water mark: that emit is answered full
/// (`YIELD_STREAM_FULL`, which the door sets from [`Conn::announce_full`]), and nothing fails.
#[test]
fn a_full_answer_is_announced_and_its_drain_hands_one_writable_piece() {
    let mut a = half_closed();
    a.emit(1, b"\r\n", false, 0, 5 * SEC).expect("answer head");
    let m = msg::frame(&[7u8; 60_000]);
    let mut got = Vec::new();
    let mut full = false;
    for _ in 0..40 {
        a.emit(1, &m, false, 0, 5 * SEC).expect("a message");
        a.drive(5 * SEC);
        drop(a.take_wire(usize::MAX));
        got.extend(a.pieces().drain(..));
        if a.announce_full(1) {
            full = true;
            break;
        }
    }
    assert!(full, "the queue reached its high-water mark");
    assert!(
        queued_answer(&a, 1) >= super::STREAM_HIGH_WATER,
        "full means at the mark"
    );
    assert!(
        got.iter().all(|p| !p.writable && !p.failed),
        "no writable piece and no failure before the drain: {got:?}"
    );

    let room = (1u32 << 30).to_be_bytes();
    let mut wire = h2(8, 0, 0, &room);
    wire.extend(h2(8, 0, 1, &room));
    a.ingest(&wire, false);
    for _ in 0..100 {
        a.drive(5 * SEC);
        drop(a.take_wire(usize::MAX));
        got.extend(a.pieces().drain(..));
    }
    assert!(queued_answer(&a, 1) <= super::STREAM_LOW_WATER, "drained");
    let writable: Vec<_> = got.iter().filter(|p| p.writable).collect();
    assert_eq!(writable.len(), 1, "one writable piece: {got:?}");
    assert_eq!(writable[0].stream, 1);
    assert!(writable[0].bytes.is_empty());
    assert!(!a.announce_full(1), "no longer full");
}

/// The request bytes a dialled call still queues for the far end, framer-side.
fn queued_request(c: &Conn, stream: u64) -> usize {
    let super::Side::Dial(d) = &c.side else {
        panic!("a dialled connection");
    };
    d.calls
        .iter()
        .find(|(id, _)| *id == stream)
        .map_or(0, |(_, s)| {
            s.chan
                .0
                .lock()
                .expect("chan")
                .frames
                .iter()
                .filter_map(|f| f.data_ref().map(bytes::Bytes::len))
                .sum()
        })
}

/// The same bound on a dialled call: an upload whose far end grants no room (its SETTINGS and
/// nothing more) is held to the bound, and fails `RESOURCE_EXHAUSTED` past it.
#[test]
fn an_upload_the_far_end_never_reads_is_bounded_and_fails_resource_exhausted() {
    let now = 5 * SEC;
    let mut d = Conn::dial("http://peer.test:50051", posture(), now).expect("dial");
    let mut c = msg::render_head(&[("path", b"/pkg.Svc/Upload")], None).expect("head");
    c.extend_from_slice(&msg::frame(b"first"));
    d.emit(1, &c, false, 0, now).expect("open the call");
    let (mut most, mut got) = (0, Vec::new());
    let turn = |d: &mut Conn, got: &mut Vec<Piece>| {
        d.drive(now);
        drop(d.take_wire(usize::MAX));
        got.extend(d.pieces().drain(..));
    };
    turn(&mut d, &mut got);

    let mut wire = h2(4, 0, 0, &[]);
    wire.extend(h2(4, 1, 0, &[]));
    d.ingest(&wire, false);
    turn(&mut d, &mut got);
    let m = msg::frame(&[7u8; 60_000]);
    for _ in 0..200 {
        let _ = d.emit(1, &m, false, 0, now);
        turn(&mut d, &mut got);
        most = most.max(queued_request(&d, 1));
    }
    assert!(
        most <= 3 << 20,
        "the framer held {most} bytes for an upload nobody reads"
    );
    let t = terminal(&got, 1).expect("the host hears the stream fail");
    assert!(t.failed, "the stream failed: {t:?}");
    assert_eq!(t.status, Some(msg::RESOURCE_EXHAUSTED));
}

/// The `grpc-message` an accepted call's end carries, as it goes on the wire: in the head of a
/// trailers-only answer, or in the trailers after one.
fn sent_message(c: &Conn, stream: u64) -> Option<Vec<u8>> {
    let super::Side::Accept(a) = &c.side else {
        panic!("an accepted connection");
    };
    let (_, s) = a.calls.iter().find(|(id, _)| *id == stream)?;
    if let Some((_, h)) = s.reply.state.lock().expect("reply").head.as_ref() {
        if let Some(v) = h.get(msg::GRPC_MESSAGE) {
            return Some(v.as_bytes().to_vec());
        }
    }
    let st = s.reply.chan.0.lock().expect("chan");
    st.frames
        .iter()
        .filter_map(|f| f.trailers_ref())
        .find_map(|t| t.get(msg::GRPC_MESSAGE))
        .map(|v| v.as_bytes().to_vec())
}

/// A REFUSAL'S `grpc-message` IS PREDEV'S BYTES. A refusal naming no `grpc-status` ends the call
/// with its neutral status mapped and predev's words, percent-encoded as predev's gRPC line
/// (tonic 0.14's `Status`) encoded them: the space and each of `"#%<>`?{}` beside the controls.
/// Both shapes: trailers-only, and trailers after the answer's head.
#[test]
fn a_refusals_grpc_message_is_percent_encoded_in_predevs_bytes() {
    let mut a = half_closed();
    a.end_call(1, b"", 413).expect("refuse");
    assert_eq!(
        sent_message(&a, 1).as_deref(),
        Some(&b"busbar%20answered%20HTTP%20413"[..]),
        "trailers-only"
    );
    let mut a = half_closed();
    a.emit(1, b"\r\n", false, 0, 5 * SEC).expect("answer head");
    a.end_call(1, b"", 401).expect("refuse");
    assert_eq!(
        sent_message(&a, 1).as_deref(),
        Some(&b"busbar%20answered%20HTTP%20401"[..]),
        "trailers after the head"
    );
}

/// AN OVERSIZE MESSAGE FAILS `RESOURCE_EXHAUSTED` NAMING THE LIMIT. A call whose message states a length
/// past the ceiling (`limits.request_body_max_bytes`, the knob that bounds every inbound body)
/// fails `RESOURCE_EXHAUSTED` (code 8) in this framer's own words, which print that configured ceiling
/// Both ends see it: the accepted side's failure piece, and the dialled
/// side's trailers and decoded message.
#[test]
fn an_oversize_message_fails_resource_exhausted_naming_the_limit_on_the_accepted_side() {
    let mut p = Pair::new();
    let limit = posture().max_message_bytes;
    let over = u32::try_from(limit + 1).expect("small");
    let mut c = msg::render_head(&[("path", b"/pkg.Svc/Big")], Some(5)).expect("head");
    c.push(0);
    c.extend_from_slice(&over.to_be_bytes());
    p.d.emit(1, &c, true, 0, p.now).expect("emit");
    p.settle();
    let words = format!(
        "the message is {over} bytes, over the limit of {limit} bytes \
         (limits.request_body_max_bytes)"
    );
    let a = terminal(&p.got_a, 1).expect("the accepted side fails it");
    assert!(a.failed, "{a:?}");
    assert_eq!(
        a.status,
        Some(msg::RESOURCE_EXHAUSTED),
        "RESOURCE_EXHAUSTED"
    );
    assert_eq!(a.bytes.as_ref(), words.as_bytes());
    let t = terminal(&p.got_d, 1).expect("the dialled side's trailers");
    assert_eq!(
        t.status,
        Some(msg::RESOURCE_EXHAUSTED),
        "RESOURCE_EXHAUSTED"
    );
    let end = last(&p.got_d, 1).expect("terminal");
    assert!(end.failed);
    assert_eq!(end.bytes.as_ref(), words.as_bytes());
}

/// AN OVERSIZE ANSWER ON THE DIAL is `RESOURCE_EXHAUSTED` in this framer's own words: predev's hop had no
/// gRPC status for it (its refusal was `BodyTooLarge`), so nothing of predev's server is copied.
#[test]
fn an_oversize_answer_on_the_dial_fails_in_this_framers_words() {
    let mut p = open_call(false, b"");
    let limit = posture().max_message_bytes;
    let over = u32::try_from(limit + 1).expect("small");
    p.a.emit(1, b"\r\n", false, 0, p.now).expect("answer head");
    let mut prefix = vec![0u8];
    prefix.extend_from_slice(&over.to_be_bytes());
    p.a.emit(1, &prefix, false, 0, p.now)
        .expect("an oversize prefix");
    p.settle();
    let t = terminal(&p.got_d, 1).cloned().expect("the dial fails it");
    assert!(t.failed, "{t:?}");
    assert_eq!(t.status, Some(msg::RESOURCE_EXHAUSTED));
    assert_eq!(
        String::from_utf8_lossy(&t.bytes),
        format!(
            "the answer's message is {over} bytes, over the limit of {limit} bytes ({})",
            crate::meta::setting::BODY_MAX_BYTES
        )
    );
}

/// A dialled call on stream 1, sent whole and unanswered; with `after_head`, its answer's head is
/// in and its body still open (after `partial` bytes of a message, where any).
fn open_call(after_head: bool, partial: &[u8]) -> Pair {
    let mut p = Pair::new();
    p.d.emit(1, &call("/pkg.Svc/Say", &[], &[b"q"]), true, 0, p.now)
        .expect("emit");
    p.settle();
    if after_head {
        p.a.emit(1, b"\r\n", false, 0, p.now).expect("answer head");
        if !partial.is_empty() {
            p.a.emit(1, partial, false, 0, p.now)
                .expect("part of a message");
        }
        p.settle();
        head(&p.got_d, 1);
    }
    assert!(terminal(&p.got_d, 1).is_none(), "the call is still open");
    p
}

/// `frame` carried to the dialled side as the far end's own bytes; the stream's terminal piece.
fn far_end_sends(mut p: Pair, frame: &[u8]) -> Piece {
    p.d.ingest(frame, false);
    p.settle();
    let t = terminal(&p.got_d, 1).cloned().expect("the stream ends");
    assert!(t.failed, "the stream fails: {t:?}");
    t
}

/// The status and text a far end's RST_STREAM `code` fails the dialled stream with, before the
/// answer's head and after it.
fn reset_both_ways(code: u32) -> [(Option<u16>, String); 2] {
    [false, true].map(|after_head| {
        let t = far_end_sends(
            open_call(after_head, b""),
            &h2(3, 0, 1, &code.to_be_bytes()),
        );
        (t.status, String::from_utf8_lossy(&t.bytes).into_owned())
    })
}

/// `code` fails the stream with `status` both ways, and the framer's own text naming `name`.
fn assert_reset(code: u32, status: u16, name: &str) {
    let text = format!("the stream was reset: {name}");
    let [before, after] = reset_both_ways(code);
    assert_eq!(before, (Some(status), text.clone()), "before the head");
    if code == 0 {
        assert_eq!(
            after,
            (
                Some(status),
                "the answer ended without a grpc-status".into()
            ),
            "after the head"
        );
    } else {
        assert_eq!(after, (Some(status), text), "after the head");
    }
}

/// Every HTTP/2 reset code fails the call with its mapped gRPC status. `STREAM_CLOSED`, which the
/// table does not list, and a code HTTP/2 does not define (RFC 9113 §7) are
/// `INTERNAL`, never read as safe to retry; `REFUSED_STREAM` is `UNAVAILABLE` (the far end processed
/// nothing).
#[test]
fn every_reset_code_fails_the_call_with_its_status() {
    let table = [
        (0x0, msg::INTERNAL, "NO_ERROR"),
        (0x1, msg::INTERNAL, "PROTOCOL_ERROR"),
        (0x2, msg::INTERNAL, "INTERNAL_ERROR"),
        (0x3, msg::INTERNAL, "FLOW_CONTROL_ERROR"),
        (0x4, msg::INTERNAL, "SETTINGS_TIMEOUT"),
        (0x5, msg::INTERNAL, "STREAM_CLOSED"),
        (0x6, msg::INTERNAL, "FRAME_SIZE_ERROR"),
        (0x7, msg::UNAVAILABLE, "REFUSED_STREAM"),
        (0x8, msg::CANCELLED, "CANCEL"),
        (0x9, msg::INTERNAL, "COMPRESSION_ERROR"),
        (0xa, msg::INTERNAL, "CONNECT_ERROR"),
        (0xb, msg::RESOURCE_EXHAUSTED, "ENHANCE_YOUR_CALM"),
        (0xc, msg::PERMISSION_DENIED, "INADEQUATE_SECURITY"),
        (0xd, msg::INTERNAL, "HTTP_1_1_REQUIRED"),
        (0x1f, msg::INTERNAL, "error code 0x1f"),
    ];
    for (code, status, name) in table {
        assert_reset(code, status, name);
    }
}

/// A RESET OF OUR OWN is read by its code as the far end's is: a malformed answer head (a
/// connection-specific field, which HTTP/2 forbids) has the connection reset the stream
/// `PROTOCOL_ERROR` itself, and the call fails `INTERNAL`.
#[test]
fn a_local_reset_is_read_by_its_code() {
    let mut block = vec![0x88, 0x00, 10];
    block.extend_from_slice(b"connection");
    block.push(5);
    block.extend_from_slice(b"close");
    let t = far_end_sends(open_call(false, b""), &h2(1, 0x4, 1, &block));
    assert_eq!(t.status, Some(msg::INTERNAL));
    assert_eq!(t.bytes.as_ref(), b"the stream was reset: PROTOCOL_ERROR");
}

/// A GOAWAY THAT LEAVES THE STREAM UNPROCESSED is read by its code, as a reset is: last stream 0
/// and `ENHANCE_YOUR_CALM` fail the open call `RESOURCE_EXHAUSTED`.
#[test]
fn a_goaway_is_read_by_its_code() {
    let mut payload = 0u32.to_be_bytes().to_vec();
    payload.extend_from_slice(&0xbu32.to_be_bytes());
    let t = far_end_sends(open_call(false, b""), &h2(7, 0, 0, &payload));
    assert_eq!(t.status, Some(msg::RESOURCE_EXHAUSTED));
    assert_eq!(
        t.bytes.as_ref(),
        b"the connection went away: ENHANCE_YOUR_CALM"
    );
}

/// A CONNECTION LOST BEFORE ANY STATUS is `UNAVAILABLE`, before the answer's head or after it: the
/// far end's bytes end with the call open.
#[test]
fn a_connection_lost_before_any_status_fails_the_call_unavailable() {
    for after_head in [false, true] {
        let mut p = open_call(after_head, b"");
        p.d.ingest(&[], true);
        p.settle();
        let t = terminal(&p.got_d, 1).cloned().expect("the stream ends");
        assert!(t.failed);
        assert_eq!(t.status, Some(msg::UNAVAILABLE), "after_head {after_head}");
        assert!(
            t.bytes
                .starts_with(b"the connection to the far end was lost"),
            "after_head {after_head}"
        );
    }
}

/// AN ANSWER THAT ENDS INSIDE A MESSAGE, with no trailers (here the far end's NO_ERROR reset after
/// part of a message), is `INTERNAL` in this framer's words.
#[test]
fn an_answer_cut_inside_a_message_fails_the_call_internal() {
    let part = &msg::frame(b"hello")[..3];
    let t = far_end_sends(open_call(true, part), &h2(3, 0, 1, &0u32.to_be_bytes()));
    assert_eq!(t.status, Some(msg::INTERNAL));
    assert_eq!(
        t.bytes.as_ref(),
        b"the answer ended inside a message, with no grpc-status"
    );
}

/// A COMPRESSION THE SERVER DOES NOT TAKE IS ANSWERED `UNIMPLEMENTED` (gRPC's compression rules,
/// `compression.md`): trailers-only, before a message is read, with `grpc-accept-encoding:
/// identity` and this framer's words, and never handed up. A call stating `identity` is no
/// compressed call, and is served.
#[test]
fn a_compression_the_server_does_not_take_is_answered_unimplemented() {
    let mut p = Pair::new();
    let fields: [(&str, &[u8]); 2] = [("path", b"/pkg.Svc/Z"), ("grpc-encoding", b"gzip")];
    let mut c = msg::render_head(&fields, Some(6)).expect("head");
    c.extend_from_slice(&[1, 0, 0, 0, 1, b'z']);
    p.d.emit(1, &c, true, 0, p.now).expect("emit");
    p.settle();
    assert!(of(&p.got_a, 1).is_empty(), "never handed up: {:?}", p.got_a);
    let h = head(&p.got_d, 1);
    assert_eq!(
        field(&h.bytes, "grpc-accept-encoding").as_deref(),
        Some(&b"identity"[..])
    );
    let t = terminal(&p.got_d, 1).expect("the trailers-only answer");
    assert_eq!(t.status, Some(msg::UNIMPLEMENTED));
    let end = last(&p.got_d, 1).expect("terminal");
    assert!(end.failed);
    assert_eq!(
        end.bytes.as_ref(),
        b"the message encoding `gzip` is not supported: this server takes identity"
    );

    let mut p = Pair::new();
    p.d.emit(
        1,
        &call("/pkg.Svc/Z", &[("grpc-encoding", b"identity")], &[b"z"]),
        true,
        0,
        p.now,
    )
    .expect("emit");
    p.settle();
    assert_eq!(
        frames(&p.got_a, 1)[0],
        msg::frame(b"z").as_slice(),
        "identity is served"
    );
}

/// THE FIRST `grpc-encoding` FIELD IS THE CALL'S on the dedicated listener too: `identity` then
/// `gzip` is served, `gzip` then `identity` is answered `UNIMPLEMENTED` and never handed up.
#[test]
fn the_first_grpc_encoding_field_is_the_calls() {
    let mut a = Conn::accept(posture(), 5 * SEC);
    a.ingest(
        &opening_with(
            Some("trailers"),
            &[("grpc-encoding", "identity"), ("grpc-encoding", "gzip")],
        ),
        false,
    );
    a.drive(5 * SEC);
    let got: Vec<Piece> = a.pieces().drain(..).collect();
    assert!(!of(&got, 1).is_empty(), "identity first: served");
    let mut a = Conn::accept(posture(), 5 * SEC);
    a.ingest(
        &opening_with(
            Some("trailers"),
            &[("grpc-encoding", "gzip"), ("grpc-encoding", "identity")],
        ),
        false,
    );
    a.drive(5 * SEC);
    assert!(a.pieces().is_empty(), "gzip first: never handed up");
    assert_eq!(held(&a), 0);
}

/// NO `grpc-timeout` GOES UPSTREAM, as predev's hop sent none (predev
/// `crates/busbar-a2a/src/a2a/relay.rs` `build_request`): not one of the dial's own, and not one
/// the head carries.
#[test]
fn no_grpc_timeout_goes_upstream_even_when_the_head_carries_one() {
    let mut p = Pair::new();
    let t0 = p.now;
    let carried: [(&str, &[u8]); 3] = [
        ("content-type", b"application/grpc"),
        ("te", b"trailers"),
        ("grpc-timeout", b"7S"),
    ];
    p.d.emit(
        1,
        &call("/pkg.Svc/Say", &carried, &[b"q"]),
        true,
        t0 + 2 * SEC,
        t0,
    )
    .expect("emit");
    p.settle();
    let h = head(&p.got_a, 1);
    assert_eq!(field(&h.bytes, "grpc-timeout"), None, "no grpc-timeout");
    assert_eq!(
        field(&h.bytes, "content-type").as_deref(),
        Some(&b"application/grpc"[..])
    );
    assert_eq!(
        p.d.next_deadline(),
        Some(t0 + 2 * SEC),
        "the attempt's own deadline still holds the call"
    );
}

/// A DIALLED STREAM FAILED AFTER ITS ANSWER'S HEAD IS RESET ON THE WIRE. A bidi call whose request
/// is still open (no content-length, the frame not ended) has its answer's head in, and then its
/// deadline passes: the host hears `DEADLINE_EXCEEDED`, and the far end hears the call reset, so it
/// stops working on it and its stream slot is freed.
#[test]
fn a_dialled_stream_failed_after_its_answers_head_is_reset_on_the_wire() {
    let mut p = Pair::new();
    let t0 = p.now;
    let mut c = msg::render_head(&[("path", b"/pkg.Svc/Chat")], None).expect("head");
    c.extend_from_slice(&msg::frame(b"first"));
    p.d.emit(1, &c, false, t0 + 2 * SEC, t0).expect("emit");
    p.settle();
    p.a.emit(1, b"\r\n", false, 0, p.now).expect("answer head");
    p.settle();
    head(&p.got_d, 1);
    assert!(terminal(&p.got_a, 1).is_none(), "the call is open");
    p.at(t0 + 2 * SEC);
    assert_eq!(
        terminal(&p.got_d, 1).and_then(|t| t.status),
        Some(msg::DEADLINE_EXCEEDED)
    );
    let a = terminal(&p.got_a, 1).expect("the far end hears the call reset");
    assert!(a.failed, "{a:?}");
    assert_eq!(a.status, Some(msg::CANCELLED));
}

/// A GRACEFUL GOAWAY THAT LEAVES THE STREAM UNPROCESSED IS `UNAVAILABLE`: a far end draining
/// (`NO_ERROR`, last stream 0) never processed the open call, which is safe to retry
/// (PROTOCOL-HTTP2.md, "GOAWAY Frame": a stream past the last one accepted is `UNAVAILABLE`).
#[test]
fn a_graceful_goaway_refusing_an_unprocessed_stream_is_unavailable() {
    let mut payload = 0u32.to_be_bytes().to_vec();
    payload.extend_from_slice(&0u32.to_be_bytes());
    let t = far_end_sends(open_call(false, b""), &h2(7, 0, 0, &payload));
    assert_eq!(t.status, Some(msg::UNAVAILABLE));
    assert_eq!(t.bytes.as_ref(), b"the connection went away: NO_ERROR");
}

/// A DIALLED FRAME THAT ENDS SHORT OF ITS HEAD'S `content-length` FAILS AT ONCE, in words: the head
/// states 20 message bytes and the frame ends after 12.
#[test]
fn a_dialled_frame_ending_short_of_its_content_length_fails_in_words() {
    let mut p = Pair::new();
    let mut c = msg::render_head(&[("path", b"/pkg.Svc/Say")], Some(20)).expect("head");
    c.extend_from_slice(&[0u8; 12]);
    p.d.emit(1, &c, true, 0, p.now).expect("emit");
    p.settle();
    let t = terminal(&p.got_d, 1)
        .cloned()
        .expect("the stream fails at once");
    assert!(t.failed, "{t:?}");
    assert_eq!(t.status, Some(msg::INTERNAL));
    assert_eq!(
        t.bytes.as_ref(),
        b"the frame ended 8 bytes short of the head's content-length"
    );
    assert_eq!(held(&p.d), 0, "the stream is over");
}

/// A dialled head whose message bytes run past its `content-length` fails the stream `INTERNAL` in
/// words, never sending the extra bytes on as a second call's.
#[test]
fn a_dialled_frame_running_past_its_content_length_fails_in_words() {
    let mut p = Pair::new();
    let mut c = msg::render_head(&[("path", b"/pkg.Svc/Say")], Some(4)).expect("head");
    c.extend_from_slice(&msg::frame(b"q"));
    p.d.emit(1, &c, true, 0, p.now).expect("emit");
    p.settle();
    let t = terminal(&p.got_d, 1).cloned().expect("the stream fails");
    assert_eq!(t.status, Some(msg::INTERNAL));
    assert_eq!(
        t.bytes.as_ref(),
        b"more message bytes than the head's content-length"
    );
}

/// A DIALLED STREAM WITH NO CONTENT-LENGTH THAT IS EMITTED ON AFTER THE FRAME THAT ENDED IT fails
/// in words, as the content-length over-run does. RED: the extra bytes were dropped and the emit
/// answered Ok.
#[test]
fn a_dialled_frame_after_the_request_ended_fails_in_words() {
    let mut p = Pair::new();
    let mut c = msg::render_head(&[("path", b"/pkg.Svc/Say")], None).expect("head");
    c.extend_from_slice(&msg::frame(b"q"));
    p.d.emit(1, &c, true, 0, p.now).expect("emit");
    let again = p.d.emit(1, &msg::frame(b"late"), false, 0, p.now);
    p.settle();
    let failed = terminal(&p.got_d, 1)
        .filter(|t| t.failed)
        .map(|t| String::from_utf8_lossy(&t.bytes).into_owned());
    assert!(
        again.is_ok() && failed.as_deref() == Some("bytes after the request's end"),
        "late bytes are refused in words: {again:?} {failed:?}"
    );
}

/// TRAILERS THAT CARRY NO `grpc-status` close UNKNOWN in words that say the status is missing,
/// never the bare `grpc-status 2` a real UNKNOWN reads as. RED: `grpc-status 2`.
#[test]
fn trailers_with_no_grpc_status_say_so() {
    let mut block = Vec::new();
    lit_field(&mut block, "x-a", "b");
    let mut p = open_call(true, b"");
    p.d.ingest(&h2(1, 0x5, 1, &block), false);
    p.settle();
    assert_eq!(
        terminal(&p.got_d, 1).and_then(|t| t.status),
        Some(msg::UNKNOWN)
    );
    assert_eq!(
        last(&p.got_d, 1).expect("terminal").bytes.as_ref(),
        b"the answer's trailers carry no grpc-status"
    );
}

/// A `grpc-status` THAT IS NOT A CANONICAL CODE, with no `grpc-message`, closes UNKNOWN in words
/// that give the value the far end sent, never `grpc-status 2`, a value it did not send. RED:
/// `grpc-status 2`.
#[test]
fn a_non_canonical_grpc_status_is_reported_as_sent() {
    for (sent, shown) in [("99", "99"), ("abc", "abc"), ("2", "")] {
        let mut block = Vec::new();
        lit_field(&mut block, "grpc-status", sent);
        let mut p = open_call(true, b"");
        p.d.ingest(&h2(1, 0x5, 1, &block), false);
        p.settle();
        assert_eq!(
            terminal(&p.got_d, 1).and_then(|t| t.status),
            Some(msg::UNKNOWN),
            "{sent}"
        );
        let want = if shown.is_empty() {
            "grpc-status 2".to_owned()
        } else {
            format!("grpc-status {shown} (not a gRPC status; read as UNKNOWN)")
        };
        assert_eq!(
            String::from_utf8_lossy(&last(&p.got_d, 1).expect("terminal").bytes),
            want,
            "{sent}"
        );
    }
}

/// A CONNECTION LOST BELOW gRPC keeps its cause in the text. RED: the fixed text alone.
#[test]
fn a_lost_connection_keeps_its_cause() {
    let mut p = open_call(true, b"");
    p.d.ingest(&[], true);
    p.settle();
    let t = terminal(&p.got_d, 1).cloned().expect("the stream ends");
    let text = String::from_utf8_lossy(&t.bytes).into_owned();
    let cause = text
        .strip_prefix("the connection to the far end was lost: ")
        .unwrap_or_else(|| panic!("no cause in {text:?}"));
    assert!(!cause.is_empty());
}

/// HPACK, literal without indexing, a new name: `name: value`.
fn lit_field(block: &mut Vec<u8>, name: &str, value: &str) {
    block.push(0x00);
    block.push(u8::try_from(name.len()).expect("short"));
    block.extend_from_slice(name.as_bytes());
    block.push(u8::try_from(value.len()).expect("short"));
    block.extend_from_slice(value.as_bytes());
}

/// A dialled call on stream 1 whose far end answers, by hand, one HEADERS frame ending the stream:
/// `:status` `status`, then `fields`.
fn answered_by_hand(status: &str, fields: &[(&str, &str)]) -> Vec<Piece> {
    let now = 5 * SEC;
    let mut d = Conn::dial("http://peer.test:50051", posture(), now).expect("dial");
    d.emit(1, &call("/pkg.Svc/Get", &[], &[b"k"]), true, 0, now)
        .expect("emit");
    let mut got: Vec<Piece> = Vec::new();
    let turn = |d: &mut Conn, got: &mut Vec<Piece>| {
        for _ in 0..20 {
            d.drive(now);
            let _ = d.take_wire(usize::MAX);
            got.extend(d.pieces().drain(..));
        }
    };
    turn(&mut d, &mut got);
    let mut wire = h2(4, 0, 0, &[]);
    wire.extend(h2(4, 1, 0, &[]));
    d.ingest(&wire, false);
    turn(&mut d, &mut got);
    let mut block = vec![0x08, u8::try_from(status.len()).expect("short")];
    block.extend_from_slice(status.as_bytes());
    for (n, v) in fields {
        lit_field(&mut block, n, v);
    }
    d.ingest(&h2(1, 0x05, 1, &block), false);
    turn(&mut d, &mut got);
    got
}

/// A `grpc-status` THE ANSWER STATES IS USED, whatever its HTTP status (`http-grpc-status-mapping.md`:
/// the table is only for an answer with no `grpc-status`; one that was provided must be used).
#[test]
fn a_non_200_answer_stating_grpc_status_is_read_by_its_grpc_status() {
    let got = answered_by_hand(
        "403",
        &[
            ("content-type", "application/grpc"),
            ("grpc-status", "5"),
            ("grpc-message", "no%20such%20key"),
        ],
    );
    let t = terminal(&got, 1).expect("the answer's status");
    assert_eq!((t.status, t.fields), (Some(5), true), "{got:?}");
    assert_eq!(t.fault, None, "the gRPC status's own reading");
    let end = last(&got, 1).expect("terminal");
    assert_eq!(
        (end.failed, end.bytes.as_ref()),
        (true, &b"no such key"[..])
    );
}

/// The same for a 200 whose content type is not gRPC's (or absent): the `grpc-status` it states is
/// its status.
#[test]
fn a_200_answer_without_a_grpc_content_type_stating_grpc_status_is_read_by_it() {
    for ct in [Some("text/plain"), None] {
        let mut fields = vec![("grpc-status", "14"), ("grpc-message", "draining")];
        if let Some(ct) = ct {
            fields.insert(0, ("content-type", ct));
        }
        let got = answered_by_hand("200", &fields);
        let t = terminal(&got, 1).expect("the answer's status");
        assert_eq!(t.status, Some(msg::UNAVAILABLE), "{ct:?}: {got:?}");
        let end = last(&got, 1).expect("terminal");
        assert_eq!(end.bytes.as_ref(), b"draining", "{ct:?}");
    }
}

/// A 200 answer with no gRPC content type and no `grpc-status` is no gRPC answer: `UNKNOWN`, in this
/// framer's words, never its body read as length-prefixed messages.
#[test]
fn a_200_answer_that_is_not_grpc_fails_unknown() {
    let got = answered_by_hand("200", &[("content-type", "text/html")]);
    let t = terminal(&got, 1).expect("the stream fails");
    assert!(t.failed, "{t:?}");
    assert_eq!(t.status, Some(msg::UNKNOWN));
    assert_eq!(t.bytes.as_ref(), b"the answer is not gRPC");
}

/// The dialled side's terminal piece for an answer whose trailers carry `grpc-message: message`.
fn failed_with_message(message: &[u8]) -> Piece {
    let mut p = Pair::new();
    p.d.emit(1, &call("/pkg.Svc/Get", &[], &[b"k"]), true, 0, p.now)
        .expect("emit");
    p.settle();
    p.a.emit(1, b"\r\n", false, 0, p.now).expect("head");
    let mut block = b"grpc-status: 13\r\ngrpc-message: ".to_vec();
    block.extend_from_slice(message);
    block.extend_from_slice(b"\r\n");
    p.a.end_call(1, &block, 0).expect("end");
    p.settle();
    last(&p.got_d, 1).cloned().expect("terminal")
}

/// A FAR END'S `grpc-message` REACHES THE HOST AS TEXT IT CAN PRINT: decoded, invalid UTF-8 replaced,
/// every control character escaped (a terminal escape or a forged log line arrives as visible
/// `\u{1b}` and `\n`), and bounded in length.
#[test]
fn a_far_ends_grpc_message_reaches_the_host_as_printable_bounded_text() {
    let end = failed_with_message(b"%1B%5B2J%0D%0Afake%20log%20line%FF");
    assert!(end.failed);
    assert_eq!(
        String::from_utf8(end.bytes.to_vec()).expect("text"),
        "\\u{1b}[2J\\r\\nfake log line\u{fffd}"
    );
    let long = vec![b'a'; 10_000];
    let end = failed_with_message(&long);
    assert_eq!(end.bytes.len(), msg::MESSAGE_TEXT_MAX, "bounded");
}

/// A TARGET'S USERINFO NEVER GOES ON THE WIRE: a target stating `user:secret@` dials its host and
/// port alone, so `:authority` carries no credential (RFC 9113 §8.3.1) and is the authority
/// `locate` stated.
#[test]
fn a_targets_userinfo_never_reaches_the_authority() {
    let mut p = Pair::new();
    p.d = Conn::dial("http://user:secret@peer.test:50051", posture(), p.now).expect("dial");
    p.d.emit(1, &call("/pkg.Svc/Say", &[], &[b"q"]), true, 0, p.now)
        .expect("emit");
    p.settle();
    let words = head(&p.got_a, 1).head.clone().expect("head words");
    assert_eq!(words.authority.as_ref(), b"peer.test:50051");
}

/// A CALL THE HOST ENDED READS NO MORE OF ITS REQUEST. The client is still uploading (no
/// END_STREAM) when the host refuses the call: the trailers go out, the upload is stopped
/// (RST_STREAM `NO_ERROR`, RFC 9113 §8.1), the call is let go of, and a message the client sends
/// after it is never handed up.
#[test]
fn a_call_the_host_ended_reads_no_more_of_its_request() {
    let mut a = Conn::accept(posture(), 5 * SEC);
    let mut wire = opening(Some("trailers"));
    wire.extend(h2(0, 0, 1, &msg::frame(b"one")));
    a.ingest(&wire, false);
    a.drive(5 * SEC);
    drop(a.pieces().drain(..));
    a.end_call(1, b"grpc-status: 7\r\n", 0).expect("refuse");
    a.drive(5 * SEC);
    let sent = a.take_wire(usize::MAX);
    assert_eq!(resets(&sent), vec![(1, 0)], "the upload is stopped");
    a.ingest(&h2(0, 0, 1, &msg::frame(b"two")), false);
    a.drive(5 * SEC);
    let got: Vec<Piece> = a.pieces().drain(..).collect();
    assert!(got.is_empty(), "nothing more for an ended call: {got:?}");
    assert_eq!(held(&a), 0, "the call is let go of");
}

/// The message bytes a connection holds for the host, handed up and not yet taken.
fn held_for_host(c: &Conn) -> usize {
    c.out.iter().map(|p| p.bytes.len()).sum()
}

/// Run `turns` rounds of a pair whose `sender` streams 60 kB messages on stream 1 as fast as its own
/// backpressure lets it, while the `reader`'s host takes NOTHING it is handed; the most bytes the
/// reader held for its host.
fn stream_into_a_host_not_reading(p: &mut Pair, dial_sends: bool, turns: usize) -> usize {
    let m = msg::frame(&[7u8; 60_000]);
    let mut most = 0;
    for _ in 0..turns {
        let (s, r) = if dial_sends {
            (&mut p.d, &mut p.a)
        } else {
            (&mut p.a, &mut p.d)
        };
        if !s.announce_full(1) {
            let _ = s.emit(1, &m, false, 0, p.now);
        }
        s.drive(p.now);
        r.drive(p.now);
        let to_r = s.take_wire(usize::MAX);
        let to_s = r.take_wire(usize::MAX);
        r.ingest(&to_r, false);
        s.ingest(&to_s, false);

        s.pieces().clear();
        most = most.max(held_for_host(r));
    }

    let r = if dial_sends { &mut p.a } else { &mut p.d };
    r.pieces().clear();
    assert!(r.wire_pending(), "the host is owed a re-call");
    r.drive(p.now);
    assert!(!r.pieces().is_empty(), "the re-call reads on");
    most
}

/// AN ACCEPTED CALL'S MESSAGES ARE BOUNDED BY THE HOST'S TAKING THEM: a client uploads faster than
/// the host takes the pieces it is handed, and the connection stops reading the call's body once it
/// holds its mark for the host, so HTTP/2 flow control holds the client back.
#[test]
fn an_accepted_upload_the_host_does_not_take_is_bounded() {
    let mut p = Pair::new();
    let mut c = msg::render_head(&[("path", b"/pkg.Svc/Upload")], None).expect("head");
    c.extend_from_slice(&msg::frame(b"first"));
    p.d.emit(1, &c, false, 0, p.now).expect("open the call");
    let most = stream_into_a_host_not_reading(&mut p, true, 400);
    assert!(
        most <= 3 << 20,
        "the accepted side held {most} bytes for a host not taking them"
    );
    assert!(most >= 1 << 20, "it held up to its mark: {most}");
}

/// The same bound on a dialled call's answer: a server streaming faster than the host takes the
/// pieces is held back once the connection holds its mark for the host.
#[test]
fn a_dialled_answer_the_host_does_not_take_is_bounded() {
    let mut p = open_call(true, b"");
    let most = stream_into_a_host_not_reading(&mut p, false, 400);
    assert!(
        most <= 3 << 20,
        "the dialled side held {most} bytes for a host not taking them"
    );
    assert!(most >= 1 << 20, "it held up to its mark: {most}");
}

/// A TRAILER BLOCK'S FORBIDDEN FIELDS ARE FILTERED AS A HEAD'S ARE: connection-specific fields
/// (RFC 9113 §8.2.2) and the answer's own `content-type` never go out in the trailers, and the
/// call ends with the block's `grpc-status`.
#[test]
fn a_trailer_blocks_forbidden_fields_are_filtered_as_a_heads_are() {
    let mut p = Pair::new();
    p.d.emit(1, &call("/pkg.Svc/Get", &[], &[b"k"]), true, 0, p.now)
        .expect("emit");
    p.settle();
    p.a.emit(1, b"\r\n", false, 0, p.now).expect("head");
    p.a.end_call(
        1,
        b"connection: close\r\ntransfer-encoding: chunked\r\ncontent-type: text/plain\r\n\
          grpc-status: 0\r\nx-kept: yes\r\n",
        0,
    )
    .expect("end");
    p.settle();
    let t = terminal(&p.got_d, 1).cloned().expect("the trailers");
    assert_eq!(
        (t.status, t.fields, t.failed),
        (Some(0), true, false),
        "{t:?}"
    );
    assert_eq!(field(&t.bytes, "x-kept").as_deref(), Some(&b"yes"[..]));
    assert_eq!(field(&t.bytes, "content-type"), None);
}

/// AN ANSWER HEAD FIELD THE WIRE CANNOT CARRY FAILS THE CALL IN WORDS, as the dial side refuses the
/// same input: the host hears `INTERNAL` naming the field, and the client is answered.
#[test]
fn an_answer_head_field_the_wire_cannot_carry_fails_the_call_in_words() {
    let mut a = half_closed();
    a.emit(1, b"x bad: v\r\n\r\n", false, 0, 5 * SEC)
        .expect("taken");
    a.drive(5 * SEC);
    let got: Vec<Piece> = a.pieces().drain(..).collect();
    let t = terminal(&got, 1).expect("the stream fails");
    assert!(t.failed, "{t:?}");
    assert_eq!(t.status, Some(msg::INTERNAL));
    assert_eq!(t.bytes.as_ref(), b"`x bad` is not a field name");
}

/// A TRAILER FIELD THE WIRE CANNOT CARRY FAILS THE REFUSAL IN WORDS and leaves the call open for
/// the host's fallback close: never trailers that silently lack a field (`grpc-status` among
/// them).
#[test]
fn a_trailer_field_the_wire_cannot_carry_fails_the_refusal_in_words() {
    let mut a = half_closed();
    a.emit(1, b"\r\n", false, 0, 5 * SEC).expect("answer head");
    assert_eq!(
        a.end_call(1, b"grpc-status: 0\r\nx-bad: a\x01b\r\n", 0),
        Err(super::Failure(
            "`x-bad`'s value is not a field value".into()
        ))
    );
    assert_eq!(held(&a), 1, "the call is still open");
    a.end_call(1, b"", 500).expect("the fallback closes it");
    assert_eq!(
        sent_message(&a, 1).as_deref(),
        Some(&b"busbar%20answered%20HTTP%20500"[..])
    );
}

/// The terminal piece an accepted call's host hears after it emits `bytes` (`end` = they end the
/// frame) as the answer's first bytes.
fn answer_head_fails(bytes: &[u8], end: bool) -> Piece {
    let mut a = half_closed();
    a.emit(1, bytes, end, 0, 5 * SEC).expect("taken");
    a.drive(5 * SEC);
    let got: Vec<Piece> = a.pieces().drain(..).collect();
    let t = terminal(&got, 1).cloned().expect("the stream fails");
    assert!(t.failed, "{t:?}");
    assert_eq!(t.status, Some(msg::INTERNAL));
    t
}

/// AN ACCEPTED ANSWER'S FRAME THAT ENDS INSIDE ITS HEAD BLOCK FAILS IN WORDS, as the dial side's
/// does: the host hears `INTERNAL` and the client is answered.
#[test]
fn an_accepted_answers_frame_ending_inside_its_head_block_fails_in_words() {
    let t = answer_head_fails(b"x-partial: yes\r\n", true);
    assert_eq!(t.bytes.as_ref(), b"the frame ended inside the head block");
}

/// An accepted answer's malformed head block fails the call `INTERNAL` in the head reader's words.
#[test]
fn an_accepted_answers_malformed_head_block_fails_in_words() {
    let t = answer_head_fails(b"not a field\r\n\r\n", false);
    assert_eq!(t.bytes.as_ref(), b"a head line is not a field");
}

/// A REFUSAL WHOSE BLOCK NAMES `grpc-status` BUT IS NO FIELD BLOCK FAILS IN WORDS and leaves the
/// call open for the host's fallback close: the status the host meant is never silently replaced by
/// its neutral status's mapping.
#[test]
fn a_refusal_naming_grpc_status_in_a_broken_block_fails_in_words() {
    let mut a = half_closed();
    assert_eq!(
        a.end_call(1, b"grpc-status: 5\r\ngrpc-message oops\r\n", 500),
        Err(super::Failure(
            "the trailer block names grpc-status but is not a field block: a head line is not a \
             field"
                .into()
        ))
    );
    assert_eq!(held(&a), 1, "the call is still open");
    assert_eq!(sent_message(&a, 1), None, "nothing was sent");
}

/// Every frame type in `wire` (an HTTP/2 frame sequence, no preface), in order.
fn frame_types(wire: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 9 <= wire.len() {
        let len =
            usize::from(wire[i]) << 16 | usize::from(wire[i + 1]) << 8 | usize::from(wire[i + 2]);
        out.push(wire[i + 3]);
        i += 9 + len;
    }
    out
}

/// THE DIALLED KEEP-ALIVE IS HONOURED: with a call open on a connection whose far end has gone
/// silent, a PING goes out at the interval, and when it is not answered within the timeout the
/// call fails rather than wait out its deadline.
#[test]
fn a_dialled_keep_alive_pings_and_fails_a_silent_far_end() {
    let now = 5 * SEC;
    let posture = Posture {
        keep_alive_interval: Some(Duration::from_secs(30)),
        ..posture()
    };
    let mut d = Conn::dial("http://peer.test:50051", posture, now).expect("dial");
    d.emit(1, &call("/pkg.Svc/Get", &[], &[b"k"]), true, 0, now)
        .expect("emit");
    let turn = |d: &mut Conn, at: u64| {
        let mut wire = Vec::new();
        let mut got = Vec::new();
        for _ in 0..20 {
            d.drive(at);
            wire.extend(d.take_wire(usize::MAX));
            got.extend(d.pieces().drain(..));
        }
        (wire, got)
    };
    turn(&mut d, now);
    let mut wire = h2(4, 0, 0, &[]);
    wire.extend(h2(4, 1, 0, &[]));
    d.ingest(&wire, false);
    let (sent, _) = turn(&mut d, now);
    assert!(!frame_types(&sent).contains(&6), "no PING yet");
    let (sent, _) = turn(&mut d, now + 29 * SEC);
    assert!(
        !frame_types(&sent).contains(&6),
        "no PING before the interval"
    );
    let (sent, got) = turn(&mut d, now + 30 * SEC);
    assert!(frame_types(&sent).contains(&6), "a PING at the interval");
    assert!(terminal(&got, 1).is_none(), "the call waits on the PING");
    let (_, got) = turn(&mut d, now + 39 * SEC);
    assert!(
        terminal(&got, 1).is_none(),
        "the call waits out the PING timeout"
    );
    let (_, got) = turn(&mut d, now + 40 * SEC);
    let t = terminal(&got, 1).expect("an unanswered PING fails the call");
    assert!(t.failed, "{t:?}");
    assert_eq!(t.status, Some(msg::UNAVAILABLE));
}

/// A DIALLED CALL THAT STATES NO DEADLINE IS HELD TO `limits.upstream_request_timeout_secs`: the host
/// is asked back at that time, and a far end that never answers fails the call
/// `DEADLINE_EXCEEDED` then, not before and not never.
#[test]
fn a_dialled_call_stating_no_deadline_fails_at_the_configured_timeout() {
    let mut p = Pair::new();
    let t0 = p.now;
    let limit = posture().timeout.as_secs() * SEC;
    p.d.emit(1, &call("/pkg.Svc/Hang", &[], &[b"q"]), true, 0, t0)
        .expect("emit");
    p.settle();
    assert_eq!(
        p.d.next_deadline(),
        Some(t0 + limit),
        "asked back at the timeout"
    );
    p.at(t0 + limit - 1);
    assert!(terminal(&p.got_d, 1).is_none(), "not before the timeout");
    p.at(t0 + limit);
    let t = terminal(&p.got_d, 1).expect("the call fails at the timeout");
    assert_eq!((t.status, t.failed), (Some(msg::DEADLINE_EXCEEDED), true));
}

/// AN ACCEPTED CALL THAT IS NOT gRPC IS ANSWERED `415` HERE AND NEVER HANDED UP: a request whose
/// content type is not gRPC's (sent by hand, as no dial of this framer would) reaches the far end as
/// a bare HTTP 415, and the host hears nothing of it.
#[test]
fn an_accepted_call_that_is_not_grpc_is_answered_415_and_never_handed_up() {
    let mut p = Pair::new();
    let super::Side::Dial(d) = &mut p.d.side else {
        panic!("a dialled connection");
    };
    let timer = p.d.io.timer();
    let mut s = super::DialStream::new(timer.sleep_until_ns(p.now + 60 * SEC));
    let req = http::Request::builder()
        .method(http::Method::POST)
        .uri("http://peer.test:50051/pkg.Svc/Say")
        .version(http::Version::HTTP_2)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(s.chan.body())
        .expect("a request");
    s.chan.end();
    s.stage = super::DStage::Queued(req);
    d.calls.push((1, s));
    p.settle();
    assert!(of(&p.got_a, 1).is_empty(), "never handed up: {:?}", p.got_a);
    assert_eq!(held(&p.a), 0);
    let t = terminal(&p.got_d, 1).expect("answered");
    assert_eq!(t.status, Some(msg::UNKNOWN), "415 maps to UNKNOWN");
    let end = last(&p.got_d, 1).expect("terminal");
    assert_eq!(end.bytes.as_ref(), b"HTTP status 415");
}

/// A REFUSED ARRIVAL IS REMEMBERED AS ENDED: a call answered 415 here (or `UNIMPLEMENTED` for an
/// encoding) used an id and is never handed up, so it must enter the ended set, or every accepted
/// id after it stands as a run of its own and the set grows without bound on a long connection.
#[test]
fn a_refused_arrival_is_remembered_as_ended() {
    let mut p = Pair::new();
    for id in [1u64, 2] {
        let super::Side::Dial(d) = &mut p.d.side else {
            panic!("a dialled connection");
        };
        let timer = p.d.io.timer();
        let mut s = super::DialStream::new(timer.sleep_until_ns(p.now + 60 * SEC));
        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("http://peer.test:50051/pkg.Svc/Say")
            .version(http::Version::HTTP_2)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(s.chan.body())
            .expect("a request");
        s.chan.end();
        s.stage = super::DStage::Queued(req);
        d.calls.push((id, s));
        p.settle();
    }
    assert!(of(&p.got_a, 1).is_empty(), "never handed up: {:?}", p.got_a);
    let super::Side::Accept(a) = &p.a.side else {
        panic!("an accepted connection");
    };
    assert_eq!(a.calls.len(), 0);
    assert!(
        a.ended.contains(1) && a.ended.contains(2),
        "both refused arrivals are ended: {:?}",
        a.ended.0
    );
}

/// A DIALLED HEAD'S CONTENT TYPE MUST BE gRPC'S, and the fields this layer owns never go upstream
/// from it: a head stating `application/json` fails `INTERNAL` in words; one stating `host` or
/// `authority` sends neither (the call's authority is the target's).
#[test]
fn a_dialled_heads_content_type_and_reserved_fields_are_this_layers() {
    let mut p = Pair::new();
    let json: [(&str, &[u8]); 1] = [("content-type", b"application/json")];
    p.d.emit(1, &call("/pkg.Svc/Say", &json, &[b"q"]), true, 0, p.now)
        .expect("emit");
    p.settle();
    let t = terminal(&p.got_d, 1).cloned().expect("refused");
    assert_eq!(t.status, Some(msg::INTERNAL));
    assert_eq!(t.bytes.as_ref(), b"content-type is not a gRPC content type");

    let mut p = Pair::new();
    let owned: [(&str, &[u8]); 2] = [("host", b"evil.test"), ("authority", b"evil.test")];
    p.d.emit(1, &call("/pkg.Svc/Say", &owned, &[b"q"]), true, 0, p.now)
        .expect("emit");
    p.settle();
    let h = head(&p.got_a, 1);
    assert_eq!(field(&h.bytes, "host"), None);
    assert_eq!(field(&h.bytes, "authority"), None);
    let words = h.head.as_ref().expect("head words");
    assert_eq!(words.authority.as_ref(), b"peer.test:50051");
}

/// A CONNECTION THAT FAILS WHILE IT HOLDS A BODY BACK FOR THE HOST STILL SAYS SO: the far end goes
/// away while the dialled side holds its mark for a host not taking its pieces, and once the host
/// has taken them the connection owes nothing more, so the op answers the failure.
#[test]
fn a_connection_failing_while_it_holds_a_body_back_still_says_so() {
    let mut p = open_call(true, b"");
    stream_into_a_host_not_reading(&mut p, false, 400);

    let m = msg::frame(&[7u8; 60_000]);
    for _ in 0..40 {
        if !p.a.announce_full(1) {
            let _ = p.a.emit(1, &m, false, 0, p.now);
        }
        p.a.drive(p.now);
        p.d.drive(p.now);
        let to_d = p.a.take_wire(usize::MAX);
        p.d.ingest(&to_d, false);
    }
    p.d.drive(p.now);
    p.d.ingest(&[], true);
    p.d.drive(p.now);
    assert!(p.d.failure().is_some(), "the connection failed");
    p.d.pieces().clear();
    assert!(!p.d.wire_pending(), "a failed connection owes no re-call");
}

/// ONE BUSY STREAM DOES NOT STARVE ANOTHER while the host holds the connection at its mark: two
/// accepted calls both upload far faster than the host takes its pieces, and each drive reads from
/// a different stream first, so both keep making headway.
#[test]
fn one_busy_stream_does_not_starve_another_while_the_host_is_slow() {
    let mut p = Pair::new();
    let m = msg::frame(&[7u8; 60_000]);
    for id in [1, 3] {
        let mut c = msg::render_head(&[("path", b"/pkg.Svc/Upload")], None).expect("head");
        c.extend_from_slice(&m);
        p.d.emit(id, &c, false, 0, p.now).expect("open");
    }

    let mut late = [0usize; 2];
    for turn in 0..300 {
        for id in [1, 3] {
            for _ in 0..4 {
                if p.d.announce_full(id) {
                    break;
                }
                let _ = p.d.emit(id, &m, false, 0, p.now);
            }
        }
        p.d.drive(p.now);
        p.a.drive(p.now);
        let to_a = p.d.take_wire(usize::MAX);
        let to_d = p.a.take_wire(usize::MAX);
        p.a.ingest(&to_a, false);
        p.d.ingest(&to_d, false);
        p.d.pieces().clear();

        for _ in 0..2 {
            if let Some(piece) = p.a.pieces().pop_front() {
                if turn >= 150 && !piece.bytes.is_empty() && !piece.fields {
                    late[usize::from(piece.stream == 2)] += 1;
                }
            }
        }
    }
    assert!(late[0] > 20 && late[1] > 20, "both streams read: {late:?}");
}

/// The actual HTTP/2 dial path against separately delivered server frames.
fn manual_reply_dial() -> (Conn, Vec<Piece>, u64) {
    let now = 5 * SEC;
    let mut d = Conn::dial("http://peer.test:50051", posture(), now).expect("dial");
    d.emit(1, &call("/pkg.Svc/Get", &[], &[b"request"]), true, 0, now)
        .unwrap();
    let mut got = Vec::new();
    manual_reply_turn(&mut d, &mut got, now);
    let mut settings = h2(4, 0, 0, &[]);
    settings.extend(h2(4, 1, 0, &[]));
    d.ingest(&settings, false);
    manual_reply_turn(&mut d, &mut got, now);
    (d, got, now)
}

fn manual_reply_turn(d: &mut Conn, got: &mut Vec<Piece>, now: u64) {
    for _ in 0..20 {
        d.drive(now);
        drop(d.take_wire(usize::MAX));
        got.extend(d.pieces().drain(..));
    }
}

fn response_head_with_status(status: Option<&str>) -> Vec<u8> {
    let mut block = vec![0x88];
    lit_field(&mut block, "content-type", "application/grpc");
    if let Some(status) = status {
        lit_field(&mut block, "grpc-status", status);
    }
    block
}

#[test]
fn a_status_in_response_headers_cannot_succeed_before_the_http2_stream_ends() {
    for coalesced in [false, true] {
        let (mut d, mut got, now) = manual_reply_dial();
        let mut first = h2(1, 0x04, 1, &response_head_with_status(Some("0")));
        let data = h2(0, 0x01, 1, &msg::frame(b"late reply payload"));
        if coalesced {
            first.extend_from_slice(&data);
        }
        d.ingest(&first, false);
        manual_reply_turn(&mut d, &mut got, now);
        assert!(
            got.iter().all(|p| p.status != Some(0)),
            "a nonterminal head is not success: {got:?}"
        );
        let failed = terminal(&got, 1).expect("malformed trailers-only head fails");
        assert!(failed.failed, "{failed:?}");
        assert_eq!(failed.status, Some(msg::INTERNAL));
        if !coalesced {
            d.ingest(&data, false);
            manual_reply_turn(&mut d, &mut got, now);
        }
        assert!(
            got.iter().all(|p| p.status != Some(0)),
            "later DATA cannot retroactively bless the head"
        );
    }
}

#[test]
fn terminal_response_headers_and_real_body_trailers_remain_successful() {
    let (mut d, mut got, now) = manual_reply_dial();
    d.ingest(
        &h2(1, 0x05, 1, &response_head_with_status(Some("0"))),
        false,
    );
    manual_reply_turn(&mut d, &mut got, now);
    assert_eq!(terminal(&got, 1).and_then(|p| p.status), Some(0));
    assert!(!last(&got, 1).unwrap().failed);

    let (mut d, mut got, now) = manual_reply_dial();
    d.ingest(&h2(1, 0x04, 1, &response_head_with_status(None)), false);
    manual_reply_turn(&mut d, &mut got, now);
    assert!(
        terminal(&got, 1).is_none(),
        "an ordinary head leaves the body open"
    );
    d.ingest(&h2(0, 0, 1, &msg::frame(b"whole reply")), false);
    manual_reply_turn(&mut d, &mut got, now);
    assert!(frames(&got, 1).contains(&msg::frame(b"whole reply").as_slice()));
    assert!(
        terminal(&got, 1).is_none(),
        "DATA without END_STREAM still awaits trailers"
    );
    let mut trailers = Vec::new();
    lit_field(&mut trailers, "grpc-status", "0");
    d.ingest(&h2(1, 0x05, 1, &trailers), false);
    manual_reply_turn(&mut d, &mut got, now);
    assert_eq!(terminal(&got, 1).and_then(|p| p.status), Some(0));
    assert!(!last(&got, 1).unwrap().failed);
}

/// Both actual HTTP/2 peers have live connection and stream tasks when the host finishes them.
#[test]
fn dropping_active_grpc_framings_releases_both_connection_tasks_and_the_service() {
    let mut pair = Pair::new();
    pair.d
        .emit(
            1,
            &call("/svc/Method", &[], &[b"request"]),
            true,
            0,
            pair.now,
        )
        .unwrap();
    pair.settle();
    assert_eq!(
        head(&pair.got_a, 1).head.as_ref().unwrap().target.as_ref(),
        b"/svc/Method"
    );
    assert_eq!(held(&pair.a), 1, "a real stream awaits its reply");
    let dial_task = std::sync::Arc::downgrade(&pair.d.conn_err);
    let accept_task = std::sync::Arc::downgrade(&pair.a.conn_err);
    let super::Side::Accept(accept) = &pair.a.side else {
        panic!("the accepted peer")
    };
    let service = std::sync::Arc::downgrade(&accept.arrivals);
    assert!(
        dial_task.strong_count() > 1,
        "the dialled connection task is live"
    );
    assert!(
        accept_task.strong_count() > 1,
        "the accepted connection task is live"
    );
    drop(pair);
    assert!(
        dial_task.upgrade().is_none(),
        "the dialled task went with its framing"
    );
    assert!(
        accept_task.upgrade().is_none(),
        "the accepted task went with its framing"
    );
    assert!(
        service.upgrade().is_none(),
        "the accepted service and stream tasks were freed"
    );
}

#[test]
fn a_new_dialled_grpc_connection_polls_its_spawned_driver_without_peer_input() {
    let mut conn = Conn::dial("http://peer.test:50051", posture(), 0).unwrap();
    conn.drive(0);
    assert!(
        conn.take_wire(usize::MAX)
            .starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
        "the spawned connection driver must run in this drive, before any peer input"
    );
}

/// A FRAMING DROPPED WITH ITS CONNECTION OPEN IS FREED. The connection's tasks sit in the framing's
/// own executor, and each held a strong handle to it: a cycle no drop broke, so a finished framing
/// leaked its h2 state, pipes and header table for the life of the process.
/// RED: the watch task's `conn_err` clone outlived the dropped `Conn`.
#[test]
fn a_dialled_conn_dropped_with_a_call_open_is_freed() {
    let mut d = Conn::dial("http://peer.test:50051", posture(), 5 * SEC).expect("dial");
    d.emit(1, &call("/pkg.Svc/Say", &[], &[b"hello"]), true, 0, 5 * SEC)
        .expect("emit");
    d.drive(5 * SEC);
    let weak = std::sync::Arc::downgrade(&d.conn_err);
    assert!(weak.strong_count() > 1, "the watch task holds the cell");
    drop(d);
    assert!(
        weak.upgrade().is_none(),
        "the dropped Conn leaked its tasks"
    );
}

/// A framing dropped with its pipe FULL (the wire at `WRITE_HIGH_WATER`, the host never taking it)
/// is freed: the far end's window is opened first, so h2 really does write that much.
#[test]
fn a_dialled_conn_dropped_with_the_pipe_full_is_freed() {
    const HIGH: usize = 256 * 1024;
    let mut d = Conn::dial("http://peer.test:50051", posture(), 5 * SEC).expect("dial");
    // The far end's preface: SETTINGS with a large INITIAL_WINDOW_SIZE, its ACK of ours, and a
    // connection-level WINDOW_UPDATE.
    let mut preface = h2(4, 0, 0, &[0, 4, 0x40, 0, 0, 0]);
    preface.extend(h2(4, 1, 0, &[]));
    preface.extend(h2(8, 0, 0, &(1u32 << 30).to_be_bytes()));
    d.drive(5 * SEC);
    let _ = d.take_wire(usize::MAX);
    d.ingest(&preface, false);
    d.drive(5 * SEC);
    let _ = d.take_wire(usize::MAX);
    let big = vec![b'x'; 900 * 1024];
    d.emit(1, &call("/pkg.Svc/Say", &[], &[&big]), true, 0, 5 * SEC)
        .expect("emit");
    // Driven without the host taking the wire: the pipe fills to its mark.
    d.drive(5 * SEC);
    // Observe the fill (taking it frees room), then let the drive refill it.
    let n = d.take_wire(HIGH).len();
    assert!(n >= HIGH, "the pipe reached its mark: {n}");
    d.drive(5 * SEC);
    assert!(
        d.take_wire(HIGH).len() >= HIGH,
        "the pipe refilled to its mark"
    );
    d.drive(5 * SEC);
    let weak = std::sync::Arc::downgrade(&d.conn_err);
    assert!(weak.strong_count() > 1, "the watch task holds the cell");
    drop(d);
    assert!(
        weak.upgrade().is_none(),
        "the dropped Conn leaked its tasks"
    );
}

#[test]
fn an_accepted_conn_dropped_with_a_call_in_flight_is_freed() {
    let mut a = Conn::accept(posture(), 5 * SEC);
    let mut wire = opening(Some("trailers"));
    wire.extend(h2(0, 0, 1, &msg::frame(b"q")));
    a.ingest(&wire, false);
    a.drive(5 * SEC);
    assert_eq!(held(&a), 1, "a call is in flight");
    let weak = std::sync::Arc::downgrade(&a.conn_err);
    assert!(weak.strong_count() > 1, "the watch task holds the cell");
    drop(a);
    assert!(
        weak.upgrade().is_none(),
        "the dropped Conn leaked its tasks"
    );
}

/// A literal HPACK field, no indexing, no Huffman.
fn lit(name: &str, value: &str) -> Vec<u8> {
    let mut v = vec![0x00, name.len() as u8];
    v.extend_from_slice(name.as_bytes());
    v.push(value.len() as u8);
    v.extend_from_slice(value.as_bytes());
    v
}

/// Premature status never becomes successful completion; an ordinary response keeps its body
/// and its actual terminal trailers.
#[test]
fn a_premature_status_is_refused_and_real_final_trailers_are_preserved() {
    for premature in [false, true] {
        let now = 5 * SEC;
        let mut d = Conn::dial("http://peer.test:50051", posture(), now).expect("dial");
        d.emit(1, &call("/pkg.Svc/Get", &[], &[b"k"]), true, 0, now)
            .expect("emit");
        let mut got: Vec<Piece> = Vec::new();
        let turn = |d: &mut Conn, got: &mut Vec<Piece>| {
            for _ in 0..20 {
                d.drive(now);
                let _ = d.take_wire(usize::MAX);
                got.extend(d.pieces().drain(..));
            }
        };
        turn(&mut d, &mut got);
        let mut wire = h2(4, 0, 0, &[]);
        wire.extend(h2(4, 1, 0, &[]));
        d.ingest(&wire, false);
        turn(&mut d, &mut got);
        let mut head_block = vec![0x88];
        head_block.extend(lit("content-type", "application/grpc"));
        if premature {
            head_block.extend(lit("grpc-status", "0"));
        }
        let mut wire = h2(1, 0x04, 1, &head_block);
        wire.extend(h2(0, 0, 1, &msg::frame(b"answer")));
        wire.extend(h2(1, 0x05, 1, &lit("grpc-status", "13")));
        d.ingest(&wire, false);
        turn(&mut d, &mut got);
        let t = terminal(&got, 1).expect("the trailers' status");
        if premature {
            assert!(
                t.failed,
                "a nonterminal status is refused, never successful: {got:?}"
            );
            assert_eq!(t.status, Some(msg::INTERNAL));
            assert!(
                got.iter().all(|piece| piece.status != Some(0)),
                "the premature OK never crosses back"
            );
        } else {
            let data = frames(&got, 1);
            assert_eq!(
                data.first().copied(),
                Some(msg::frame(b"answer").as_slice()),
                "the legitimate message reaches the host: {got:?}"
            );
            assert_eq!(
                t.status,
                Some(13),
                "the actual final trailers supply the status: {got:?}"
            );
        }
    }
}

/// A gRPC CALL IS A POST. A `GET` with a gRPC content-type is answered here and never handed up.
/// RED: it was handed up as a call whose method is GET.
#[test]
fn a_get_with_a_grpc_content_type_is_refused_and_never_handed_up() {
    let mut a = Conn::accept(posture(), 5 * SEC);
    let mut wire = opening(Some("trailers"));
    let at = wire.iter().rposition(|b| *b == 0x83).expect(":method POST");
    wire[at] = 0x82; // :method GET
    a.ingest(&wire, false);
    a.drive(5 * SEC);
    let got: Vec<Piece> = a.pieces().drain(..).collect();
    assert!(got.is_empty(), "a GET was handed up as a call: {got:?}");
    assert!(!a.take_wire(usize::MAX).is_empty(), "it was answered");
    // Its id is used; the next call (arrival 2, h2 stream 3) is still served.
    let mut next = opening(Some("trailers"));
    next.drain(..24 + 9);
    let mut block_frame = next.split_off(0);
    block_frame[8] = 3; // stream 3
    a.ingest(&block_frame, false);
    a.drive(5 * SEC);
    let got: Vec<Piece> = a.pieces().drain(..).collect();
    assert_eq!(
        head(&got, 2).head.as_ref().map(|w| w.method.as_ref()),
        Some(&b"POST"[..])
    );
}

/// A DIALLED CALL THIS FRAMER RESETS IS RESET `CANCEL`, as a client's cancel or deadline is
/// (PROTOCOL-HTTP2.md). RED: the reset went out `INTERNAL_ERROR` (2): hyper reads the reason from
/// an `h2::Error` in the body error's source chain, and an `io::Error` hides its inner error.
#[test]
fn a_dialled_call_past_its_deadline_is_reset_cancel() {
    let now = 5 * SEC;
    let mut d = Conn::dial("http://peer.test:50051", posture(), now).expect("dial");
    let mut bytes = msg::render_head(&[("path", b"/pkg.Svc/Get")], Some(1000)).expect("a head");
    bytes.extend_from_slice(&msg::frame(b"k"));
    d.emit(1, &bytes, false, now + 2 * SEC, now).expect("emit");
    let mut sent: Vec<u8> = Vec::new();
    let mut turn = |d: &mut Conn, at: u64| {
        for _ in 0..20 {
            d.drive(at);
            sent.extend(d.take_wire(usize::MAX));
            d.pieces().clear();
        }
    };
    turn(&mut d, now);
    let mut wire = h2(4, 0, 0, &[]);
    wire.extend(h2(4, 1, 0, &[]));
    d.ingest(&wire, false);
    turn(&mut d, now);
    turn(&mut d, now + 2 * SEC);
    assert_eq!(resets(&sent[24..]), vec![(1, 8)], "RST_STREAM CANCEL");
}

#[test]
fn sensitive_query_targets_fail_before_request_construction() {
    let mut c = Conn::dial("http://peer.test:50051", posture(), 0).unwrap();
    let sensitive = super::SensitiveFields::new(vec![":path".into()]).unwrap();
    let result = c.emit_sensitive(
        1,
        &call("/svc/Call?key=secret", &[], &[]),
        true,
        0,
        0,
        sensitive,
    );
    result.unwrap();
    let failed = c
        .pieces()
        .iter()
        .find(|piece| piece.failed)
        .expect("sensitive path refused");
    assert_eq!(failed.status, Some(msg::INTERNAL));
    assert!(!String::from_utf8_lossy(&failed.bytes).contains("key=secret"));
}

#[test]
fn head_buffer_growth_preserves_credentials_until_consumed() {
    let mut head = super::HeadBuf::new(Vec::with_capacity(1));
    super::append_head(&mut head, b"authorization: secret");
    super::append_head(&mut head, b"\r\nx-other: value\r\n\r\n");
    assert_eq!(
        head.as_slice(),
        b"authorization: secret\r\nx-other: value\r\n\r\n"
    );
}

#[test]
fn partial_messages_share_a_connection_budget() {
    let mut p = Pair::new();
    for id in 1..=4 {
        let mut bytes = msg::render_head(&[("path", b"/svc/Call")], None).unwrap();
        bytes.extend_from_slice(&msg::prefix(1 << 20).unwrap());
        bytes.extend(std::iter::repeat_n(7, 900 * 1024));
        p.d.emit(id, &bytes, false, 0, p.now).unwrap();
        p.settle();
    }
    assert!(p
        .got_a
        .iter()
        .any(|piece| piece.status == Some(msg::RESOURCE_EXHAUSTED)));
    let super::Side::Accept(accepted) = &p.a.side else {
        panic!("accepted connection")
    };
    let partial: usize = accepted
        .calls
        .iter()
        .filter_map(|(_, stream)| stream.body.as_ref())
        .map(|(_, messages)| messages.buffered())
        .sum();
    assert!(partial <= super::stream_bound(posture().max_message_bytes));
}

#[test]
fn initial_response_status_fields_do_not_end_a_streaming_response() {
    let mut p = Pair::new();
    p.d.emit(1, &call("/svc/Call", &[], &[b"request"]), true, 0, p.now)
        .unwrap();
    p.settle();
    let mut response = msg::render_head(
        &[
            ("grpc-status", b"0"),
            ("grpc-message", b"premature"),
            ("grpc-status-details-bin", b"cHJlbWF0dXJl"),
            ("x-application", b"kept"),
        ],
        None,
    )
    .unwrap();
    response.extend(msg::frame(b"answer"));
    p.a.emit(1, &response, true, 0, p.now).unwrap();
    p.settle();
    let initial = head(&p.got_d, 1);
    assert_eq!(
        field(&initial.bytes, "x-application"),
        Some(b"kept".to_vec())
    );
    for name in ["grpc-status", "grpc-message", "grpc-status-details-bin"] {
        assert_eq!(field(&initial.bytes, name), None);
    }
    assert!(terminal(&p.got_d, 1).is_none());
    assert_eq!(frames(&p.got_d, 1), vec![msg::frame(b"answer").as_slice()]);
    p.a.end_call(1, b"grpc-status: 13\r\ngrpc-message: actual\r\n", 0)
        .unwrap();
    p.settle();
    assert_eq!(terminal(&p.got_d, 1).unwrap().status, Some(msg::INTERNAL));
}

#[test]
fn a_cancelled_partial_request_releases_its_budget_in_the_same_round() {
    let mut p = Pair::new();
    for id in 1..=2 {
        let mut bytes = msg::render_head(&[("path", b"/svc/Call")], None).unwrap();
        bytes.extend_from_slice(&msg::prefix(1 << 20).unwrap());
        bytes.extend(std::iter::repeat_n(7, 900 * 1024));
        p.d.emit(id, &bytes, false, 0, p.now).unwrap();
        p.settle();
    }
    let super::Side::Accept(accepted) = &mut p.a.side else {
        panic!("accepted");
    };
    assert_eq!(accepted.calls.len(), 2);
    let partial = |accepted: &super::Accept| {
        accepted
            .calls
            .iter()
            .filter_map(|(_, s)| s.body.as_ref())
            .map(|(_, m)| m.buffered())
            .sum::<usize>()
    };
    let before = partial(accepted);
    assert!(before > 1 << 20);
    accepted.calls[0].1.reply.chan.let_go();
    let mut out = std::collections::VecDeque::new();
    let mut room = super::Room::of(&out, 0);
    room.partial = before;
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    accepted.step(&mut out, &mut room, posture().max_message_bytes, &mut cx);
    assert!(partial(accepted) < before);
    assert_eq!(room.partial, partial(accepted));
}

#[test]
fn admission_queue_is_capped_and_reaps_all_reset_requests_in_one_round() {
    use busbar_contract::abi::mechanism::extensions;
    use busbar_contract::abi::sdk::transport::policy::Loans;
    use busbar_contract::abi::transport::guest_policy;
    let initial = guest_policy::encode(7, 1, &[]).unwrap();
    let ext = extensions::encode(&[(guest_policy::EXT_GUEST_POLICY, &initial)]);
    let mut p = Pair::new();
    p.a = p.a.with_policies(Loans::from_initial(&ext).unwrap(), 0);
    for id in 1..=super::PENDING_REQUEST_LIMIT as u64 {
        p.d.emit(id, &call("/svc/Call", &[], &[]), false, 0, p.now)
            .unwrap();
    }
    p.settle();
    let super::Side::Accept(accepted) = &mut p.a.side else {
        panic!("accepted");
    };
    assert_eq!(accepted.waiting.len(), super::PENDING_REQUEST_LIMIT);
    let mut donor = Pair::new();
    donor
        .d
        .emit(1, &call("/svc/Call", &[], &[]), false, 0, donor.now)
        .unwrap();
    donor.settle();
    let super::Side::Accept(donor_accept) = &mut donor.a.side else {
        panic!("accepted");
    };
    let (body, _) = donor_accept.calls[0].1.body.take().unwrap();
    let mut request = http::Request::new(body);
    *request.method_mut() = http::Method::POST;
    request.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static(msg::CONTENT_TYPE),
    );
    let reply = super::Reply::default();
    accepted
        .arrivals
        .lock()
        .unwrap()
        .new
        .push_back((201, request, reply.clone()));
    let mut out = std::collections::VecDeque::new();
    let mut room = super::Room::of(&out, 0);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    accepted.step(&mut out, &mut room, posture().max_message_bytes, &mut cx);
    assert_eq!(accepted.waiting.len(), super::PENDING_REQUEST_LIMIT);
    assert_eq!(
        reply.state.lock().unwrap().head.as_ref().unwrap().0,
        http::StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(reply.chan.ended());
    for request in &accepted.waiting {
        request.reply.chan.let_go();
    }
    accepted.step(&mut out, &mut room, posture().max_message_bytes, &mut cx);
    assert!(accepted.waiting.is_empty());
    assert_eq!(
        out.iter()
            .filter(|piece| piece.status == Some(msg::CANCELLED))
            .count(),
        super::PENDING_REQUEST_LIMIT
    );
}

#[test]
fn partial_responses_share_a_connection_budget() {
    let mut p = Pair::new();
    for id in 1..=4 {
        p.d.emit(id, &call("/svc/Call", &[], &[]), true, 0, p.now)
            .unwrap();
        p.settle();
        let mut bytes = b"\r\n".to_vec();
        bytes.extend_from_slice(&msg::prefix(1 << 20).unwrap());
        bytes.extend(std::iter::repeat_n(7, 900 * 1024));
        p.a.emit(id, &bytes, false, 0, p.now).unwrap();
        p.settle();
    }
    assert!(p
        .got_d
        .iter()
        .any(|piece| piece.status == Some(msg::RESOURCE_EXHAUSTED)));
    let super::Side::Dial(dial) = &p.d.side else {
        panic!("dialled");
    };
    let partial: usize = dial
        .calls
        .iter()
        .map(|(_, stream)| match &stream.stage {
            super::DStage::Body(_, messages) => messages.buffered(),
            _ => 0,
        })
        .sum();
    assert!(partial <= super::stream_bound(posture().max_message_bytes));
}

#[test]
fn accepted_headers_and_resets_wait_for_the_host_to_drain() {
    let mut p = Pair::new();
    p.d.emit(1, &call("/svc/Call", &[], &[]), false, 0, p.now)
        .unwrap();
    p.settle();
    let super::Side::Accept(accepted) = &mut p.a.side else {
        panic!("accepted");
    };
    let (body, _) = accepted.calls[0].1.body.take().unwrap();
    accepted.calls[0].1.reply.chan.let_go();
    let mut request = http::Request::new(body);
    *request.method_mut() = http::Method::POST;
    request.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static(msg::CONTENT_TYPE),
    );
    accepted
        .arrivals
        .lock()
        .unwrap()
        .new
        .push_back((2, request, super::Reply::default()));
    let mut out = std::collections::VecDeque::from([Piece::data(
        99,
        bytes::Bytes::from(vec![0; super::INBOUND_HIGH_WATER]),
    )]);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    for _ in 0..3 {
        let mut room = super::Room::of(&out, 0);
        accepted.step(&mut out, &mut room, posture().max_message_bytes, &mut cx);
        assert!(room.held_back);
        assert_eq!(out.len(), 1);
        assert_eq!(accepted.arrivals.lock().unwrap().new.len(), 1);
        assert_eq!(accepted.calls.len(), 1);
    }
    out.clear();
    let mut room = super::Room::of(&out, 0);
    accepted.step(&mut out, &mut room, posture().max_message_bytes, &mut cx);
    assert!(accepted.arrivals.lock().unwrap().new.is_empty());
    assert!(out
        .iter()
        .any(|piece| piece.stream == 2 && piece.head.is_some()));
    assert!(out
        .iter()
        .any(|piece| piece.stream == 1 && piece.status == Some(msg::CANCELLED)));
}

#[test]
fn accepted_reset_keeps_its_reason_when_the_reply_is_dropped_first() {
    use busbar_contract::abi::mechanism::extensions;
    use busbar_contract::abi::sdk::transport::policy::Loans;
    use busbar_contract::abi::transport::guest_policy;
    for waiting in [false, true] {
        for code in [1u32, 2, 3, 7, 8, 11, 12] {
            let mut a = Conn::accept(posture(), 5 * SEC);
            if waiting {
                let initial = guest_policy::encode(7, 1, &[]).unwrap();
                let ext = extensions::encode(&[(guest_policy::EXT_GUEST_POLICY, &initial)]);
                a = a.with_policies(Loans::from_initial(&ext).unwrap(), 0);
            }
            a.ingest(&opening(Some("trailers")), false);
            a.drive(5 * SEC);
            a.pieces().clear();
            drop(a.take_wire(usize::MAX));
            a.ingest(&h2(3, 0, 1, &code.to_be_bytes()), false);
            a.drive(5 * SEC);
            let got: Vec<_> = a.pieces().drain(..).collect();
            let ended = terminal(&got, 1).expect("reset ends the accepted call");
            assert_eq!(
                ended.status,
                Some(msg::status_of_reset(code)),
                "reset {code}, waiting {waiting}"
            );
            assert_eq!(held(&a), 0);
            let super::Side::Accept(accepted) = &a.side else {
                unreachable!()
            };
            assert!(accepted.waiting.is_empty());
        }
    }
}

/// A peer can close a drained connection without first sending GOAWAY.
#[test]
fn eof_after_a_complete_call_ends_the_connection_without_failure() {
    for same_drive in [false, true] {
        let mut p = open_call(true, b"");
        p.a.end_call(1, b"grpc-status: 0\r\n", 0).expect("end");
        if same_drive {
            p.a.drive(p.now);
            let wire = p.a.take_wire(usize::MAX);
            p.d.ingest(&wire, true);
            p.d.drive(p.now);
            p.got_d.extend(p.d.pieces().drain(..));
        } else {
            p.settle();
            p.d.ingest(&[], true);
            p.d.drive(p.now);
        }
        assert_eq!(terminal(&p.got_d, 1).unwrap().status, Some(msg::OK));
        assert!(p.d.ended(), "same_drive {same_drive}");
        assert_eq!(p.d.failure(), None, "same_drive {same_drive}");
    }
}

#[test]
fn eof_with_an_unfinished_call_still_fails_the_connection() {
    let mut p = open_call(true, b"");
    p.d.ingest(&[], true);
    p.d.drive(p.now);
    assert!(p.d.failure().is_some());
    assert!(p.d.pieces().iter().any(|piece| piece.failed));
}

#[test]
fn eof_inside_a_frame_after_a_complete_call_still_fails() {
    for prefix in [3, 10] {
        let mut p = open_call(true, b"");
        p.a.end_call(1, b"grpc-status: 0\r\n", 0).expect("end");
        p.settle();
        // A PING truncated in its frame header or payload is never a clean EOF.
        let ping = h2(6, 0, 0, &[0; 8]);
        p.d.ingest(&ping[..prefix], true);
        p.d.drive(p.now);
        assert!(p.d.failure().is_some(), "prefix {prefix}");
    }
}

#[test]
fn eof_before_the_peer_settings_still_fails() {
    let mut d = Conn::dial("http://peer.test:50051", posture(), 0).expect("dial");
    d.drive(0);
    d.ingest(&[], true);
    d.drive(0);
    assert!(d.failure().is_some());
}

/// Leave a legal maximum-sized response incomplete so normal WINDOW_UPDATE traffic
/// transfers its prefix without filling the host's output queue. The final DATA,
/// a second message, trailers and EOF arrive in one drive.
fn buffered_reply_eof(trailers: bool, truncated: bool) -> (Pair, Vec<u8>) {
    let mut p = open_call(true, b"");
    let payload = vec![0x5a; super::INBOUND_HIGH_WATER];
    let framed = msg::frame(&payload);
    let split = framed.len() - 1024;
    p.a.emit(1, &framed[..split], false, 0, p.now).unwrap();
    p.settle();
    assert!(p.d.pieces().is_empty());
    let mut last = framed[split..].to_vec();
    last.extend(msg::frame(b"tail"));
    p.a.emit(1, &last, false, 0, p.now).unwrap();
    if trailers {
        p.a.end_call(1, b"grpc-status: 0\r\n", 0).unwrap();
    }
    p.a.drive(p.now);
    let mut wire = p.a.take_wire(usize::MAX);
    assert!(!wire.is_empty());
    if truncated {
        wire.extend_from_slice(&h2(6, 0, 0, &[0; 8])[..10]);
    }
    p.d.ingest(&wire, true);
    p.d.drive(p.now);
    assert!(
        p.d.held_back,
        "the actual response reached the host high-water mark"
    );
    assert!(held_for_host(&p.d) >= super::INBOUND_HIGH_WATER);
    (p, payload)
}

#[test]
fn eof_drains_buffered_body_and_trailers_after_host_backpressure() {
    let (mut p, payload) = buffered_reply_eof(true, false);
    assert_eq!(p.d.failure(), None, "complete frames remain drainable");
    assert!(
        p.d.wire_pending(),
        "the host must be recalled to drain the reply"
    );
    assert!(terminal(&p.got_d, 1).is_none());
    let queued = held_for_host(&p.d);
    for _ in 0..3 {
        p.d.drive(p.now);
        assert_eq!(held_for_host(&p.d), queued, "backpressure remains bounded");
        assert_eq!(p.d.failure(), None);
    }
    p.got_d.extend(p.d.pieces().drain(..));
    p.d.drive(p.now);
    p.got_d.extend(p.d.pieces().drain(..));
    let bodies: Vec<_> = p
        .got_d
        .iter()
        .filter(|piece| !piece.fields && !piece.end && !piece.bytes.is_empty())
        .map(|piece| piece.bytes.as_ref())
        .collect();
    assert_eq!(
        bodies,
        vec![
            msg::frame(&payload).as_slice(),
            msg::frame(b"tail").as_slice()
        ]
    );
    assert_eq!(terminal(&p.got_d, 1).unwrap().status, Some(msg::OK));
    assert!(!p.got_d.iter().any(|piece| piece.failed));
    assert_eq!(held(&p.d), 0);
    assert!(p.d.ended());
    assert_eq!(p.d.failure(), None);
}

#[test]
fn eof_buffered_body_without_trailers_still_fails_after_drain() {
    let (mut p, _) = buffered_reply_eof(false, false);
    p.got_d.extend(p.d.pieces().drain(..));
    p.d.drive(p.now);
    assert!(p.d.failure().is_some());
    assert!(p.d.pieces().iter().any(|piece| piece.failed));
}

#[test]
fn eof_buffered_body_with_truncated_frame_still_fails() {
    let (p, _) = buffered_reply_eof(true, true);
    assert!(p.d.failure().is_some());
}
