// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The engine, both sides at once: a dialled [`Conn`] and an accepted one wired back to back, the
//! test carrying each one's wire bytes to the other and holding the clock.

use std::time::Duration;

use crate::hyper_io::{Owed, Piece};

use super::{Conn, Posture};
use crate::msg;

const SEC: u64 = 1_000_000_000;

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

    // The accepted side sees the call's head (its head words in the slots, never as fields), its
    // one message, and the far end's last (the empty piece): the dialled side sent END_STREAM
    // after the message.
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

    // The dialled side: the head (no code), the message, the trailers carrying grpc-status, and
    // the empty terminal piece.
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
    // RED arm of the half-close: a call whose head states no length and whose frame does not end
    // leaves the request stream open, and the accepted side never sees the far end's last.
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
    // The frame's end is the half-close.
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
    // Nothing emitted first: the status goes out in the one HEADERS frame.
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
    // The accepted side numbers calls in arrival order.
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
    let mut block = vec![0x83, 0x86]; // :method POST, :scheme http
    block.push(0x04); // :path, by its static name
    lit(&mut block, "/pkg.Svc/Say");
    block.push(0x01); // :authority
    lit(&mut block, "peer.test");
    block.extend_from_slice(&[0x0f, 0x10]); // content-type (static index 31)
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
    // END_HEADERS.
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

/// RED: a `te` other than `trailers` is reset with HTTP/2 `PROTOCOL_ERROR` before it is a call,
/// as predev's server (tonic 0.14 over h2 0.4; v1.5.5 served no gRPC) did; nothing is handed up.
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
    // `te: trailers` is served too, and dropped as hop-by-hop.
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
/// UNAVAILABLE), on a head and its status block, exactly as a trailers-only answer arrives. It is
/// never a failed stream with nothing read, which the host would take for no answer at all and
/// fail over as transient. 1.5.5's breaker read an HTTP 401 or 403 as `Auth`, which is `HardDown`
/// (v1.5.5 `crates/busbar/src/breaker.rs`, its step 2 and its `Auth | Billing => HardDown`
/// arm), and this framer's fault table reads UNAUTHENTICATED and PERMISSION_DENIED as hard.
#[test]
fn a_bare_http_status_answer_is_an_answer_with_the_status_it_stands_for() {
    use busbar_contract::abi::transport::{FAULT_CALLER, FAULT_HARD, FAULT_TRANSIENT};
    // The fault reading is the HTTP status's own, by 1.5.5's bands:
    // a bare 400 is INTERNAL to the caller but the caller's fault to the breaker, as 1.5.5 read it.
    for (http, grpc, fault) in [
        (401u16, msg::UNAUTHENTICATED, FAULT_HARD),
        (403, msg::PERMISSION_DENIED, FAULT_HARD),
        (503, msg::UNAVAILABLE, FAULT_TRANSIENT),
        (400, msg::INTERNAL, FAULT_CALLER),
        (409, msg::UNKNOWN, FAULT_CALLER),
        (500, msg::UNKNOWN, FAULT_TRANSIENT),
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
        // The far end, by hand: its SETTINGS and the ACK of ours once the call is on the wire,
        // then one HEADERS frame ending the stream with `:status` alone (HPACK literal without
        // indexing, the name `:status` at static index 8).
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
/// stream failing `CANCELLED`, the call is let go of, and an answer emitted after it queues
/// nothing.
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
    assert!(
        a.emit(1, &msg::frame(b"two"), false, 0, 5 * SEC).is_err(),
        "nothing more is taken for the cancelled call"
    );
    assert!(a.pieces().is_empty(), "one terminal piece, once");
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
/// arrive after the stream's terminal piece. They open nothing: no second terminal piece, no
/// held call, and no deadline firing later on a stream the host already saw end.
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
/// emitting past the mark is the framer's to bound: it may fail the stream"). RED before the fix:
/// every emitted message waited in an unbounded queue behind the shut window.
#[test]
fn an_answer_the_far_end_never_reads_is_bounded_and_fails_resource_exhausted() {
    let mut a = half_closed();
    a.emit(1, b"\r\n", false, 0, 5 * SEC).expect("answer head");
    let m = msg::frame(&[7u8; 60_000]);
    let (mut most, mut got) = (0, Vec::new());
    for _ in 0..200 {
        // Once the stream failed, an emit on it is the host's late one: dropped or refused.
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
/// (`YIELD_STREAM_FULL`, which the door sets from [`Conn::announce_full`]), and nothing fails. Once
/// the far end opens its windows and the queue drains to its low-water mark, the stream hands one
/// writable piece (`PIECE_WRITABLE`), and only then.
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
    // The far end opens the connection's window and the stream's.
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
/// nothing more) is held to the bound, and fails `RESOURCE_EXHAUSTED` past it. RED before the fix.
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
    // The far end's SETTINGS and the ACK of ours: the call goes out, and no window ever opens.
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
        format!("the answer's message is {over} bytes, over the limit of {limit} bytes")
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
        // `hyper` reads a NO_ERROR reset after the head as the body's end: the answer ended with
        // no trailers, and that is INTERNAL in its own words.
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

// The gRPC over HTTP/2 table (PROTOCOL-HTTP2.md, "Errors"), one test per code.

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
/// `PROTOCOL_ERROR` itself, and the call fails `INTERNAL`. RED: UNAVAILABLE, a local reset not read
/// by its code.
#[test]
fn a_local_reset_is_read_by_its_code() {
    // HPACK: `:status: 200` (static index 8), then `connection: close` as a literal.
    let mut block = vec![0x88, 0x00, 10];
    block.extend_from_slice(b"connection");
    block.push(5);
    block.extend_from_slice(b"close");
    let t = far_end_sends(open_call(false, b""), &h2(1, 0x4, 1, &block));
    assert_eq!(t.status, Some(msg::INTERNAL));
    assert_eq!(t.bytes.as_ref(), b"the stream was reset: PROTOCOL_ERROR");
}

/// A GOAWAY THAT LEAVES THE STREAM UNPROCESSED is read by its code, as a reset is: last stream 0
/// and `ENHANCE_YOUR_CALM` fail the open call `RESOURCE_EXHAUSTED`. RED: UNAVAILABLE.
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
/// far end's bytes end with the call open. RED: INTERNAL after the head, with `hyper`'s text.
#[test]
fn a_connection_lost_before_any_status_fails_the_call_unavailable() {
    for after_head in [false, true] {
        let mut p = open_call(after_head, b"");
        p.d.ingest(&[], true);
        p.settle();
        let t = terminal(&p.got_d, 1).cloned().expect("the stream ends");
        assert!(t.failed);
        assert_eq!(t.status, Some(msg::UNAVAILABLE), "after_head {after_head}");
        assert_eq!(
            t.bytes.as_ref(),
            b"the connection to the far end was lost",
            "after_head {after_head}"
        );
    }
}

/// AN ANSWER THAT ENDS INSIDE A MESSAGE, with no trailers (here the far end's NO_ERROR reset after
/// part of a message), is `INTERNAL` in this framer's words. RED: UNKNOWN.
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
/// the head carries. The attempt's deadline still holds the call, here.
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
/// stops working on it and its stream slot is freed. RED: the request body stayed open forever and
/// no RST_STREAM went out.
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
/// (PROTOCOL-HTTP2.md, "GOAWAY Frame": a stream past the last one accepted is `UNAVAILABLE`). RED:
/// INTERNAL, read as a reset's `NO_ERROR`.
#[test]
fn a_graceful_goaway_refusing_an_unprocessed_stream_is_unavailable() {
    let mut payload = 0u32.to_be_bytes().to_vec();
    payload.extend_from_slice(&0u32.to_be_bytes());
    let t = far_end_sends(open_call(false, b""), &h2(7, 0, 0, &payload));
    assert_eq!(t.status, Some(msg::UNAVAILABLE));
    assert_eq!(t.bytes.as_ref(), b"the connection went away: NO_ERROR");
}

/// A DIALLED FRAME THAT ENDS SHORT OF ITS HEAD'S `content-length` FAILS AT ONCE, in words: the head
/// states 20 message bytes and the frame ends after 12. The host hears `INTERNAL` with the reason
/// on that emit, never a `DEADLINE_EXCEEDED` minutes later. RED: the request never ended, and the
/// call hung to its deadline with nothing said.
#[test]
fn a_dialled_frame_ending_short_of_its_content_length_fails_in_words() {
    let mut p = Pair::new();
    let mut c = msg::render_head(&[("path", b"/pkg.Svc/Say")], Some(20)).expect("head");
    c.extend_from_slice(&[0u8; 12]);
    p.d.emit(1, &c, true, 0, p.now).expect("emit");
    p.settle();
    let t = terminal(&p.got_d, 1).cloned().expect("the stream fails at once");
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

/// HPACK, literal without indexing, a new name: `name: value`.
fn lit_field(block: &mut Vec<u8>, name: &str, value: &str) {
    block.push(0x00);
    block.push(u8::try_from(name.len()).expect("short"));
    block.extend_from_slice(name.as_bytes());
    block.push(u8::try_from(value.len()).expect("short"));
    block.extend_from_slice(value.as_bytes());
}

/// A dialled call on stream 1 whose far end answers, by hand, one HEADERS frame ending the stream:
/// `:status` `status`, then `fields`. The pieces the dial hands up.
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
/// the table is only for an answer with no `grpc-status`; one that was provided must be used). A
/// gateway's 403 carrying `grpc-status: 5` and its message is `NOT_FOUND` with that message, and the
/// breaker reads the gRPC status (the caller's), never the 403's hard fault. RED: PERMISSION_DENIED,
/// `HTTP status 403`, hard.
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
    assert_eq!((end.failed, end.bytes.as_ref()), (true, &b"no such key"[..]));
}

/// The same for a 200 whose content type is not gRPC's (or absent): the `grpc-status` it states is
/// its status. RED: UNKNOWN, `the answer is not gRPC`.
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
/// `\u{1b}` and `\n`), and bounded in length. RED: the raw bytes, ESC and LF among them.
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
/// `locate` stated. RED: `:authority` was `user:secret@peer.test:50051`.
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
