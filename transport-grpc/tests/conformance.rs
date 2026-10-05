// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `grpc` DOOR'S CONFORMANCE: the same door, compiled in and dropped in, driven the same way.
//!
//! The test is the HOST (`common`): it holds an in-memory socket whose far end is tonic's service
//! (dialled scenarios) or tonic's client (the accepted scenario), a virtual clock, and the sink.
//! Every answer is judged by the transport kind's own check. Each scenario runs through the
//! linked door and through the cdylib `cargo test` built from `examples/grpc_door.rs`. Both
//! must print the same proof lines, and an exchange re-called through a tiny sink must equal
//! the roomy one byte for byte.

mod common;

use std::time::Duration;

use bytes::Bytes;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::transport::{
    Ops, SIDE_ACCEPT, SIDE_DIAL, STATUS_CALLER_FAULT, STATUS_FAR_END_FAULT, STATUS_SUCCESS,
};
use common::*;

const QUIET: Duration = Duration::from_millis(300);

/// Dial scenarios against tonic's service; answer the proof lines.
fn dial(ops: &'static Ops, rt: &tokio::runtime::Runtime, caps: Caps) -> (Vec<String>, Host) {
    let mut proof = Vec::new();
    let mut host = Host::open(ops, "{}", caps);
    let loc = host.locate("http://peer.test:50051").expect("locate");
    proof.push(format!("locate {loc:?}"));
    host.begin(
        SIDE_DIAL,
        "http://peer.test:50051",
        "",
        Some(serve_in_memory(rt)),
    );
    let t0 = host.now;

    // Unary, with the caller's deadline five seconds out.
    host.ask(1, "/t.T/Unary", b"hello", t0 + 5 * SEC);
    host.pump_until(QUIET, |_| false);
    let f = host.frames(1);
    proof.push(format!(
        "unary head x-answer={:?} content-type={:?}",
        field(&f[0], "x-answer"),
        field(&f[0], "content-type")
    ));
    proof.push(format!("unary messages {:?}", &f[1..]));
    proof.push(format!("unary terminal {:?}", host.terminal(1)));
    assert_eq!(field(&f[0], "x-answer").as_deref(), Some("yes"));
    assert_eq!(f[1..], [lpm(b"got:hello;timeout=5000000u")]);
    assert_eq!(host.terminal(1), Some((0, STATUS_SUCCESS, false, vec![])));

    // Server streaming.
    host.ask(3, "/t.T/List", b"q", t0 + 5 * SEC);
    host.pump_until(QUIET, |_| false);
    let f = host.frames(3);
    proof.push(format!("list messages {:?}", &f[1..]));
    assert_eq!(f[1..], [lpm(b"a"), lpm(b"bb"), lpm(b"ccc")]);
    assert_eq!(host.terminal(3), Some((0, STATUS_SUCCESS, false, vec![])));

    // A non-zero status: trailers-only, percent-encoded message, classed as the caller's fault.
    host.ask(5, "/t.T/Fail", b"k", t0 + 5 * SEC);
    host.pump_until(QUIET, |_| false);
    proof.push(format!("fail terminal {:?}", host.terminal(5)));
    assert_eq!(
        host.terminal(5),
        Some((5, STATUS_CALLER_FAULT, true, FAIL_TEXT.as_bytes().to_vec()))
    );

    // An unknown method: UNIMPLEMENTED, the far end's fault.
    host.ask(7, "/t.T/Nope", b"", t0 + 5 * SEC);
    host.pump_until(QUIET, |_| false);
    let t = host.terminal(7).expect("terminal");
    proof.push(format!("nope terminal code={} class={}", t.0, t.1));
    assert_eq!((t.0, t.1, t.2), (12, STATUS_FAR_END_FAULT, true));

    // A call the far end never answers: DEADLINE_EXCEEDED at the caller's deadline, not before.
    host.ask(9, "/t.T/Hang", b"", t0 + 2 * SEC);
    host.pump_until(QUIET, |_| false);
    proof.push(format!(
        "hang asks back at {:?}",
        host.next_deadline().map(|d| d - t0)
    ));
    assert_eq!(host.advance(t0 + 2 * SEC - 1), Outcome::Ready);
    assert!(host.terminal(9).is_none(), "not before the deadline");
    assert_eq!(host.advance(t0 + 2 * SEC), Outcome::Ready);
    let t = host.terminal(9).expect("terminal");
    proof.push(format!("hang terminal code={} failed={}", t.0, t.2));
    assert_eq!((t.0, t.2), (4, true));
    (proof, host)
}

/// The accepted scenario: tonic's client calls this door, and the host answers.
fn accept(ops: &'static Ops, rt: &tokio::runtime::Runtime) -> Vec<String> {
    let mut proof = Vec::new();
    let (cli, srv) = tokio::io::duplex(1 << 20);
    let mut host = Host::open(ops, "{}", ROOMY);
    host.begin(SIDE_ACCEPT, "", "", Some(bridge(rt, srv)));
    let io = std::sync::Mutex::new(Some(cli));
    let channel = rt
        .block_on(
            tonic::transport::Endpoint::from_static("http://door.test").connect_with_connector(
                tower::service_fn(move |_| {
                    let io = io.lock().expect("io").take();
                    async move {
                        io.map(hyper_util::rt::TokioIo::new)
                            .ok_or_else(|| std::io::Error::other("one connection only"))
                    }
                }),
            ),
        )
        .expect("channel");
    let call = rt.spawn(async move {
        let mut g = tonic::client::Grpc::new(channel);
        g.ready().await.expect("ready");
        let mut req = tonic::Request::new(b"ping".to_vec());
        req.metadata_mut()
            .insert("x-meta", "one".parse().expect("value"));
        g.unary(
            req,
            http::uri::PathAndQuery::from_static("/t.T/Unary"),
            RawCodec,
        )
        .await
    });
    // The call's head, its message, then the client's last.
    host.pump_until(QUIET, |_| false);
    let f = host.frames(1);
    let words = host.head_words(1).expect("the call's head words");
    proof.push(format!(
        "accepted head words={words:?} x-meta={:?} content-type={:?} te={:?}",
        field(&f[0], "x-meta"),
        field(&f[0], "content-type"),
        field(&f[0], "te")
    ));
    proof.push(format!("accepted messages {:?}", &f[1..]));
    assert_eq!(
        words,
        ("POST".into(), "/t.T/Unary".into(), "door.test".into())
    );
    assert_eq!(field(&f[0], "path"), None, "no pseudo-field");
    assert_eq!(field(&f[0], "te"), None, "te is checked, then dropped");
    assert_eq!(
        f[1..],
        [lpm(b"ping"), vec![]],
        "the message, then the client's last"
    );

    let mut answer = b"x-answer: yes\r\n\r\n".to_vec();
    answer.extend_from_slice(&lpm(b"pong"));
    assert_eq!(host.emit(1, &answer, true, 0), Outcome::Ready);
    assert_eq!(host.refuse(1, b"grpc-status: 0\r\n"), Outcome::Ready);
    host.pump_until(QUIET, |_| false);
    let r = rt
        .block_on(async { tokio::time::timeout(Duration::from_secs(5), call).await })
        .expect("the client's call ends")
        .expect("join")
        .expect("status OK");
    let answered = format!(
        "client got {:?} x-answer={:?}",
        r.get_ref(),
        r.metadata().get("x-answer")
    );
    proof.push(answered);
    assert_eq!(r.get_ref().as_ref(), b"pong");
    host.close();
    proof
}

/// `frames` with every `date:` line taken out. The server stamps each answer's head with the second
/// it answered in. That field is not the framer's, so both runs lose it before they are compared.
fn undated(frames: &[u8]) -> Vec<u8> {
    let mut out = frames.to_vec();
    while let Some(at) = out.windows(6).position(|w| w == b"date: ") {
        let end = at
            + out[at..]
                .windows(2)
                .position(|w| w == b"\r\n")
                .expect("a line")
            + 2;
        out.drain(at..end);
    }
    out
}

/// The re-call rule's check: an exchange collected through a sink so small that every op is
/// re-called must be the SAME frame bytes as one collected through a roomy sink.
fn recall_continues(tight: &[u8], roomy: &[u8]) -> Result<(), String> {
    let (tight, roomy) = (undated(tight), undated(roomy));
    if tight == roomy {
        Ok(())
    } else {
        Err(format!(
            "frames differ: {} bytes vs {}",
            tight.len(),
            roomy.len()
        ))
    }
}

/// Two images' proof lines must be the same lines.
fn same_proof(a: &[String], b: &[String]) -> Result<(), String> {
    match a.iter().zip(b).position(|(x, y)| x != y) {
        None if a.len() == b.len() => Ok(()),
        None => Err(format!("{} lines vs {}", a.len(), b.len())),
        Some(i) => Err(format!("line {i}: {:?} vs {:?}", a[i], b[i])),
    }
}

#[test]
fn the_linked_and_the_dropped_in_door_frame_the_same() {
    let rt = runtime();
    let l = linked();
    let (d, _lib) = dropped();
    assert!(
        !std::ptr::eq(l, d),
        "two images: the linked table and the dropped-in one"
    );
    let mut runs = Vec::new();
    for (image, ops) in [("linked", l), ("dropped", d)] {
        let (mut proof, host) = dial(ops, &rt, ROOMY);
        host.close();
        proof.extend(accept(ops, &rt));
        for line in &proof {
            println!("PROOF {image}: {line}");
        }
        runs.push(proof);
    }
    assert_eq!(same_proof(&runs[0], &runs[1]), Ok(()));
    // RED: a dropped-in image that answered one line differently is caught.
    let mut off = runs[1].clone();
    off[2].push('!');
    assert!(
        same_proof(&runs[0], &off).is_err(),
        "a differing line is caught"
    );
}

#[test]
fn a_yield_more_recall_answers_nothing_twice() {
    let rt = runtime();
    let (d, _lib) = dropped();
    for (image, ops) in [("linked", linked()), ("dropped", d)] {
        let (roomy_proof, roomy) = dial(ops, &rt, ROOMY);
        let (tight_proof, tight) = dial(ops, &rt, TIGHT);
        println!(
            "PROOF {image}: re-called frames={} bytes, same as roomy: {:?}",
            tight.frame_log.len(),
            recall_continues(&tight.frame_log, &roomy.frame_log)
        );
        assert_eq!(same_proof(&tight_proof, &roomy_proof), Ok(()));
        assert_eq!(recall_continues(&tight.frame_log, &roomy.frame_log), Ok(()));
        // RED: a framer that answered a piece twice on a re-call is caught.
        let mut dup = tight.frame_log.clone();
        let first = dup[..5].to_vec();
        dup.splice(5..5, first);
        assert!(
            recall_continues(&dup, &roomy.frame_log).is_err(),
            "a duplicated piece is caught"
        );
        tight.close();
        roomy.close();
    }
}

#[test]
fn locate_offers_h2_alone_on_a_secured_target_and_nothing_in_the_clear() {
    let (d, _lib) = dropped();
    for ops in [linked(), d] {
        let mut host = Host::open(ops, "{}", ROOMY);
        let tls = host.locate("https://peer.test").expect("locate");
        assert_eq!(
            (
                tls.authority.as_str(),
                tls.name.as_str(),
                tls.secure,
                tls.offer.as_slice()
            ),
            ("peer.test:443", "peer.test", true, &b"\x02h2"[..])
        );
        let clear = host.locate("http://[::1]:50051").expect("locate");
        assert_eq!(
            (
                clear.authority.as_str(),
                clear.secure,
                clear.offer.as_slice()
            ),
            ("[::1]:50051", false, &b""[..])
        );
        assert_eq!(host.locate("grpc://peer.test"), Err(Outcome::Failed));
        host.close();
    }
}

// ── ONE STREAM (`SIDE_ACCEPT_STREAM`, ARCHITECT 4l) ──────────────────────────────────────────────

/// The unit's message on the close: every byte tonic 0.14 percent-encodes, and some it does not.
const MESSAGE: &str = "not here: \u{2713} 100% {x} <y> `z` ?q #h \"s\" ok-_.~";
/// The unit's details, raw (the value it writes is their base64, without padding, verbatim).
const DETAILS: &[u8] = &[0x08, 0x05, 0x12, 0x03, b'a', b'b', 0xff, 0x00, 0x7f];

/// Base64, standard alphabet, without padding: the value 1.5.5's tonic wrote for raw details.
fn b64_nopad(raw: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in raw.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for k in 0..=chunk.len() {
            out.push(char::from(A[((n >> (18 - 6 * k)) & 63) as usize]));
        }
    }
    out
}

/// What 1.5.5's gRPC line wrote for a status: tonic 0.14's own header rendering, as field lines
/// (with `head`: the trailers-only answer's `:status` and `content-type` first, `into_http`).
fn tonic_block(status: tonic::Status, head: bool) -> String {
    let mut out = String::new();
    let map = if head {
        let r = status.into_http::<()>();
        out.push_str(&format!(":status: {}\r\n", r.status().as_u16()));
        r.headers().clone()
    } else {
        let mut map = http::HeaderMap::new();
        status
            .add_header(&mut map)
            .expect("tonic renders the status");
        map
    };
    for (n, v) in &map {
        out.push_str(&format!("{n}: {}\r\n", v.to_str().expect("text")));
    }
    out
}

/// One stream through `ops`: its body's messages, a reply framed, and the close rendered from the
/// close's final tail alone; the proof lines, and the closing block.
fn one_stream(ops: &'static Ops, caps: Caps) -> (Vec<String>, String) {
    let mut proof = Vec::new();
    let mut host = Host::open(ops, "{}", caps);
    let fields = [("content-type", "application/grpc"), ("te", "trailers")];
    assert_eq!(host.begin_stream("/t.T/Unary", &fields), Outcome::Ready);
    let mut body = lpm(b"hello");
    body.extend(lpm(b""));
    body.extend(lpm(b"again"));
    assert_eq!(host.feed(&body, true), Outcome::Ready);
    let messages = host.frames(1);
    proof.push(format!("messages {messages:?}"));
    assert_eq!(
        messages,
        [b"hello".to_vec(), Vec::new(), b"again".to_vec()],
        "each message's payload, an empty one too"
    );
    let at = host.wire_log.len();
    assert_eq!(host.emit(1, b"got:", false, 0), Outcome::Ready);
    assert_eq!(host.emit(1, b"hello", true, 0), Outcome::Ready);
    let reply = host.wire_log[at..].to_vec();
    proof.push(format!("reply {reply:?}"));
    assert_eq!(
        reply,
        lpm(b"got:hello"),
        "one reply message, length-prefixed"
    );
    let at = host.wire_log.len();
    let details = b64_nopad(DETAILS);
    assert_eq!(
        host.finish_final(5, MESSAGE.as_bytes(), details.as_bytes()),
        Outcome::Ready
    );
    let block = String::from_utf8(host.wire_log[at..].to_vec()).expect("text");
    proof.push(format!("close {block:?}"));
    host.close();
    (proof, block)
}

/// THE CLOSE IS THE DOOR'S, BOTH WAYS IN, IN 1.5.5'S BYTES: the linked and the dropped-in door
/// frame one stream the same (a tight sink's re-calls included), and the closing block is the
/// trailers tonic 0.14 wrote for the same status, message and details (a status-with-details cell),
/// and for a whole end.
#[test]
fn the_linked_and_the_dropped_in_door_close_one_stream_the_same_in_1_5_5s_bytes() {
    let l = linked();
    let (d, _lib) = dropped();
    let mut runs = Vec::new();
    for (image, ops) in [("linked", l), ("dropped", d)] {
        for caps in [ROOMY, TIGHT] {
            let (proof, block) = one_stream(ops, caps);
            for line in &proof {
                println!("PROOF {image}: {line}");
            }
            assert_eq!(
                block,
                tonic_block(
                    tonic::Status::with_details(
                        tonic::Code::NotFound,
                        MESSAGE,
                        Bytes::from_static(DETAILS)
                    ),
                    false
                ),
                "{image}: the close is 1.5.5's trailers, byte for byte"
            );
            runs.push(proof);
        }
    }
    for run in &runs[1..] {
        assert_eq!(same_proof(&runs[0], run), Ok(()));
    }
    // A whole end: `grpc-status: 0` alone.
    let mut host = Host::open(l, "{}", ROOMY);
    host.begin_stream("/t.T/Unary", &[("content-type", "application/grpc")]);
    let at = host.wire_log.len();
    assert_eq!(host.finish_final(0, b"", b""), Outcome::Ready);
    assert_eq!(
        String::from_utf8_lossy(&host.wire_log[at..]),
        tonic_block(tonic::Status::new(tonic::Code::Ok, ""), false)
    );
    host.close();
}

/// A STREAM REFUSED BEFORE ANY REPLY is the door's trailers-only answer, in 1.5.5's bytes (tonic
/// 0.14's `into_http` for the status the refusal's neutral status maps to, predev's words).
#[test]
fn a_stream_refused_before_any_reply_is_1_5_5s_trailers_only_answer() {
    let (d, _lib) = dropped();
    for ops in [linked(), d] {
        let mut host = Host::open(ops, "{}", ROOMY);
        host.begin_stream("/t.T/Unary", &[("content-type", "application/grpc")]);
        let at = host.wire_log.len();
        assert_eq!(host.refuse_as(1, b"", 401), Outcome::Ready);
        assert_eq!(
            String::from_utf8_lossy(&host.wire_log[at..]),
            tonic_block(
                tonic::Status::new(tonic::Code::Unauthenticated, "busbar answered HTTP 401"),
                true
            )
        );
        host.close();
    }
}

/// RED: a call that is not gRPC is refused at `begin`; details that are not one field value fail
/// the close.
#[test]
fn a_call_that_is_not_grpc_and_details_that_are_not_a_value_are_refused() {
    let mut host = Host::open(linked(), "{}", ROOMY);
    assert_eq!(
        host.begin_stream("/t.T/Unary", &[("content-type", "application/json")]),
        Outcome::Refused
    );
    let mut host = Host::open(linked(), "{}", ROOMY);
    host.begin_stream("/t.T/Unary", &[("content-type", "application/grpc")]);
    assert_eq!(
        host.finish_final(13, b"x", b"line\r\nbreak"),
        Outcome::Failed
    );
}
