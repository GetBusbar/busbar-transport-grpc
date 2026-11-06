// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `grpc` DOOR'S CONFORMANCE: the same door, compiled in and dropped in, driven the same way.

mod common;

use std::time::Duration;

use bytes::Bytes;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::transport::{
    Ops, SIDE_ACCEPT, SIDE_DIAL, STATUS_CALLER_FAULT, STATUS_FAR_END_FAULT, STATUS_SUCCESS,
};
use common::*;

const QUIET: Duration = Duration::from_millis(300);

/// The most a scenario waits on the far end (idle) before it is judged: a loaded runner's stall is
/// waited out, never read as the far end's answer.
const BOUND: Duration = Duration::from_secs(10);

/// Pump until `stream` has its terminal piece, and say so: never index an exchange that is not
/// over.
fn until_over(host: &mut Host, stream: u64) {
    assert_eq!(
        host.pump_until(BOUND, move |got| over(got, stream).is_some()),
        Outcome::Ready
    );
    assert!(over(&host.got, stream).is_some(), "stream {stream} ended");
}

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

    host.ask(1, "/t.T/Unary", b"hello", t0 + 5 * SEC);
    until_over(&mut host, 1);
    let f = host.frames(1);
    proof.push(format!(
        "unary head x-answer={:?} content-type={:?}",
        field(&f[0], "x-answer"),
        field(&f[0], "content-type")
    ));
    proof.push(format!("unary messages {:?}", &f[1..]));
    proof.push(format!("unary terminal {:?}", host.terminal(1)));
    assert_eq!(field(&f[0], "x-answer").as_deref(), Some("yes"));
    assert_eq!(f[1..], [lpm(b"got:hello")], "no grpc-timeout goes upstream");
    assert_eq!(host.terminal(1), Some((0, STATUS_SUCCESS, false, vec![])));

    host.ask(3, "/t.T/List", b"q", t0 + 5 * SEC);
    until_over(&mut host, 3);
    let f = host.frames(3);
    proof.push(format!("list messages {:?}", &f[1..]));
    assert_eq!(f[1..], [lpm(b"a"), lpm(b"bb"), lpm(b"ccc")]);
    assert_eq!(host.terminal(3), Some((0, STATUS_SUCCESS, false, vec![])));

    host.ask(5, "/t.T/Fail", b"k", t0 + 5 * SEC);
    until_over(&mut host, 5);
    proof.push(format!("fail terminal {:?}", host.terminal(5)));
    assert_eq!(
        host.terminal(5),
        Some((5, STATUS_CALLER_FAULT, true, FAIL_TEXT.as_bytes().to_vec()))
    );

    host.ask(7, "/t.T/Nope", b"", t0 + 5 * SEC);
    until_over(&mut host, 7);
    let t = host.terminal(7).expect("terminal");
    proof.push(format!("nope terminal code={} class={}", t.0, t.1));
    assert_eq!((t.0, t.1, t.2), (12, STATUS_FAR_END_FAULT, true));

    host.ask(9, "/t.T/Hang", b"", t0 + 2 * SEC);
    host.pump_until(QUIET, |_| false);
    proof.push(format!(
        "hang asks back at {:?}",
        host.next_deadline().map(|d| d - t0)
    ));
    assert_eq!(
        host.next_deadline(),
        Some(t0 + 2 * SEC),
        "the door asks to be called back exactly at the call's deadline"
    );
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

    let last = |got: &[Got]| got.iter().any(|g| g.stream == 1 && g.end());
    assert_eq!(host.pump_until(BOUND, last), Outcome::Ready);
    assert!(last(&host.got), "the client's last arrived");
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
    assert_eq!(field(&f[0], "x-meta").as_deref(), Some("one"));
    assert_eq!(
        field(&f[0], "content-type").as_deref(),
        Some("application/grpc")
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
/// it answered in.
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

/// A TLS gRPC LISTENER OFFERS `h2`: asked for an ACCEPTING listener's offer (`LocateIn::accept`,
/// the empty target the connector passes), `locate` answers `h2` alone, the protocol every gRPC
/// client negotiates over TLS (tonic's TLS connector and grpc-go refuse a connection without it),
/// and states no authority, name or head line.
#[test]
fn a_listener_is_offered_h2_alone() {
    let (d, _lib) = dropped();
    for ops in [linked(), d] {
        let mut host = Host::open(ops, "{}", ROOMY);
        let l = host.locate_listener().expect("the listener's offer");
        assert_eq!(l.offer.as_slice(), &b"\x02h2"[..]);
        assert_eq!(
            (l.authority.as_str(), l.name.as_str(), l.defaults.as_str()),
            ("", "", "")
        );
        host.close();
    }
}

/// THE FRAMER'S OWN HEAD LINES ARE STATED AT `locate`, so the host puts them in the head BEFORE the
/// auth signs it: the content type and `te: trailers`, in the order the
/// dial writes them, and the dial then sends them as signed.
#[test]
fn locate_states_the_framers_own_head_lines_before_the_auth_signs() {
    let (d, _lib) = dropped();
    for ops in [linked(), d] {
        let mut host = Host::open(ops, "{}", ROOMY);
        let loc = host.locate("https://peer.test").expect("locate");
        assert_eq!(
            loc.defaults,
            "content-type: application/grpc\r\nte: trailers\r\n"
        );
        host.close();
        let mut host = Host::open(ops, r#"{"limits.upstream_request_timeout_secs":5}"#, ROOMY);
        let loc = host.locate("http://peer.test:50051").expect("locate");
        assert_eq!(
            loc.defaults,
            "content-type: application/grpc\r\nte: trailers\r\n"
        );
        host.close();
    }
}

/// The unit's message on the close: every byte tonic 0.14 percent-encodes, and some it does not.
const MESSAGE: &str = "not here: \u{2713} 100% {x} <y> `z` ?q #h \"s\" ok-_.~";
/// The unit's details, raw (the value it writes is their base64, without padding, verbatim).
const DETAILS: &[u8] = &[0x08, 0x05, 0x12, 0x03, b'a', b'b', 0xff, 0x00, 0x7f];

/// Base64, standard alphabet, without padding: the value predev's tonic wrote for raw details.
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

/// What predev's gRPC line wrote for a status: tonic 0.14's own header rendering, as field lines
/// (with `head`: the trailers-only answer's fields, including `content-type`, from `into_http`).
/// The opening HTTP status is separate handoff metadata, never a pseudo-field in this block.
fn tonic_block(status: tonic::Status, head: bool) -> String {
    let mut out = String::new();
    let map = if head {
        let r = status.into_http::<()>();
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

/// A trailers-only reply hands the outer transport its opening status separately from fields.
fn assert_opening_status(host: &Host, at: usize) {
    use busbar_contract::abi::transport::PIECE_CODE_HANDOFF;
    let opening = &host.got[at..];
    assert_eq!(opening.len(), 1, "exactly one opening status handoff");
    let piece = &opening[0];
    assert_eq!((piece.stream, piece.code), (1, 200));
    assert!(piece.fields() && piece.coded());
    assert_ne!(piece.flags & PIECE_CODE_HANDOFF, 0);
    assert!(
        !piece.failed(),
        "the opening HTTP status is not an RPC failure"
    );
    assert!(
        !piece.end(),
        "the opening status is not a terminal stream piece"
    );
    assert!(
        piece.bytes.is_empty(),
        "status is metadata, not a field line"
    );
}

/// One stream through `ops`: its body's messages, a reply framed, and the close rendered from the
/// close's final tail alone; the proof lines, and the closing block.
fn one_stream(ops: &'static Ops, caps: Caps) -> (Vec<String>, String) {
    let mut proof = Vec::new();
    let mut host = Host::open(ops, "{}", caps);
    let fields = [("content-type", "application/grpc"), ("te", "trailers")];
    assert_eq!(host.begin_stream("/t.T/Unary", &fields), Outcome::Ready);
    assert_eq!(
        host.wire_log,
        b"trailer: grpc-status, grpc-message, grpc-status-details-bin, grpc-accept-encoding\r\n",
        "the initial declaration drains through Timer before any body on either sink size"
    );
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

/// THE CLOSE IS THE DOOR'S, BOTH WAYS IN, IN PREDEV'S BYTES: the linked and the dropped-in door
/// frame one stream the same (a tight sink's re-calls included), and the closing block is the
/// trailers tonic 0.14 wrote for the same status, message and details (a status-with-details cell),
/// and for a whole end.
#[test]
fn the_linked_and_the_dropped_in_door_close_one_stream_the_same_in_predevs_bytes() {
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
                "{image}: the close is predev's trailers, byte for byte"
            );
            runs.push(proof);
        }
    }
    for run in &runs[1..] {
        assert_eq!(same_proof(&runs[0], run), Ok(()));
    }
    // A whole end: `grpc-status: 0` alone, on both images.
    let (d, _lib) = dropped();
    for ops in [l, d] {
        let mut host = Host::open(ops, "{}", ROOMY);
        assert_eq!(
            host.begin_stream("/t.T/Unary", &[("content-type", "application/grpc")]),
            Outcome::Ready
        );
        let at = host.wire_log.len();
        assert_eq!(host.finish_final(0, b"", b""), Outcome::Ready);
        assert_eq!(
            String::from_utf8_lossy(&host.wire_log[at..]),
            tonic_block(tonic::Status::new(tonic::Code::Ok, ""), false)
        );
        host.close();
    }
}

/// A STREAM REFUSED BEFORE ANY REPLY is the door's trailers-only answer, in predev's bytes (tonic
/// 0.14's `into_http` for the status the refusal's neutral status maps to, predev's words).
#[test]
fn a_stream_refused_before_any_reply_is_predevs_trailers_only_answer() {
    let (d, _lib) = dropped();
    for ops in [linked(), d] {
        let mut host = Host::open(ops, "{}", ROOMY);
        host.begin_stream("/t.T/Unary", &[("content-type", "application/grpc")]);
        let at = host.wire_log.len();
        let pieces_at = host.got.len();
        assert_eq!(host.refuse_as(1, b"", 401), Outcome::Ready);
        assert_opening_status(&host, pieces_at);
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

/// Non-gRPC calls and details that cannot form a field value are refused.
#[test]
fn a_call_that_is_not_grpc_and_details_that_are_not_a_value_are_refused() {
    use busbar_contract::abi::mechanism::call::Span;
    let (d, _lib) = dropped();
    for ops in [linked(), d] {
        let mut refused = Host::open(ops, "{}", ROOMY);
        assert_eq!(
            refused.begin_stream("/t.T/Unary", &[("content-type", "application/json")]),
            Outcome::Refused
        );
        refused.close();
        let mut host = Host::open(ops, "{}", ROOMY);
        host.begin_stream("/t.T/Unary", &[("content-type", "application/grpc")]);
        let at = host.wire_log.len();
        let (msg_bytes, details) = (b"x", b"line\r\nbreak");
        let blob = [&msg_bytes[..], &details[..]].concat();
        let span = |offset: u32, len: u32| Span { offset, len };
        assert_eq!(
            host.finish_spans(13, &blob, span(0, 1), span(1, 11)),
            (
                Outcome::Failed,
                "finish: the status details are not one field value".to_owned()
            )
        );
        assert_eq!(host.wire_log.len(), at, "nothing written");
        assert_eq!(host.refuse_as(1, b"", 500), Outcome::Ready);
        assert!(
            String::from_utf8_lossy(&host.wire_log[at..]).contains("grpc-status: 2\r\n"),
            "the fallback refusal closes the call"
        );
        host.close();
    }
}

/// A STREAM COMPRESSED WITH AN ENCODING THE DOOR DOES NOT TAKE closes `UNIMPLEMENTED` with the
/// encodings it takes (gRPC's compression rules, `compression.md`), whatever refusal the host closes
/// the failed stream with.
#[test]
fn a_stream_in_an_encoding_the_door_does_not_take_closes_unimplemented() {
    let (d, _lib) = dropped();
    for ops in [linked(), d] {
        let mut host = Host::open(ops, "{}", ROOMY);
        let fields = [
            ("content-type", "application/grpc"),
            ("grpc-encoding", "gzip"),
        ];
        assert_eq!(host.begin_stream("/t.T/Unary", &fields), Outcome::Ready);
        assert_eq!(host.feed(&[1, 0, 0, 0, 1, b'z'], true), Outcome::Failed);
        let at = host.wire_log.len();
        let pieces_at = host.got.len();
        assert_eq!(host.refuse_as(1, b"", 400), Outcome::Ready);
        assert_opening_status(&host, pieces_at);
        assert_eq!(
            String::from_utf8_lossy(&host.wire_log[at..]),
            "content-type: application/grpc\r\ngrpc-accept-encoding: identity\r\n\
             grpc-status: 12\r\ngrpc-message: the%20message%20encoding%20%60gzip%60%20is%20not\
             %20supported:%20this%20server%20takes%20identity\r\n"
        );
        host.close();
    }
}

/// AN OVERSIZE MESSAGE IS REFUSED AT THE CONFIGURED LIMIT, IN THIS FRAMER'S WORDS:
/// `limits.request_body_max_bytes` bounds a message on the accepting side, and the close
/// is `RESOURCE_EXHAUSTED` with text that prints the configured number, whatever refusal the host then
/// closes the failed stream with.
#[test]
fn an_oversize_message_is_refused_at_the_configured_limit_in_this_framers_words() {
    let (d, _lib) = dropped();
    for ops in [linked(), d] {
        let mut host = Host::open(ops, r#"{"limits.request_body_max_bytes":2048}"#, ROOMY);
        let fields = [("content-type", "application/grpc")];
        assert_eq!(host.begin_stream("/t.T/Unary", &fields), Outcome::Ready);
        let mut body = vec![0u8];
        body.extend_from_slice(&2049u32.to_be_bytes());
        assert_eq!(host.feed(&body, false), Outcome::Failed);
        let at = host.wire_log.len();
        let pieces_at = host.got.len();
        assert_eq!(host.refuse_as(1, b"", 400), Outcome::Ready);
        assert_opening_status(&host, pieces_at);
        assert_eq!(
            String::from_utf8_lossy(&host.wire_log[at..]),
            "content-type: application/grpc\r\ngrpc-status: 8\r\n\
             grpc-message: the%20message%20is%202049%20bytes,%20over%20the%20limit%20of%202048\
             %20bytes%20(limits.request_body_max_bytes)\r\n"
        );
        host.close();
    }
}

/// THE SDK'S WORDS, both images: `validate` refuses a blob that is no JSON object and a key this
/// transport does not read (`settings_reading`), and every op of the carrier role (and `detach`,
/// `adopt`) is REFUSED naming the op (`not_served!`), as tcp, stdio and http answer.
#[test]
fn settings_and_the_unserved_ops_answer_the_sdks_words() {
    use busbar_contract::abi::mechanism::call::OutHead;
    use busbar_contract::abi::transport::{
        slot, AcceptIn, AcceptOut, AdoptIn, ArrivalIn, ArrivalOut, ConnIn, ConnOut, DialIn,
        FramerOut, FramingIn, IoOut, ListenIn, ListenOut, ReadIn, ShutIn, WriteIn,
    };
    let (d, _lib) = dropped();
    for ops in [linked(), d] {
        assert_eq!(validate(ops, "{}"), (Outcome::Ready, String::new()));
        for bad in ["not json", "[]"] {
            assert_eq!(
                validate(ops, bad),
                (
                    Outcome::Failed,
                    "settings: must be a JSON object".to_owned()
                ),
                "{bad}"
            );
        }
        assert_eq!(
            validate(ops, r#"{"limits.nope":1}"#),
            (
                Outcome::Failed,
                "settings: limits.nope is not a setting this transport reads".to_owned()
            )
        );
        assert_eq!(
            validate(ops, r#"{"limits.upstream_request_timeout_secs":"5"}"#),
            (
                Outcome::Failed,
                "settings: limits.upstream_request_timeout_secs must be a count of seconds above 0"
                    .to_owned()
            )
        );
        let host = Host::open(ops, "{}", ROOMY);
        let refused = |op: &str| {
            (
                Outcome::Refused,
                format!("{op}: the grpc framer does not serve this op"),
            )
        };
        let o = host.ops;
        let got = [
            // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
            // and the door instance for this synchronous call; the selected slot and index agree.
            unsafe { host.bare::<ListenIn, ListenOut>(o.listen, slot::LISTEN) },
            // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
            // and the door instance for this synchronous call; the selected slot and index agree.
            unsafe { host.bare::<AcceptIn, AcceptOut>(o.accept, slot::ACCEPT) },
            // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
            // and the door instance for this synchronous call; the selected slot and index agree.
            unsafe { host.bare::<DialIn, ConnOut>(o.dial, slot::DIAL) },
            // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
            // and the door instance for this synchronous call; the selected slot and index agree.
            unsafe { host.bare::<ReadIn, IoOut>(o.read, slot::READ) },
            // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
            // and the door instance for this synchronous call; the selected slot and index agree.
            unsafe { host.bare::<WriteIn, IoOut>(o.write, slot::WRITE) },
            // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
            // and the door instance for this synchronous call; the selected slot and index agree.
            unsafe { host.bare::<ConnIn, OutHead>(o.flush, slot::FLUSH) },
            // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
            // and the door instance for this synchronous call; the selected slot and index agree.
            unsafe { host.bare::<ShutIn, OutHead>(o.shut, slot::SHUT) },
            // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
            // and the door instance for this synchronous call; the selected slot and index agree.
            unsafe { host.bare::<ArrivalIn, ArrivalOut>(o.arrival, slot::ARRIVAL) },
            // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
            // and the door instance for this synchronous call; the selected slot and index agree.
            unsafe { host.bare::<FramingIn, FramerOut>(o.detach, slot::DETACH) },
            // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
            // and the door instance for this synchronous call; the selected slot and index agree.
            unsafe { host.bare::<AdoptIn, FramerOut>(o.adopt, slot::ADOPT) },
        ];
        let want = [
            "listen", "accept", "dial", "read", "write", "flush", "shut", "arrival", "detach",
            "adopt",
        ]
        .map(refused);
        assert_eq!(got, want);
        host.close();
    }
}

/// ONE STREAM'S REPLY HAS THE BACKPRESSURE AND THE BOUND A CONNECTION'S STREAM HAS (the transport
/// ABI's "A STREAM'S OWN BACKPRESSURE").
#[test]
fn one_streams_reply_is_answered_full_drains_writable_and_is_bounded() {
    use busbar_contract::abi::transport::{PIECE_WRITABLE, YIELD_STREAM_FULL};
    let (d, _lib) = dropped();
    for ops in [linked(), d] {
        let settings = r#"{"limits.request_body_max_bytes":65536}"#;
        let mut host = Host::open(ops, settings, Caps(4096, 4096, 8));
        let fields = [("content-type", "application/grpc")];
        assert_eq!(host.begin_stream("/t.T/Unary", &fields), Outcome::Ready);
        let m = vec![7u8; 60_000];
        let full = (0..40).find(|_| {
            let (r, flags, _) = host.emit_held(1, &m, true);
            assert_eq!(r, Outcome::Ready);
            flags & YIELD_STREAM_FULL != 0
        });
        assert!(
            full.is_some(),
            "the reply's queue reached its high-water mark"
        );
        assert_eq!(
            host.emit_drain(1),
            Outcome::Ready,
            "the far end reads again"
        );
        let writable: Vec<&Got> = host
            .got
            .iter()
            .filter(|g| g.flags & PIECE_WRITABLE != 0)
            .collect();
        assert_eq!(writable.len(), 1, "one writable piece once drained");

        let cut = (0..400).find_map(|_| match host.emit_held(1, &m, true) {
            (Outcome::Ready, _, _) => None,
            other => Some(other),
        });
        let (r, _, why) = cut.expect("a host emitting past the bound has the reply cut");
        assert_eq!(r, Outcome::Failed);
        assert_eq!(
            why,
            "emit: the stream's queue is past its bound: the far end is not reading"
        );
        assert_eq!(host.emit_drain(1), Outcome::Ready);
        let at = host.wire_log.len();
        assert_eq!(host.finish_final(0, b"", b""), Outcome::Ready);
        assert_eq!(
            String::from_utf8_lossy(&host.wire_log[at..]),
            "grpc-status: 8\r\ngrpc-message: the%20stream's%20queue%20is%20past%20its%20bound:\
             %20the%20far%20end%20is%20not%20reading\r\n",
            "the cut reply closes RESOURCE_EXHAUSTED, never OK"
        );
        host.close();
    }
}

/// A CLOSE THAT IS PENDING LEAVES THE CALL IN ITS FRAMING: an op crossing the host's `finish`
/// re-calls (the ABI does not serialize ops per framing) finds the call, never "no such framing".
/// RED: `finish` took the call out of the map while it worked, so the crossing `timer` failed.
#[test]
fn an_op_crossing_a_pending_finish_still_finds_its_call() {
    use busbar_contract::abi::mechanism::call::Span;
    let span = |offset: u32, len: u32| Span { offset, len };
    let (d, _lib) = dropped();
    for ops in [linked(), d] {
        let mut host = Host::open(ops, "{}", TIGHT);
        assert_eq!(
            host.begin_stream("/t.T/Unary", &[("content-type", "application/grpc")]),
            Outcome::Ready
        );
        let message = vec![b'm'; 3000];
        assert_eq!(
            host.finish_spans(5, &message, span(0, 3000), span(3000, 0))
                .0,
            Outcome::Ready
        );
        let crossing = host.crossing_timer();
        let (ran, observed) = std::sync::mpsc::channel();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen = std::sync::Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            let mut lost = 0_usize;
            let (_, why) = crossing();
            if why.contains("no such framing") {
                lost += 1;
            }
            ran.send(()).expect("main thread awaits crossing");
            while !seen.load(std::sync::atomic::Ordering::Relaxed) {
                let (_, why) = crossing();
                if why.contains("no such framing") {
                    lost += 1;
                }
            }
            lost
        });
        // A close of many bytes through a sink of seven: hundreds of re-calls.
        observed
            .recv()
            .expect("a crossing op ran while finish was pending");
        // Far fewer re-calls than the close needs: it is pending throughout.
        for _ in 0..60 {
            let (r, why) = host.finish_spans(5, &message, span(0, 3000), span(3000, 0));
            assert_eq!((r, why.as_str()), (Outcome::Ready, ""));
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let lost = thread.join().expect("the crossing thread ran");
        assert_eq!(lost, 0, "crossing ops lost the call");
        host.close();
    }
}

/// A FINAL TAIL WHOSE SPAN LIES OUTSIDE ITS BYTES IS REFUSED IN WORDS, never read as no message:
/// `finish` fails naming the span, writes nothing, and leaves the call for the host's fallback
/// refusal to close.
#[test]
fn a_final_tail_whose_span_lies_outside_its_bytes_is_refused_in_words() {
    use busbar_contract::abi::mechanism::call::Span;
    let (d, _lib) = dropped();
    for ops in [linked(), d] {
        let mut host = Host::open(ops, "{}", ROOMY);
        host.begin_stream("/t.T/Unary", &[("content-type", "application/grpc")]);
        let at = host.wire_log.len();
        let past = Span { offset: 2, len: 10 };
        let none = Span { offset: 0, len: 0 };
        assert_eq!(
            host.finish_spans(5, b"gone", past, none),
            (
                Outcome::Failed,
                "finish: the final message lies outside the close's bytes".to_owned()
            )
        );
        assert_eq!(host.wire_log.len(), at, "nothing written");
        assert_eq!(
            host.finish_spans(5, b"gone", none, past),
            (
                Outcome::Failed,
                "finish: the final details lie outside the close's bytes".to_owned()
            )
        );
        assert_eq!(host.refuse_as(1, b"", 500), Outcome::Ready);
        assert!(
            String::from_utf8_lossy(&host.wire_log[at..]).contains("grpc-status: 2\r\n"),
            "the fallback refusal closes the call"
        );
        host.close();
    }
}

/// A HOST BUFFER TOO SMALL FOR `locate`'S ANSWER IS A SHORT ANSWER, never a truncated success: each
/// buffer's needed size is stated, whichever is short (the framer's own head lines too, which every
/// call is owed), and on the listener path the offer's.
#[test]
fn locate_answers_short_for_any_buffer_too_small() {
    let (d, _lib) = dropped();
    for ops in [linked(), d] {
        let mut host = Host::open(ops, "{}", ROOMY);
        let target = "https://peer.test";
        for (k, caps) in [
            [3, 256, 64, 256],
            [256, 3, 64, 256],
            [256, 256, 1, 256],
            [256, 256, 64, 5],
        ]
        .into_iter()
        .enumerate()
        {
            let (r, o, why) = host.locate_lent(target, false, caps);
            assert_eq!(r, Outcome::Failed, "buffer {k}");
            assert_eq!(why, "locate: a host buffer is too small", "buffer {k}");
            assert_eq!(
                (
                    o.authority_needed,
                    o.name_needed,
                    o.alpn_needed,
                    o.defaults_needed
                ),
                (13, 9, 3, 46),
                "buffer {k}: every needed size stated"
            );
        }
        let (r, o, why) = host.locate_lent("", true, [0, 0, 2, 0]);
        assert_eq!(
            (r, o.alpn_needed, why.as_str()),
            (Outcome::Failed, 3, "locate: a host buffer is too small")
        );
        host.close();
    }
}

/// `refresh` READS ITS SETTINGS AS `validate` DOES, and new ones apply to framings begun after it:
/// an undeclared key or a bad value is refused in validate's words (the settings in force stay),
/// and a new ceiling bounds the next stream's messages.
#[test]
fn refresh_reads_its_settings_as_validate_does_and_applies_them() {
    let (d, _lib) = dropped();
    for ops in [linked(), d] {
        let mut host = Host::open(ops, "{}", ROOMY);
        assert_eq!(
            host.refresh(r#"{"limits.nope":1}"#),
            (
                Outcome::Failed,
                "settings: limits.nope is not a setting this transport reads".to_owned()
            )
        );
        assert_eq!(
            host.refresh(r#"{"limits.request_body_max_bytes":0}"#),
            (
                Outcome::Failed,
                "settings: limits.request_body_max_bytes must be a count of bytes above 0"
                    .to_owned()
            )
        );
        // The refused blobs applied nothing: the default ceiling still takes a 17-byte message.
        assert_eq!(
            host.begin_stream("/t.T/Unary", &[("content-type", "application/grpc")]),
            Outcome::Ready
        );
        assert_ne!(
            host.feed(&lpm(&[7u8; 17]), false),
            Outcome::Failed,
            "a refused refresh left the settings in force"
        );
        assert_eq!(
            host.refresh(r#"{"limits.request_body_max_bytes":16}"#),
            (Outcome::Ready, String::new())
        );
        assert_eq!(
            host.begin_stream("/t.T/Unary", &[("content-type", "application/grpc")]),
            Outcome::Ready
        );
        assert_eq!(
            host.feed(&lpm(&[7u8; 17]), false),
            Outcome::Failed,
            "the new ceiling"
        );
        host.close();
    }
}

/// EVERY OP'S TEXT NAMES ITS OP (`<op>: <reason>`, the kind's grammar), the framing's own failures
/// included: an op with no open instance, on no such framing, or failed by the framing.
#[test]
fn every_ops_text_names_its_op() {
    use busbar_contract::abi::transport::{
        slot, BeginIn, EmitIn, FramerOut, FramingIn, IngestIn, RefuseIn, SIDE_ACCEPT,
    };
    let (d, _lib) = dropped();
    for ops in [linked(), d] {
        let mut host = Host::open(ops, "{}", ROOMY);
        let o = host.ops;
        assert_eq!(
            // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
            // and the door instance for this synchronous call; the selected slot and index agree.
            unsafe {
                host.op_text::<BeginIn, FramerOut>(o.begin, slot::BEGIN, false, |i| {
                    i.side = SIDE_ACCEPT;
                })
            },
            (Outcome::Failed, "begin: no open instance".to_owned())
        );
        assert_eq!(
            // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
            // and the door instance for this synchronous call; the selected slot and index agree.
            unsafe {
                host.op_text::<IngestIn, FramerOut>(o.ingest, slot::INGEST, true, |i| {
                    i.framing = 999
                })
            },
            (Outcome::Failed, "ingest: no such framing".to_owned())
        );
        assert_eq!(
            // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
            // and the door instance for this synchronous call; the selected slot and index agree.
            unsafe {
                host.op_text::<FramingIn, FramerOut>(o.timer, slot::TIMER, true, |i| {
                    i.framing = 999
                })
            },
            (Outcome::Failed, "timer: no such framing".to_owned())
        );
        host.begin(SIDE_ACCEPT, "", "", None);
        let framing = host.framing;
        assert_eq!(
            // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
            // and the door instance for this synchronous call; the selected slot and index agree.
            unsafe {
                host.op_text::<RefuseIn, FramerOut>(o.refuse, slot::REFUSE, true, |i| {
                    i.framing = framing;
                    i.stream = 9;
                    i.has_stream = 1;
                })
            },
            (Outcome::Failed, "refuse: no such stream: 9".to_owned())
        );
        assert_eq!(
            // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
            // and the door instance for this synchronous call; the selected slot and index agree.
            unsafe {
                host.op_text::<EmitIn, FramerOut>(o.emit, slot::EMIT, true, |i| {
                    i.framing = framing;
                    i.stream = 9;
                })
            },
            (Outcome::Failed, "emit: no such stream: 9".to_owned())
        );
        host.close();
    }
}

/// A TARGET CARRYING USERINFO IS REFUSED AT `locate` AND AT `begin`, as http and ws refuse it, and
/// never echoed: a credential never rides a URL.
#[test]
fn a_target_carrying_userinfo_is_refused_and_never_echoed() {
    use busbar_contract::abi::transport::{slot, BeginIn, FramerOut, SIDE_DIAL};
    let (d, _lib) = dropped();
    let target = "https://user:secret@peer.test";
    for ops in [linked(), d] {
        let mut host = Host::open(ops, "{}", ROOMY);
        let (r, _, why) = host.locate_lent(target, false, [256, 256, 64, 256]);
        assert_eq!(
            (r, why.as_str()),
            (
                Outcome::Failed,
                "locate: the target carries userinfo; credentials never ride a URL"
            )
        );
        let o = host.ops;
        // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
        // and the door instance for this synchronous call; the selected slot and index agree.
        let (r, why) = unsafe {
            host.op_text::<BeginIn, FramerOut>(o.begin, slot::BEGIN, true, |i| {
                i.side = SIDE_DIAL;
                i.target = s(target);
            })
        };
        assert_eq!(
            (r, why.as_str()),
            (
                Outcome::Failed,
                "begin: the target carries userinfo; credentials never ride a URL"
            )
        );
        assert!(!why.contains("secret"));
        host.close();
    }
}

/// Zero-capacity hosts receive the same required-size response as every short buffer.
#[test]
fn locate_requires_its_defaults_buffer_even_at_zero_capacity() {
    let (d, _lib) = dropped();
    for ops in [linked(), d] {
        let mut host = Host::open(ops, "{}", ROOMY);
        let needed = b"content-type: application/grpc\r\nte: trailers\r\n".len() as u64;
        for cap in [0, 1, needed as usize - 1] {
            let (outcome, out, _) =
                host.locate_lent("http://peer.test", false, [256, 256, 64, cap]);
            assert_eq!(outcome, Outcome::Failed);
            assert_eq!(out.defaults_needed, needed);
            assert_eq!(out.defaults_written, 0);
        }
        let (outcome, out, _) =
            host.locate_lent("http://peer.test", false, [256, 256, 64, needed as usize]);
        assert_eq!(outcome, Outcome::Ready);
        assert_eq!(out.defaults_written, needed);
        host.close();
    }
}

/// Existing timer outputs carry the deadline in either door, including tiny output sinks.
#[test]
fn a_body_only_deadline_yields_cancellation_and_cannot_finish_successfully() {
    let (d, _lib) = dropped();
    for ops in [linked(), d] {
        for caps in [ROOMY, TIGHT] {
            let mut host = Host::open(ops, "{}", caps);
            let deadline = host.now + 1_000_000;
            assert_eq!(
                host.begin_stream(
                    "/t.T/Unary",
                    &[("content-type", "application/grpc"), ("grpc-timeout", "1m")]
                ),
                Outcome::Ready
            );
            assert_eq!(host.next_deadline(), Some(deadline));
            assert_eq!(host.advance(deadline - 1), Outcome::Ready);
            assert!(host.got.iter().all(|piece| !piece.failed()));
            assert_eq!(host.advance(deadline), Outcome::Ready);
            assert!(host.got.iter().any(Got::failed));
            assert_eq!(host.next_deadline(), None);
            let wire_before = host.wire_log.len();
            assert_eq!(host.emit(1, b"too late", true, 0), Outcome::Ready);
            assert_eq!(host.wire_log.len(), wire_before);
            assert_eq!(host.finish_final(0, b"", b""), Outcome::Ready);
            assert_eq!(
                &host.wire_log[wire_before..],
                b"grpc-status: 4\r\ngrpc-message: deadline%20exceeded\r\n"
            );
            host.close();
        }
    }
}

/// A ONE-STREAM CLOSE IS THE CALL'S LAST ANSWER: a close stating success while a reply message is
/// half written cannot be success, and nothing comes after it to refuse the call, so it closes
/// `INTERNAL` in the framer's words (the half message dropped) and the framing is let go.
#[test]
fn a_success_close_inside_a_reply_message_closes_internal_and_lets_the_call_go() {
    let (d, _lib) = dropped();
    for ops in [linked(), d] {
        let mut host = Host::open(ops, "{}", ROOMY);
        host.begin_stream("/t.T/Unary", &[("content-type", "application/grpc")]);
        assert_eq!(host.emit(1, b"half", false, 0), Outcome::Ready);
        let at = host.wire_log.len();
        assert_eq!(host.finish_final(0, b"", b""), Outcome::Ready);
        let block = String::from_utf8_lossy(&host.wire_log[at..]).into_owned();
        assert!(block.contains("grpc-status: 13\r\n"), "{block}");
        assert!(!block.contains("grpc-status: 0\r\n"), "{block}");
        assert!(!block.contains("half"), "{block}");
        assert_eq!(
            host.finish_final(0, b"", b""),
            Outcome::Failed,
            "the closed call is no longer held"
        );
        host.close();
    }
}

/// `begin` REFUSES WHAT IT CANNOT SERVE IN ITS OWN WORDS: a dialled target that is not text or not
/// a URL, a side it does not know, and a policy it cannot read; and none of them leaves a framing.
#[test]
fn begin_names_why_it_cannot_serve_a_target_a_side_or_a_policy() {
    use busbar_contract::abi::mechanism::call::{AbiStr, Blob, BLOB_OCTETS};
    use busbar_contract::abi::mechanism::extensions;
    use busbar_contract::abi::transport::guest_policy::EXT_GUEST_POLICY;
    use busbar_contract::abi::transport::{slot, BeginIn, FramerOut};
    let (d, _lib) = dropped();
    let not_text = [0xff_u8, 0xfe];
    let bad_policy = extensions::encode(&[(EXT_GUEST_POLICY, b"invalid")]);
    for ops in [linked(), d] {
        let host = Host::open(ops, "{}", ROOMY);
        let o = host.ops;
        // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
        // and the door instance for this synchronous call; the selected slot and index agree.
        let begin = |set: &dyn Fn(&mut BeginIn)| unsafe {
            host.op_text::<BeginIn, FramerOut>(o.begin, slot::BEGIN, true, |i| set(i))
        };
        assert_eq!(
            begin(&|i| {
                i.side = SIDE_DIAL;
                i.target = AbiStr {
                    ptr: not_text.as_ptr(),
                    len: not_text.len(),
                };
            }),
            (Outcome::Failed, "begin: the target is not text".to_owned())
        );
        assert_eq!(
            begin(&|i| {
                i.side = SIDE_DIAL;
                i.target = s("not a url");
            }),
            (Outcome::Failed, "begin: the target is not a URL".to_owned())
        );
        assert_eq!(
            begin(&|i| i.side = 99),
            (
                Outcome::Failed,
                "begin: the side is neither accept nor dial".to_owned()
            )
        );
        let (r, why) = begin(&|i| {
            i.side = SIDE_ACCEPT;
            i.head.extensions = Blob {
                ptr: bad_policy.as_ptr(),
                len: bad_policy.len(),
                fmt: BLOB_OCTETS,
                flags: 0,
            };
        });
        assert_eq!(r, Outcome::Failed);
        assert!(why.starts_with("begin: "), "{why}");
        host.close();
    }
}

/// `locate` SAYS WHY A TARGET CANNOT BE DIALLED when it is not a URL at all.
#[test]
fn locate_names_a_target_that_is_not_a_url() {
    let (d, _lib) = dropped();
    for ops in [linked(), d] {
        let mut host = Host::open(ops, "{}", ROOMY);
        let (r, _, why) = host.locate_lent("http://[::1", false, [256, 256, 64, 256]);
        assert_eq!(
            (r, why.as_str()),
            (Outcome::Failed, "locate: the target is not a URL")
        );
        host.close();
    }
}

/// A CONNECTION IS NEVER REFUSED WHOLE, and a finished connection's framing is gone with its end.
#[test]
fn a_connection_is_not_refused_whole_and_a_finished_one_is_gone() {
    use busbar_contract::abi::transport::{slot, FinishIn, FramerOut, RefuseIn};
    let (d, _lib) = dropped();
    for ops in [linked(), d] {
        let mut host = Host::open(ops, "{}", ROOMY);
        host.begin(SIDE_ACCEPT, "", "", None);
        let framing = host.framing;
        let o = host.ops;
        assert_eq!(
            // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
            // and the door instance for this synchronous call; the selected slot and index agree.
            unsafe {
                host.op_text::<RefuseIn, FramerOut>(o.refuse, slot::REFUSE, true, |i| {
                    i.framing = framing;
                    i.has_stream = 0;
                })
            },
            (
                Outcome::Refused,
                "refuse: gRPC refuses a call, never a connection".to_owned()
            )
        );
        for (outcome, words) in [
            (Outcome::Ready, ""),
            (Outcome::Failed, "finish: no such framing"),
        ] {
            assert_eq!(
                // SAFETY: as above.
                unsafe {
                    host.op_text::<FinishIn, FramerOut>(o.finish, slot::FINISH, true, |i| {
                        i.framing = framing;
                    })
                },
                (outcome, words.to_owned())
            );
        }
        assert_eq!(
            // SAFETY: as above; no instance is lent.
            unsafe {
                host.op_text::<FinishIn, FramerOut>(o.finish, slot::FINISH, false, |i| {
                    i.framing = framing;
                })
            },
            (Outcome::Failed, "finish: no open instance".to_owned())
        );
        host.close();
    }
}

/// `encode` WRITES ONE CALL OR SAYS WHY IT CANNOT: the target head word wins over an envelope
/// `path`, and a field that is not text, a line that cannot be written, or a wire buffer too small
/// for the call is a failure in the op's words.
#[test]
fn encode_names_what_the_envelope_cannot_express_and_what_does_not_fit() {
    use busbar_contract::abi::mechanism::call::{AbiStr, Field};
    use busbar_contract::abi::transport::{slot, EncodeIn, FramerOut};
    let (d, _lib) = dropped();
    for ops in [linked(), d] {
        let mut host = Host::open(ops, "{}", ROOMY);
        let wire = host.encode("/pkg.Svc/Call", &[("path", "/ignored"), ("x-a", "1")], b"b");
        let head = String::from_utf8_lossy(&wire);
        assert_eq!(head.matches("path: ").count(), 1, "{head}");
        assert!(
            head.starts_with("path: /pkg.Svc/Call\r\nx-a: 1\r\n"),
            "{head}"
        );
        assert!(!head.contains("/ignored"));

        let o = host.ops;
        let not_text = [0xff_u8];
        let bad_name = [Field {
            name: AbiStr {
                ptr: not_text.as_ptr(),
                len: 1,
            },
            value: s("v"),
        }];
        let bad_line = [Field {
            name: s("x-a"),
            value: s("one\r\ntwo"),
        }];
        let fine = [Field {
            name: s("x-a"),
            value: s("v"),
        }];
        let encode = |fields: &[Field], wire_cap: usize| {
            let mut wire = vec![0_u8; wire_cap];
            // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
            // and the door instance for this synchronous call; the selected slot and index agree.
            unsafe {
                host.op_text::<EncodeIn, FramerOut>(o.encode, slot::ENCODE, true, |i| {
                    i.target = s("/pkg.Svc/Call");
                    i.fields = fields.as_ptr();
                    i.fields_len = fields.len();
                    i.sink.wire = wire.as_mut_ptr();
                    i.sink.wire_cap = wire.len();
                })
            }
        };
        assert_eq!(
            encode(&bad_name, 4096),
            (
                Outcome::Failed,
                "encode: a field name is not text".to_owned()
            )
        );
        assert_eq!(
            encode(&bad_line, 4096),
            (
                Outcome::Failed,
                "encode: the envelope cannot be expressed on this wire".to_owned()
            )
        );
        assert_eq!(
            encode(&fine, 8),
            (
                Outcome::Failed,
                "encode: the rendered call is larger than the wire buffer".to_owned()
            )
        );
        host.close();
    }
}
