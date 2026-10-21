// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One stream's framing (`SIDE_ACCEPT_STREAM`): payloads out of the body, a reply framed, the close
//! as status lines (trailers after a reply, the whole answer before one).

use super::*;

fn grpc() -> StreamCall {
    StreamCall::open(
        [(&b"content-type"[..], &b"application/grpc+proto"[..])].into_iter(),
        1024,
    )
    .expect("a gRPC call")
}

fn wire(c: &mut StreamCall) -> String {
    String::from_utf8(c.take_wire(usize::MAX)).expect("text")
}

#[test]
fn the_bodys_messages_are_the_units_payloads() {
    let mut c = grpc();
    let mut body = msg::frame(b"a");
    body.extend(msg::frame(b"bc"));
    c.ingest(&body[..4], false).unwrap();
    assert!(c.pieces().is_empty(), "no message is whole yet");
    c.ingest(&body[4..], true).unwrap();
    let got: Vec<Vec<u8>> = c.pieces().drain(..).map(|p| p.bytes.to_vec()).collect();
    assert_eq!(got, [b"a".to_vec(), b"bc".to_vec()]);
    assert!(
        grpc().ingest(&msg::frame(b"abc")[..6], true).is_err(),
        "cut short"
    );
}

#[test]
fn a_close_after_a_reply_is_trailers_and_before_one_the_whole_answer() {
    let mut c = grpc();
    c.emit(b"hi", true);
    assert_eq!(c.take_wire(usize::MAX), msg::frame(b"hi"));
    c.finish(5, b"no such", b"AAEC").unwrap();
    assert_eq!(
        wire(&mut c),
        "grpc-status: 5\r\ngrpc-message: no%20such\r\ngrpc-status-details-bin: AAEC\r\n"
    );
    assert!(c.ended());
    c.refuse(b"", 500, false).unwrap();
    assert_eq!(wire(&mut c), "", "a closed call owes nothing more");

    let mut c = grpc();
    c.refuse(b"", 429, false).unwrap();
    assert_eq!(
        wire(&mut c),
        ":status: 200\r\ncontent-type: application/grpc\r\ngrpc-status: 14\r\n\
         grpc-message: busbar%20answered%20HTTP%20429\r\n"
    );
    let mut c = grpc();
    c.refuse(b"grpc-status: 7\r\ngrpc-message: no\r\n", 0, false)
        .unwrap();
    assert_eq!(
        wire(&mut c),
        ":status: 200\r\ncontent-type: application/grpc\r\ngrpc-status: 7\r\ngrpc-message: no\r\n",
        "a block that states its status is the close, verbatim"
    );
}

#[test]
fn a_call_that_is_not_grpc_is_refused_before_it_is_one() {
    assert!(StreamCall::open([(&b"content-type"[..], &b"text/plain"[..])].into_iter(), 1).is_err());
    assert!(StreamCall::open(std::iter::empty(), 1).is_err());
}

/// The encoding is predev's gRPC line's (v1.5.5 served no gRPC).
#[test]
fn the_status_message_is_encoded_as_predev_encoded_it() {
    assert_eq!(
        msg::encode_status_message("a b%\"#<>`?{}~\u{2713}\n".as_bytes()),
        "a%20b%25%22%23%3C%3E%60%3F%7B%7D~%E2%9C%93%0A"
    );
}

/// AN OVERSIZE MESSAGE ON ONE STREAM CLOSES IT `OUT_OF_RANGE` NAMING THE LIMIT. The body's message
/// states a length past the ceiling: `ingest` fails, and the refusal the host then closes the
/// stream with (its neutral status for a body it could not decode, the failure's text as its
/// bytes) is rendered as `grpc-status: 11` and this framer's own words, which print the configured
/// limit (coordinator ruling (b)). RED before the fix: the words were predev's server's.
#[test]
fn an_oversize_message_closes_the_stream_out_of_range_naming_the_limit() {
    let mut c = grpc();
    let mut body = vec![0u8];
    body.extend_from_slice(&1025u32.to_be_bytes());
    let why = c.ingest(&body, false).expect_err("over the ceiling");
    c.refuse(why.0.as_bytes(), 400, false).unwrap();
    assert_eq!(
        wire(&mut c),
        ":status: 200\r\ncontent-type: application/grpc\r\ngrpc-status: 11\r\n\
         grpc-message: the%20message%20is%201025%20bytes,%20over%20the%20limit%20of%201024%20bytes\
         %20(limits.request_body_max_bytes)\r\n"
    );
}

/// A FINAL STATUS THAT CANNOT BE RENDERED LEAVES THE CALL OPEN for the host's fallback refusal: a
/// details value with a byte no field line may carry fails `finish`, writes nothing, and the
/// refusal that follows still closes the call with a `grpc-status`. RED before the fix: `finish`
/// marked the call closed first, so the refusal wrote nothing and the client saw no status.
#[test]
fn a_finish_that_cannot_render_leaves_the_call_for_the_fallback_refusal() {
    let mut c = grpc();
    assert!(c.finish(0, b"ok", b"\x01").is_err());
    assert!(!c.ended(), "the call is still open");
    c.refuse(&[], 0, false)
        .expect("the fallback refusal closes it");
    assert!(wire(&mut c).contains("grpc-status:"));
}

/// A `grpc-timeout` THE CALLER STATES IS NEVER ENFORCED HERE, as predev's server enforced none:
/// the call asks the host for no timer, and however long it runs it is never closed
/// `DEADLINE_EXCEEDED` by this framing; the value stays in the head the host keeps, a fact for the
/// plane. RED before the fix: the framing asked for a timer at the stated deadline and failed the
/// call `DEADLINE_EXCEEDED` there.
#[test]
fn a_stated_grpc_timeout_is_never_enforced_here() {
    let mut c = StreamCall::open(
        [
            (&b"content-type"[..], &b"application/grpc"[..]),
            (&b"grpc-timeout"[..], &b"5m"[..]),
        ]
        .into_iter(),
        1024,
    )
    .expect("a gRPC call");
    assert_eq!(c.next_deadline(), None, "no timer is asked for");
    c.ingest(&msg::frame(b"q"), true).expect("served");
    assert!(
        c.pieces().drain(..).all(|p| !p.failed),
        "nothing fails the call"
    );
    c.emit(b"late but answered", true);
    c.finish(0, b"", b"").unwrap();
    let mut answer = msg::frame(b"late but answered");
    answer.extend_from_slice(b"grpc-status: 0\r\n");
    assert_eq!(c.take_wire(usize::MAX), answer);
}

/// AN EMIT AFTER THE CLOSE WRITES NOTHING: a reply message the host emits once the call is closed
/// is dropped, as the dedicated listener drops one after its reply is over; it never lands behind
/// the closing lines the host sends as trailers. RED before the fix: the message was framed into
/// the wire after the status lines.
#[test]
fn an_emit_after_the_close_writes_nothing() {
    let mut c = grpc();
    c.refuse(b"", 429, false).unwrap();
    drop(c.take_wire(usize::MAX));
    c.emit(b"late", true);
    assert_eq!(wire(&mut c), "", "nothing after the close");
    let mut c = grpc();
    c.finish(0, b"", b"").unwrap();
    drop(c.take_wire(usize::MAX));
    c.emit(b"late", true);
    assert_eq!(wire(&mut c), "");
}

/// A call whose head states `fields` after its gRPC content type.
fn open_with(fields: &[(&'static [u8], &'static [u8])]) -> StreamCall {
    StreamCall::open(
        std::iter::once((&b"content-type"[..], &b"application/grpc"[..]))
            .chain(fields.iter().copied()),
        1024,
    )
    .expect("a gRPC call")
}

/// The close a compression the door does not take ends a call with, before any reply: the whole
/// answer, `UNIMPLEMENTED` with the encodings the door takes, and this framer's words.
const UNIMPLEMENTED_GZIP: &str = ":status: 200\r\ncontent-type: application/grpc\r\n\
     grpc-accept-encoding: identity\r\ngrpc-status: 12\r\ngrpc-message: the%20message%20encoding\
     %20%60gzip%60%20is%20not%20supported:%20this%20server%20takes%20identity\r\n";

/// A COMPRESSION THE DOOR DOES NOT TAKE IS `UNIMPLEMENTED` WITH THE ENCODINGS IT TAKES (gRPC's
/// compression rules, `compression.md`): the call's first `ingest` fails, and whatever refusal the
/// host then closes it with, the close is `grpc-accept-encoding: identity` and `grpc-status: 12`.
/// `identity` is no compression. RED before the fix: `grpc-encoding` was never read, the compressed
/// message failed `INTERNAL`, and the close was the refusal's neutral status mapped.
#[test]
fn a_compression_the_door_does_not_take_closes_unimplemented() {
    let mut c = open_with(&[(&b"grpc-encoding"[..], &b"gzip"[..])]);
    let why = c.ingest(&[1, 0, 0, 0, 1, b'z'], true).expect_err("refused");
    assert_eq!(
        why.0,
        "the message encoding `gzip` is not supported: this server takes identity"
    );
    assert!(c.pieces().is_empty(), "no message is handed up");
    c.refuse(why.0.as_bytes(), 400, false).unwrap();
    assert_eq!(wire(&mut c), UNIMPLEMENTED_GZIP);
    let mut c = open_with(&[(&b"grpc-encoding"[..], &b"identity"[..])]);
    c.ingest(&msg::frame(b"a"), true)
        .expect("identity is no compression");
    assert_eq!(c.pieces().len(), 1);
}

/// THE FIRST `grpc-encoding` FIELD IS THE CALL'S: a repeat is not read. A call that states
/// `identity` and then `gzip` is served; one that states `gzip` and then `identity` is refused
/// `UNIMPLEMENTED`. RED before the fix: the last field won, so each call was read the other way.
#[test]
fn the_first_grpc_encoding_field_is_the_calls() {
    let mut c = open_with(&[
        (&b"grpc-encoding"[..], &b"identity"[..]),
        (&b"grpc-encoding"[..], &b"gzip"[..]),
    ]);
    c.ingest(&msg::frame(b"a"), true)
        .expect("the first field, identity, is the call's");
    assert_eq!(c.pieces().len(), 1);
    let mut c = open_with(&[
        (&b"grpc-encoding"[..], &b"gzip"[..]),
        (&b"grpc-encoding"[..], &b"identity"[..]),
    ]);
    let why = c.ingest(&msg::frame(b"a"), true).expect_err("refused");
    c.refuse(why.0.as_bytes(), 400, false).unwrap();
    assert_eq!(wire(&mut c), UNIMPLEMENTED_GZIP);
}

/// A HEAD THE HOST ALREADY SENT IS NOT SENT AGAIN (Q128 grpc L1, ruling (a)): when the host states
/// `RefuseIn::head_sent`, the refusal is the call's closing lines only, the trailers after the
/// head it answered. RED before the fix: the framer judged by its own state alone and wrote a
/// second `:status: 200` head.
#[test]
fn a_refusal_after_the_hosts_head_is_its_closing_lines_only() {
    let mut c = grpc();
    c.refuse(b"", 429, true).unwrap();
    assert_eq!(
        wire(&mut c),
        "grpc-status: 14\r\ngrpc-message: busbar%20answered%20HTTP%20429\r\n"
    );
    let mut c = grpc();
    c.refuse(b"grpc-status: 7\r\ngrpc-message: no\r\n", 0, true)
        .unwrap();
    assert_eq!(wire(&mut c), "grpc-status: 7\r\ngrpc-message: no\r\n");
}
