// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One stream's framing (`SIDE_ACCEPT_STREAM`): payloads out of the body, a reply framed, the close
//! as status lines (trailers after a reply, the whole answer before one).

use super::*;

fn grpc() -> StreamCall {
    StreamCall::open(
        [(&b"content-type"[..], &b"application/grpc+proto"[..])].into_iter(),
        1024,
        0,
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
    assert!(StreamCall::open(
        [(&b"content-type"[..], &b"text/plain"[..])].into_iter(),
        1,
        0
    )
    .is_err());
    assert!(StreamCall::open(std::iter::empty(), 1, 0).is_err());
}

/// The encoding is predev's, which is tonic 0.14's `Status` (v1.5.5 served no gRPC).
#[test]
fn the_status_message_is_encoded_as_predevs_tonic_encoded_it() {
    assert_eq!(
        msg::encode_status_message("a b%\"#<>`?{}~\u{2713}\n".as_bytes()),
        "a%20b%25%22%23%3C%3E%60%3F%7B%7D~%E2%9C%93%0A"
    );
}

/// AN OVERSIZE MESSAGE ON ONE STREAM CLOSES IT `OUT_OF_RANGE` IN PREDEV'S WORDS. The body's message
/// states a length past the ceiling: `ingest` fails, and the refusal the host then closes the
/// stream with (its neutral status for a body it could not decode, the failure's text as its
/// bytes) is rendered as predev answered it: `grpc-status: 11` and tonic 0.14's text, encoded as
/// tonic encoded it, the limit being the ceiling. RED before the fix: the neutral status mapped,
/// with predev's refusal words.
#[test]
fn an_oversize_message_closes_the_stream_out_of_range_in_predevs_words() {
    let mut c = grpc();
    let mut body = vec![0u8];
    body.extend_from_slice(&1025u32.to_be_bytes());
    let why = c.ingest(&body, false).expect_err("over the ceiling");
    c.refuse(why.0.as_bytes(), 400, false).unwrap();
    assert_eq!(
        wire(&mut c),
        ":status: 200\r\ncontent-type: application/grpc\r\ngrpc-status: 11\r\n\
         grpc-message: Error,%20decoded%20message%20length%20too%20large:%20found%201025%20bytes,\
         %20the%20limit%20is:%201024%20bytes\r\n"
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

/// THE CALLER'S `grpc-timeout` HOLDS ON THE SHARED LISTENER TOO: the deadline runs from the call's
/// arrival, the framer asks the host for its timer, and past it the call fails
/// `DEADLINE_EXCEEDED` with a failure piece, as the dedicated listener's accept path fails it; the
/// host's refusal then closes it `DEADLINE_EXCEEDED`. RED before the fix: the stream path read only
/// `content-type` and never asked for a timer.
#[test]
fn a_stated_grpc_timeout_closes_the_call_deadline_exceeded() {
    let mut c = StreamCall::open(
        [
            (&b"content-type"[..], &b"application/grpc"[..]),
            (&b"grpc-timeout"[..], &b"5m"[..]),
        ]
        .into_iter(),
        1024,
        1_000,
    )
    .expect("a gRPC call");
    assert_eq!(c.next_deadline(), Some(1_000 + 5_000_000));
    c.expire(1_000 + 4_999_999);
    assert!(c.pieces().is_empty(), "not yet");
    c.expire(1_000 + 5_000_000);
    assert!(c
        .pieces()
        .drain(..)
        .any(|p| p.status == Some(msg::DEADLINE_EXCEEDED)));
    assert_eq!(c.next_deadline(), None);
    c.refuse(b"", 504, false).unwrap();
    assert_eq!(
        wire(&mut c),
        ":status: 200\r\ncontent-type: application/grpc\r\ngrpc-status: 4\r\n\
         grpc-message: deadline%20exceeded\r\n",
        "before any head, the close is the whole answer"
    );
}

/// A call opened with a `grpc-timeout` of 5ms at host time 1000, already past it.
fn expired() -> StreamCall {
    let mut c = StreamCall::open(
        [
            (&b"content-type"[..], &b"application/grpc"[..]),
            (&b"grpc-timeout"[..], &b"5m"[..]),
        ]
        .into_iter(),
        1024,
        1_000,
    )
    .expect("a gRPC call");
    c.expire(1_000 + 5_000_000);
    c
}

/// A DEADLINE AFTER THE HOST'S HEAD WRITES CLOSING LINES ONLY: the timer does not say whether the
/// host sent the response head, so the expiry writes nothing, and the close is the host's refusal,
/// which states it (`head_sent`): after a head, the `DEADLINE_EXCEEDED` lines alone, never a second
/// `:status`. RED before the fix: the expiry wrote `:status: 200` and a content type into the
/// trailers of a head the host had already sent.
#[test]
fn a_deadline_after_the_hosts_head_writes_its_closing_lines_only() {
    let mut c = expired();
    assert_eq!(wire(&mut c), "", "the expiry writes nothing");
    assert!(!c.ended(), "the close is the host's refusal");
    c.refuse(b"", 504, true).unwrap();
    assert_eq!(
        wire(&mut c),
        "grpc-status: 4\r\ngrpc-message: deadline%20exceeded\r\n"
    );
    assert!(c.ended());
    // The unit's own final status after the expiry closes it DEADLINE_EXCEEDED all the same.
    let mut c = expired();
    c.finish(0, b"", b"").unwrap();
    assert_eq!(
        wire(&mut c),
        "grpc-status: 4\r\ngrpc-message: deadline%20exceeded\r\n"
    );
}

/// AN EMIT AFTER THE CLOSE WRITES NOTHING: a reply message the host emits once the call is closed
/// (or past its deadline) is dropped, as the dedicated listener drops one after its reply is over;
/// it never lands behind the closing lines the host sends as trailers. RED before the fix: the
/// message was framed into the wire after the status lines.
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
    let mut c = expired();
    c.emit(b"late", true);
    assert_eq!(wire(&mut c), "", "nothing after the deadline");
}

/// A COMPRESSION THE DOOR DOES NOT TAKE IS `UNIMPLEMENTED` WITH THE ENCODINGS IT TAKES, as
/// predev's gRPC line (tonic 0.14, no compression enabled) answered it: the call's first `ingest`
/// fails, and whatever refusal the host then closes it with, the close is `grpc-accept-encoding:
/// identity`, `grpc-status: 12` and tonic's words, in tonic's order. `identity` is no compression.
/// RED before the fix: `grpc-encoding` was never read, the compressed message failed `INTERNAL`,
/// and the close was the refusal's neutral status mapped.
#[test]
fn a_compression_the_door_does_not_take_closes_unimplemented() {
    let open = |encoding: &'static [u8]| {
        StreamCall::open(
            [
                (&b"content-type"[..], &b"application/grpc"[..]),
                (&b"grpc-encoding"[..], encoding),
            ]
            .into_iter(),
            1024,
            0,
        )
        .expect("a gRPC call")
    };
    let mut c = open(b"gzip");
    let why = c.ingest(&[1, 0, 0, 0, 1, b'z'], true).expect_err("refused");
    assert_eq!(
        why.0,
        "Content is compressed with `gzip` which isn't supported"
    );
    assert!(c.pieces().is_empty(), "no message is handed up");
    c.refuse(why.0.as_bytes(), 400, false).unwrap();
    assert_eq!(
        wire(&mut c),
        ":status: 200\r\ncontent-type: application/grpc\r\ngrpc-accept-encoding: identity\r\n\
         grpc-status: 12\r\ngrpc-message: Content%20is%20compressed%20with%20%60gzip%60%20which\
         %20isn't%20supported\r\n"
    );
    let mut c = open(b"identity");
    c.ingest(&msg::frame(b"a"), true)
        .expect("identity is no compression");
    assert_eq!(c.pieces().len(), 1);
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
