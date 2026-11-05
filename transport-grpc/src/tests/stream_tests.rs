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
fn a_reply_emitted_in_pieces_is_one_message_and_the_wire_drains_in_cuts() {
    let mut c = grpc();
    c.emit(b"he", false).unwrap();
    c.emit(b"", false).unwrap();
    c.emit(b"llo", true).unwrap();
    c.emit(b"!", true).unwrap();
    let mut want = msg::frame(b"hello");
    want.extend(msg::frame(b"!"));
    let mut got = c.take_wire(3);
    assert_eq!(got.len(), 3);
    while c.wire_pending() {
        got.extend(c.take_wire(4));
    }
    assert_eq!(got, want);
}

#[test]
fn a_close_after_a_reply_is_trailers_and_before_one_the_whole_answer() {
    let mut c = grpc();
    c.emit(b"hi", true).unwrap();
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
        "content-type: application/grpc\r\ngrpc-status: 14\r\n\
         grpc-message: busbar%20answered%20HTTP%20429\r\n"
    );
    let mut c = grpc();
    c.refuse(b"grpc-status: 7\r\ngrpc-message: no\r\n", 0, false)
        .unwrap();
    assert_eq!(
        wire(&mut c),
        "content-type: application/grpc\r\ngrpc-status: 7\r\ngrpc-message: no\r\n",
        "a block that states its status is the close, verbatim"
    );
}

#[test]
fn a_call_that_is_not_grpc_is_refused_before_it_is_one() {
    assert!(StreamCall::open([(&b"content-type"[..], &b"text/plain"[..])].into_iter(), 1).is_err());
    assert!(StreamCall::open(std::iter::empty(), 1).is_err());
}

/// A gRPC call is a POST: a stream whose stated method is another is refused at `begin`.
#[test]
fn a_stream_whose_method_is_not_post_is_refused() {
    let grpc_type = (&b"content-type"[..], &b"application/grpc"[..]);
    for m in [&b"GET"[..], b"PUT"] {
        let e = StreamCall::open([grpc_type, (&b":method"[..], m)].into_iter(), 1)
            .err()
            .expect("refused");
        assert!(e.0.contains("its method"), "{}", e.0);
    }
    assert!(StreamCall::open([grpc_type, (&b":method"[..], &b"POST"[..])].into_iter(), 1).is_ok());
}

/// The encoding is predev's gRPC line's (v1.5.5 served no gRPC).
#[test]
fn the_status_message_is_encoded_as_predev_encoded_it() {
    assert_eq!(
        msg::encode_status_message("a b%\"#<>`?{}~\u{2713}\n".as_bytes()),
        "a%20b%25%22%23%3C%3E%60%3F%7B%7D~%E2%9C%93%0A"
    );
}

/// AN OVERSIZE MESSAGE ON ONE STREAM CLOSES IT `RESOURCE_EXHAUSTED` NAMING THE LIMIT. The body's message
/// states a length past the ceiling: `ingest` fails, and the refusal the host then closes the
/// stream with (its neutral status for a body it could not decode, the failure's text as its
/// bytes) is rendered as `grpc-status: 8` and this framer's own words, which print the configured
/// limit.
#[test]
fn an_oversize_message_closes_the_stream_resource_exhausted_naming_the_limit() {
    let mut c = grpc();
    let mut body = vec![0u8];
    body.extend_from_slice(&1025u32.to_be_bytes());
    let why = c.ingest(&body, false).expect_err("over the ceiling");
    c.refuse(why.0.as_bytes(), 400, false).unwrap();
    assert_eq!(
        wire(&mut c),
        "content-type: application/grpc\r\ngrpc-status: 8\r\n\
         grpc-message: the%20message%20is%201025%20bytes,%20over%20the%20limit%20of%201024%20bytes\
         %20(limits.request_body_max_bytes)\r\n"
    );
}

/// A FINAL STATUS THAT CANNOT BE RENDERED LEAVES THE CALL OPEN for the host's fallback refusal: a
/// details value with a byte no field line may carry fails `finish`, writes nothing, and the
/// refusal that follows still closes the call with a `grpc-status`.
#[test]
fn a_finish_that_cannot_render_leaves_the_call_for_the_fallback_refusal() {
    let mut c = grpc();
    assert!(c.finish(0, b"ok", b"\x01").is_err());
    assert!(!c.ended(), "the call is still open");
    c.refuse(&[], 0, false)
        .expect("the fallback refusal closes it");
    assert!(wire(&mut c).contains("grpc-status:"));
}

/// The body adapter exposes a host deadline, reports cancellation once, and refuses late success.
#[test]
fn a_stated_grpc_timeout_expires_and_overrides_a_late_success() {
    let mut c = StreamCall::open(
        [
            (&b"content-type"[..], &b"application/grpc"[..]),
            (&b"grpc-timeout"[..], &b"5m"[..]),
        ]
        .into_iter(),
        1024,
    )
    .unwrap();
    c.start_clock(1_000_000_000);
    assert_eq!(c.next_deadline(), Some(1_005_000_000));
    c.expire(1_004_999_999);
    assert!(!c.timed_out());
    c.expire(1_005_000_000);
    assert_eq!(c.pieces().drain(..).filter(|piece| piece.failed).count(), 1);
    assert_eq!(c.next_deadline(), None);
    c.expire(2_000_000_000);
    assert!(c.pieces().is_empty());
    c.emit(b"late but answered", true).unwrap();
    c.finish(0, b"", b"").unwrap();
    assert_eq!(
        c.take_wire(usize::MAX),
        b"grpc-status: 4\r\ngrpc-message: deadline%20exceeded\r\n"
    );
}

#[test]
fn a_body_adapter_without_a_timeout_asks_for_no_timer() {
    let mut c = grpc();
    c.start_clock(5_000_000_000);
    c.expire(u64::MAX);
    assert_eq!(c.next_deadline(), None);
    assert!(!c.timed_out());
}

/// AN EMIT AFTER THE CLOSE WRITES NOTHING: a reply message the host emits once the call is closed
/// is dropped, as the dedicated listener drops one after its reply is over; it never lands behind
/// the closing lines the host sends as trailers.
#[test]
fn an_emit_after_the_close_writes_nothing() {
    let mut c = grpc();
    c.refuse(b"", 429, false).unwrap();
    drop(c.take_wire(usize::MAX));
    c.emit(b"late", true).unwrap();
    assert_eq!(wire(&mut c), "", "nothing after the close");
    let mut c = grpc();
    c.finish(0, b"", b"").unwrap();
    drop(c.take_wire(usize::MAX));
    c.emit(b"late", true).unwrap();
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
const UNIMPLEMENTED_GZIP: &str = "content-type: application/grpc\r\n\
     grpc-accept-encoding: identity\r\ngrpc-status: 12\r\ngrpc-message: the%20message%20encoding\
     %20%60gzip%60%20is%20not%20supported:%20this%20server%20takes%20identity\r\n";

/// A COMPRESSION THE DOOR DOES NOT TAKE IS `UNIMPLEMENTED` WITH THE ENCODINGS IT TAKES (gRPC's
/// compression rules, `compression.md`): the call's first `ingest` fails, and whatever refusal the
/// host then closes it with, the close is `grpc-accept-encoding: identity` and `grpc-status: 12`.
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
/// `UNIMPLEMENTED`.
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

/// A HEAD THE HOST ALREADY SENT IS NOT SENT AGAIN: when the host states
/// `RefuseIn::head_sent`, the refusal is the call's closing lines only, the trailers after the
/// head it answered.
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

/// A REFUSAL STATING NO STATUS EITHER WAY IS `UNKNOWN` WITH ITS OWN WORDS, as the connection side
/// ends the same refusal: no `grpc-status` in its bytes and no neutral status (`0`, none stated).
#[test]
fn a_refusal_stating_no_status_either_way_is_unknown_with_its_words() {
    let mut c = grpc();
    c.refuse(b"upstream gone", 0, false).unwrap();
    assert_eq!(
        wire(&mut c),
        "content-type: application/grpc\r\ngrpc-status: 2\r\n\
         grpc-message: upstream%20gone\r\n"
    );
}

/// The same on one stream: a refusal whose block names `grpc-status` but is no field block fails in
/// words, writes nothing, and leaves the call for the fallback close.
#[test]
fn a_refusal_naming_grpc_status_in_a_broken_block_fails_in_words() {
    let mut c = grpc();
    let why = c
        .refuse(b"grpc-status: 5\r\nbroken line\r\n", 500, false)
        .expect_err("refused in words");
    assert_eq!(
        why.0,
        "the trailer block names grpc-status but is not a field block: a head line is not a field"
    );
    assert_eq!(wire(&mut c), "", "nothing written");
    c.refuse(b"", 500, false).expect("the fallback closes it");
    assert!(wire(&mut c).contains("grpc-status: 2\r\n"));
}

/// A REFUSAL BLOCK'S OWN `content-type` (and any connection-specific field) IS DROPPED, as the
/// connection side drops it: the trailers-only answer states one content type, the framer's, and
/// never a field HTTP/2 forbids (RFC 9113 §8.2.2).
#[test]
fn a_refusal_blocks_own_content_type_and_connection_fields_are_dropped() {
    let mut c = grpc();
    c.refuse(
        b"content-type: application/grpc+proto\r\nconnection: close\r\ngrpc-status: 7\r\n",
        0,
        false,
    )
    .unwrap();
    assert_eq!(
        wire(&mut c),
        "content-type: application/grpc\r\ngrpc-status: 7\r\n"
    );
}

#[test]
fn an_unfinished_large_reply_can_finish_before_drainable_wire_backpressure() {
    let mut c = StreamCall::open(
        [(&b"content-type"[..], &b"application/grpc"[..])].into_iter(),
        2 * STREAM_HIGH_WATER,
    )
    .unwrap();
    let mut payload = vec![b'a'; STREAM_HIGH_WATER];
    c.emit(&payload, false).unwrap();
    assert!(
        !c.wire_pending(),
        "an unfinished frame has no drainable wire"
    );
    assert!(
        !c.announce_full(),
        "Full would prevent the host submitting the final fragment"
    );
    assert!(c.take_wire(usize::MAX).is_empty());
    assert!(c.pieces().is_empty(), "no spurious writable before Full");

    c.emit(b"tail", true).unwrap();
    payload.extend_from_slice(b"tail");
    let expected = msg::frame(&payload);
    assert!(
        c.announce_full(),
        "the complete, drainable reply still applies backpressure"
    );
    let mut got = c.take_wire(expected.len() - STREAM_LOW_WATER - 1);
    assert!(c.pieces().is_empty(), "above low water remains full");
    got.extend(c.take_wire(1));
    let writable: Vec<_> = c.pieces().drain(..).collect();
    assert_eq!(writable.len(), 1);
    assert!(writable[0].writable);
    assert_eq!(writable[0].stream, STREAM);
    assert!(writable[0].bytes.is_empty());
    got.extend(c.take_wire(usize::MAX));
    assert_eq!(
        got, expected,
        "one exact framed reply, with no lost or repeated bytes"
    );
    assert!(c.pieces().is_empty(), "writable is announced once");
    assert!(!c.announce_full());
}

#[test]
fn a_successful_finish_cannot_discard_an_unfinished_reply_message() {
    for previous in [false, true] {
        let mut c = grpc();
        let mut expected = Vec::new();
        if previous {
            c.emit(b"already complete", true).unwrap();
            expected.extend(msg::frame(b"already complete"));
        }
        c.emit(b"reply prefix", false).unwrap();
        assert!(
            c.finish(0, b"", b"").is_err(),
            "an unfinished message is not success"
        );
        assert!(
            !c.ended(),
            "a failed finish leaves the call available for recovery"
        );
        assert_eq!(
            c.take_wire(usize::MAX),
            expected,
            "no successful trailer was written"
        );
        c.emit(b" and suffix", true)
            .expect("the same message can still complete");
        c.finish(0, b"", b"")
            .expect("the complete reply can finish");
        let mut completed = msg::frame(b"reply prefix and suffix");
        completed.extend_from_slice(b"grpc-status: 0\r\n");
        assert_eq!(c.take_wire(usize::MAX), completed);
        assert!(c.ended());
    }
}

/// A CALL WHOSE BODY THE FRAMER REFUSED CLOSES WITH THE FRAMER'S STATUS, NOT THE UNIT'S: after an
/// oversize message `finish(0, ..)` (core's close, or its Drop) must be `RESOURCE_EXHAUSTED`, never OK.
#[test]
fn a_finish_after_an_oversize_message_is_resource_exhausted_not_ok() {
    let mut c = grpc();
    let mut body = vec![0u8];
    body.extend_from_slice(&1025u32.to_be_bytes());
    c.ingest(&body, false).expect_err("over the ceiling");
    c.finish(0, b"", b"").unwrap();
    let w = wire(&mut c);
    assert!(w.contains("grpc-status: 8\r\n"), "{w}");
    assert!(!w.contains("grpc-status: 0"), "{w}");
}

/// A COMPRESSED MESSAGE WITH NO ENCODING ON THE STREAM PATH CLOSES INTERNAL with the framer's words,
/// as on the connection side, not with the host's neutral refusal status.
#[test]
fn a_compressed_message_without_an_encoding_closes_internal_on_a_stream() {
    let mut c = grpc();
    let why = c.ingest(&[1, 0, 0, 0, 1, b'z'], true).expect_err("refused");
    c.refuse(why.0.as_bytes(), 500, false).unwrap();
    let w = wire(&mut c);
    assert!(w.contains("grpc-status: 13\r\n"), "{w}");
    assert!(w.contains("a%20message%20is%20compressed"), "{w}");
}

/// A truncated body closes INTERNAL too.
#[test]
fn a_truncated_body_closes_internal_on_a_stream() {
    let mut c = grpc();
    c.ingest(&msg::frame(b"abc")[..6], true).expect_err("cut");
    c.finish(0, b"", b"").unwrap();
    let w = wire(&mut c);
    assert!(w.contains("grpc-status: 13\r\n"), "{w}");
}

/// A `grpc-encoding` of C1 control bytes is named escaped, printable ASCII only.
#[test]
fn an_encoding_name_with_controls_is_escaped_in_the_refusal() {
    let mut c = open_with(&[(&b"grpc-encoding"[..], "\u{9b}[31m".as_bytes())]);
    let why = c.ingest(&msg::frame(b"a"), true).expect_err("refused");
    assert!(
        why.0
            .chars()
            .all(|ch| ch.is_ascii() && !ch.is_ascii_control()),
        "{}",
        why.0
    );
    assert!(why.0.contains("\\xc2\\x9b"), "{}", why.0);
}

/// An unfinished reply refuses a successful close without writes and remains recoverable;
/// an explicit nonzero host refusal retains its status.
#[test]
fn an_unfinished_reply_cannot_close_successfully_and_a_refusal_keeps_its_status() {
    for status in [0, 5] {
        let mut c = grpc();
        c.emit(b"half of a mess", false).unwrap();
        let result = c.finish(status, b"", b"");
        if status == 0 {
            assert!(result.is_err(), "an unfinished reply cannot report success");
            assert!(
                c.take_wire(usize::MAX).is_empty(),
                "no partial body or successful trailer was written"
            );
            assert!(!c.ended(), "a refused successful close remains recoverable");
            c.emit(b"age", true).expect("the same reply may complete");
            c.finish(0, b"", b"").expect("the whole reply may close");
            let mut expected = msg::frame(b"half of a message");
            expected.extend_from_slice(b"grpc-status: 0\r\n");
            assert_eq!(c.take_wire(usize::MAX), expected);
        } else {
            result.expect("an explicit refusal may close the unfinished writer");
            assert_eq!(
                wire(&mut c),
                "grpc-status: 5\r\n",
                "the host's explicit failure is retained"
            );
        }
        assert!(c.ended());
    }
}

#[test]
fn unfinished_reply_can_be_refused_and_empty_success_remains_valid() {
    let mut c = grpc();
    c.emit(b"unfinished", false).unwrap();
    assert!(c.finish(0, b"", b"").is_err());
    c.refuse(b"reply could not complete", 500, false).unwrap();
    let failed = wire(&mut c);
    assert!(failed.contains("grpc-status:"));
    assert!(!failed.contains("grpc-status: 0\r\n"));
    assert!(!failed.contains("unfinished"));
    let opening = c.pieces().pop_front().expect("refusal opening status");
    assert_eq!(opening.status, Some(200));
    assert!(StreamCall::code_handoff(&opening));
    assert!(c.ended());

    let mut c = grpc();
    c.emit(b"", false).unwrap();
    c.finish(0, b"", b"").expect("no pending reply bytes");
    assert_eq!(wire(&mut c), "grpc-status: 0\r\n");
    assert!(c.ended());

    let mut c = grpc();
    c.emit(b"unfinished", false).unwrap();
    c.finish(13, b"failed upstream", b"")
        .expect("an explicit failure still closes");
    assert!(wire(&mut c).contains("grpc-status: 13\r\n"));
    assert!(c.ended());
}

#[test]
fn unfinished_fragments_past_the_bound_cut_the_reply() {
    let mut c = StreamCall::open(
        [(&b"content-type"[..], &b"application/grpc"[..])].into_iter(),
        100,
    )
    .unwrap();
    let bound = crate::transport::stream_bound(100);
    let chunk = [b'a'; 64];
    let mut sent = 0;
    let mut err = None;
    while sent <= bound + chunk.len() {
        match c.emit(&chunk, false) {
            Ok(()) => sent += chunk.len(),
            Err(e) => {
                err = Some(e);
                break;
            }
        }
    }
    let e = err.expect("end=false fragments past the bound are cut");
    assert!(sent <= bound, "cut only once past the bound");
    assert_eq!(e.0, crate::transport::OVER_BOUND);
    c.emit(b"more", false).unwrap();
    c.emit(b"tail", true).unwrap();
    assert!(
        c.take_wire(usize::MAX).is_empty(),
        "a cut reply writes nothing more"
    );
}

#[test]
fn refusal_opening_status_is_metadata_in_its_declared_domain() {
    let mut call = grpc();
    call.refuse(b"", 429, false).unwrap();
    let opening = call.pieces().pop_front().expect("opening status piece");
    assert_eq!(opening.status, Some(200));
    assert!(StreamCall::code_handoff(&opening));
    assert!(opening.fields);
    assert!(!wire(&mut call).contains(":status"));
}
