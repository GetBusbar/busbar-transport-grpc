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
    c.refuse(b"", 500).unwrap();
    assert_eq!(wire(&mut c), "", "a closed call owes nothing more");

    let mut c = grpc();
    c.refuse(b"", 429).unwrap();
    assert_eq!(
        wire(&mut c),
        ":status: 200\r\ncontent-type: application/grpc\r\ngrpc-status: 14\r\n\
         grpc-message: busbar%20answered%20HTTP%20429\r\n"
    );
    let mut c = grpc();
    c.refuse(b"grpc-status: 7\r\ngrpc-message: no\r\n", 0)
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

#[test]
fn the_status_message_is_encoded_as_1_5_5_encoded_it() {
    assert_eq!(
        msg::encode_status_message("a b%\"#<>`?{}~\u{2713}\n".as_bytes()),
        "a%20b%25%22%23%3C%3E%60%3F%7B%7D~%E2%9C%93%0A"
    );
}
