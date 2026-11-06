// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST'S RECEIVE BACKPRESSURE: a connection framing reports the far-side bytes it holds
//! unread (`framer.retained_input`), so a host does not keep feeding a connection whose far end
//! has stopped reading what it owes it.

mod common;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::transport::SIDE_ACCEPT;
use common::{dropped, linked, Host, ROOMY};

/// The client preface, an empty SETTINGS, then `pings` PINGs: each owes the far end a PING ACK.
fn ping_flood(pings: usize) -> Vec<u8> {
    let mut wire = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    wire.extend([0, 0, 0, 4, 0, 0, 0, 0, 0]);
    for n in 0..pings {
        wire.extend([0, 0, 8, 6, 0, 0, 0, 0, 0]);
        wire.extend((n as u64).to_be_bytes());
    }
    wire
}

/// A far end that sends PINGs and takes none of the ACKs it is owed stalls the connection once
/// the owed bytes reach their high-water mark: what it sent past that is held unread, and the
/// answer says how much. As the host takes the owed bytes the connection reads on, and the report
/// falls to zero.
#[test]
fn a_stalled_connection_reports_the_far_side_bytes_it_holds_unread() {
    for ops in [linked(), dropped().0] {
        let mut host = Host::open(ops, "{}", ROOMY);
        host.begin(SIDE_ACCEPT, "", "", None);
        let flood = ping_flood(30_000);
        let (outcome, retained) = host.feed_reported(&flood);
        assert_eq!(outcome, Outcome::Ready);
        let retained = retained.expect("the answer reports the input it retains");
        assert!(
            retained > 0 && retained < flood.len() as u64,
            "a stalled connection holds part of what it was fed: {retained} of {}",
            flood.len()
        );
        let mut last = retained;
        for _ in 0..1_000 {
            let (outcome, now) = host.feed_reported(&[]);
            assert_eq!(outcome, Outcome::Ready);
            last = now.expect("every answer reports");
            if last == 0 {
                break;
            }
        }
        assert_eq!(
            last, 0,
            "once the owed bytes are taken, nothing is held unread"
        );
        host.close();
    }
}

/// A CONNECTION THE FAR END BROKE STILL SAYS WHY: a DATA frame on stream 0 is a connection error
/// (RFC 9113 §6.1), and the GOAWAY the HTTP/2 machine writes for it reaches the host's wire before
/// the framing fails, never dropped with it.
#[test]
fn a_connection_error_hands_the_host_its_goaway_before_failing() {
    for ops in [linked(), dropped().0] {
        let mut host = Host::open(ops, "{}", ROOMY);
        host.begin(SIDE_ACCEPT, "", "", None);
        let mut wire = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        wire.extend([0, 0, 0, 4, 0, 0, 0, 0, 0]);
        wire.extend([0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
        let _ = host.feed(&wire, false);
        let mut types = Vec::new();
        let mut at = 0;
        let log = &host.wire_log;
        while at + 9 <= log.len() {
            let len = usize::from(log[at]) << 16
                | usize::from(log[at + 1]) << 8
                | usize::from(log[at + 2]);
            types.push(log[at + 3]);
            at += 9 + len;
        }
        assert!(
            types.contains(&7),
            "the GOAWAY reached the host's wire: frame types {types:?}"
        );
        assert_eq!(
            host.feed(&[], false),
            Outcome::Failed,
            "once its wire is taken, the broken connection fails"
        );
        host.close();
    }
}
