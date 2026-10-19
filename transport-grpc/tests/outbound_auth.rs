// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BINDING'S AUTH THROUGH THE DOOR (ruling 23; THE DESIGN §6 "Auth points and guest lists",
//! items 5 and 7): a dial whose binding has an auth calls it through the host's `auth.call`, with
//! the binding's own handle, at the points the binding names. The host verifies the handle first
//! and refuses a stale or foreign one; the framer then refuses the connection (at `begin`, the peer
//! point) or the stream (at `emit`, the head), and no HEADERS frame for it goes out.

#![allow(unsafe_code, missing_docs)]

mod common;

use std::ffi::c_void;
use std::mem::size_of;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use busbar_contract::abi::auth::{FieldSpan, FIELD_SENSITIVE, POINT_FRAME, POINT_HEAD, POINT_PEER};
use busbar_contract::abi::host::service::{
    AuthAnswer, AuthCallIn, AuthRef, HostSlots, ServiceOut, UnitRef, FLOW_CONTINUE, SCHEME_PLAIN,
    SCHEME_SECURE, SCHEME_UNDECLARED, SERVICES,
};
use busbar_contract::abi::mechanism::call::{Outcome, RawOutcome, Span};
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables, Ticket};
use busbar_contract::abi::transport::{SIDE_ACCEPT, SIDE_DIAL};

use common::{linked, Host, ROOMY, SEC};

/// The binding's own handle, as the kernel minted it for this framer.
const BOUND: AuthRef = AuthRef { id: 7, mac: 77 };
/// A handle of another generation (stale) or another owner (foreign): the host refuses it.
const STALE: AuthRef = AuthRef { id: 7, mac: 78 };
const FOREIGN: AuthRef = AuthRef { id: 9, mac: 99 };
/// The stream's unit, as the kernel minted it for the request.
const UNIT: UnitRef = UnitRef { id: 5, mac: 6 };

/// What the host saw on one `auth.call`: the handle, the point, the unit, the connection and
/// stream, and the request's field names.
#[derive(Debug, Clone)]
struct Seen {
    auth: AuthRef,
    point: u32,
    unit: UnitRef,
    conn: u64,
    stream: u64,
    scheme: u8,
    names: Vec<String>,
}

static SEEN: Mutex<Vec<Seen>> = Mutex::new(Vec::new());

/// The stream whose head the host answers NOT READY the first time its handle is called (`0` =
/// none), and the handles it pended: a resume on the same handle reads the stored answer.
static PEND_STREAM: AtomicU64 = AtomicU64::new(0);
static PENDED: Mutex<Vec<(u32, u32, u32)>> = Mutex::new(Vec::new());

/// The tests share the host's statics: one at a time.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// The host's `auth.call`: the handle verified FIRST (a stale or foreign one is REFUSED before
/// any work); at the peer point a bare continue; at the head one credential line.
extern "C" fn auth_call(_ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK hands a live `AuthCallIn` (its buffers the caller's) and a live `out`.
    unsafe {
        let i = input.cast::<AuthCallIn>().read_unaligned();
        let lent = |p: *const u8, n: usize| {
            if n == 0 {
                String::new()
            } else {
                String::from_utf8_lossy(std::slice::from_raw_parts(p, n)).into_owned()
            }
        };
        let names = if i.request.fields_len == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(i.request.fields, i.request.fields_len)
                .iter()
                .map(|f| lent(f.name.ptr, f.name.len))
                .collect()
        };
        SEEN.lock().expect("seen").push(Seen {
            auth: i.auth,
            point: i.point,
            unit: i.unit,
            conn: i.conn,
            stream: i.stream,
            scheme: i.request.scheme,
            names,
        });
        if i.auth != BOUND {
            (*out).outcome = RawOutcome::of(Outcome::Refused);
            return RawOutcome::of(Outcome::Refused);
        }
        let h = i.head.handle;
        let key = (h.ticket.slot, h.ticket.generation, h.seq);
        if i.point != POINT_PEER && i.stream == PEND_STREAM.load(Ordering::SeqCst) {
            let mut pended = PENDED.lock().expect("pended");
            if !pended.contains(&key) {
                pended.push(key);
                (*out).outcome = RawOutcome::of(Outcome::Pending);
                return RawOutcome::of(Outcome::Pending);
            }
        }
        let peer = i.point == POINT_PEER;
        let (name, value): (&[u8], &[u8]) = (b"authorization", b"Bearer bound");
        if !peer {
            std::ptr::copy_nonoverlapping(name.as_ptr(), i.buf, name.len());
            std::ptr::copy_nonoverlapping(value.as_ptr(), i.buf.add(name.len()), value.len());
            i.spans.write_unaligned(FieldSpan {
                name: Span {
                    offset: 0,
                    len: name.len() as u32,
                },
                value: Span {
                    offset: name.len() as u32,
                    len: value.len() as u32,
                },
                flags: FIELD_SENSITIVE,
                _reserved: 0,
            });
            (*out).len = (name.len() + value.len()) as u64;
            (*out).items = 1;
        }
        i.answer.write_unaligned(AuthAnswer {
            size: size_of::<AuthAnswer>() as u32,
            flow: FLOW_CONTINUE,
            unit: if peer { UnitRef::NONE } else { i.unit },
        });
        (*out).outcome = RawOutcome::of(Outcome::Ready);
    }
    RawOutcome::of(Outcome::Ready)
}

/// Host tables serving `auth.call` alone, leaked for the test's life.
fn tables() -> *const HostTables {
    let mut slots: HostSlots = common::z();
    slots.size = size_of::<HostSlots>() as u32;
    slots.slots = SERVICES;
    slots.auth_call = Some(auth_call);
    let slots: &'static HostSlots = Box::leak(Box::new(slots));
    let mut t: HostTables = common::z();
    t.size = size_of::<HostTables>() as u32;
    t.services = slots;
    Box::leak(Box::new(t))
}

/// The HTTP/2 frames a dialled connection wrote: (type, stream), after the client preface.
fn frames(wire: &[u8]) -> Vec<(u8, u32)> {
    const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    assert!(
        wire.starts_with(PREFACE),
        "a dialled connection opens with the preface"
    );
    let mut at = PREFACE.len();
    let mut out = Vec::new();
    while at + 9 <= wire.len() {
        let len = u32::from_be_bytes([0, wire[at], wire[at + 1], wire[at + 2]]) as usize;
        let stream = u32::from_be_bytes([
            wire[at + 5] & 0x7f,
            wire[at + 6],
            wire[at + 7],
            wire[at + 8],
        ]);
        out.push((wire[at + 3], stream));
        at += 9 + len;
    }
    out
}

const HEADERS: u8 = 0x1;

/// A host opened with the services table, dialling with `points` and `auth`.
fn bound(points: u32, auth: AuthRef) -> Host {
    let mut h = Host::open_with(linked(), "{}", ROOMY, tables());
    h.points = points;
    h.auth = auth;
    h.ticket = Ticket {
        slot: 1,
        generation: 1,
    };
    h.unit = UNIT;
    h
}

fn calls() -> Vec<Seen> {
    std::mem::take(&mut *SEEN.lock().expect("seen"))
}

/// RULING 23, THE HANDLE: a stale or foreign ref is refused, at either point, and nothing of the
/// refused connection or stream goes out; the binding's own ref is called at the points it names,
/// with the stream's unit and the framing's connection, over gRPC's own lines.
#[test]
fn a_stale_or_foreign_ref_is_refused_and_the_bound_one_signs() {
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _ = calls();

    // THE PEER POINT: a stale or foreign ref refuses the connection at `begin`.
    for wrong in [STALE, FOREIGN] {
        let mut h = bound(POINT_PEER | POINT_HEAD, wrong);
        assert_eq!(
            h.try_begin(SIDE_DIAL, "http://peer.test:50051", "", None),
            Outcome::Refused,
            "a {wrong:?} ref refuses the dial"
        );
        let seen = calls();
        assert_eq!(seen.len(), 1, "the peer point is called once");
        assert_eq!((seen[0].auth, seen[0].point), (wrong, POINT_PEER));
        assert!(h.wire_log.is_empty(), "nothing of a refused dial goes out");
        h.close();
    }

    // THE HEAD: a stale or foreign ref refuses the stream at `emit`; no HEADERS go out.
    for wrong in [STALE, FOREIGN] {
        let mut h = bound(POINT_HEAD, wrong);
        h.begin(SIDE_DIAL, "http://peer.test:50051", "", None);
        assert!(
            calls().is_empty(),
            "no peer point: nothing is called at begin"
        );
        let c = h.encode("/t.T/Unary", &[], b"q");
        assert_eq!(h.emit(1, &c, true, 30 * SEC), Outcome::Ready);
        let seen = calls();
        assert_eq!(seen.len(), 1, "the head is called once");
        assert_eq!((seen[0].auth, seen[0].point), (wrong, POINT_HEAD));
        let (code, _, failed, _) = h.terminal(1).expect("the refused stream ends");
        assert!(failed, "the stream fails");
        assert_eq!(code, 16, "UNAUTHENTICATED");
        assert!(
            !frames(&h.wire_log).contains(&(HEADERS, 1)),
            "no HEADERS for a refused stream"
        );
        h.close();
    }

    // THE BOUND REF: called at the peer point once, then at the head with the stream's unit, over
    // the request gRPC built (its own lines among it); the stream's HEADERS then go out.
    let mut h = bound(POINT_PEER | POINT_HEAD, BOUND);
    h.begin(SIDE_DIAL, "http://peer.test:50051", "", None);
    let c = h.encode("/t.T/Unary", &[("x-meta", "m")], b"q");
    assert_eq!(h.emit(1, &c, true, 30 * SEC), Outcome::Ready);
    let seen = calls();
    assert_eq!(seen.len(), 2, "peer once, then the head: {seen:?}");
    assert_eq!((seen[0].point, seen[0].unit), (POINT_PEER, UnitRef::NONE));
    let head = &seen[1];
    assert_eq!(
        (head.auth, head.point, head.unit),
        (BOUND, POINT_HEAD, UNIT)
    );
    assert_eq!(head.stream, 1);
    assert_eq!(
        head.conn, seen[0].conn,
        "one connection, named the same at both points"
    );
    assert_eq!(head.names, ["content-type", "te", "grpc-timeout", "x-meta"]);
    assert!(h.terminal(1).is_none(), "the signed stream is not failed");
    assert!(
        frames(&h.wire_log).contains(&(HEADERS, 1)),
        "its HEADERS go out"
    );
    h.close();
}

/// A point this framer does not serve, or a host that serves no auth call, refuses the dial: an
/// unsigned request never leaves.
#[test]
fn an_unknown_point_or_no_host_service_refuses_the_dial() {
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut h = bound(POINT_HEAD | POINT_FRAME, BOUND);
    assert_eq!(
        h.try_begin(SIDE_DIAL, "http://peer.test:50051", "", None),
        Outcome::Refused
    );
    h.close();

    let mut h = Host::open(linked(), "{}", ROOMY);
    h.points = POINT_HEAD;
    h.auth = BOUND;
    assert_eq!(
        h.try_begin(SIDE_DIAL, "http://peer.test:50051", "", None),
        Outcome::Refused
    );
    h.close();
}

/// How many HEADERS frames went out.
fn heads_sent(wire: &[u8]) -> usize {
    frames(wire).iter().filter(|(t, _)| *t == HEADERS).count()
}

/// A PENDING ANSWER PARKS ONLY ITS OWN STREAM, THROUGH THE DOOR (THE DESIGN §6 item 7; step 2's
/// per-stream tickets): stream 1's `emit` crosses on its own ticket and answers PENDING, nothing of
/// it going out; stream 3's `emit`, on another ticket, is signed and its HEADERS go out meanwhile;
/// stream 1's resume (its ticket, no new bytes) reads the stored answer and its HEADERS follow.
#[test]
fn a_pending_auth_on_one_stream_does_not_hold_another_through_the_door() {
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _ = calls();
    PEND_STREAM.store(1, Ordering::SeqCst);
    let mut h = bound(POINT_HEAD, BOUND);
    h.begin(SIDE_DIAL, "http://peer.test:50051", "", None);
    let one = h.encode("/t.T/One", &[], b"1");
    let three = h.encode("/t.T/Three", &[], b"3");
    let ticket = |slot| Ticket {
        slot,
        generation: 1,
    };

    h.ticket = ticket(2);
    assert_eq!(h.emit(1, &one, true, 30 * SEC), Outcome::Pending);
    assert_eq!(
        heads_sent(&h.wire_log),
        0,
        "nothing of a parked stream goes out"
    );

    h.ticket = ticket(3);
    assert_eq!(h.emit(3, &three, true, 30 * SEC), Outcome::Ready);
    assert_eq!(
        heads_sent(&h.wire_log),
        1,
        "stream 3 went out while stream 1 is parked"
    );
    assert!(h.terminal(3).is_none(), "stream 3 is not failed");

    // THE RESUME: stream 1's own ticket, no new bytes.
    h.ticket = ticket(2);
    assert_eq!(h.emit(1, &[], true, 30 * SEC), Outcome::Ready);
    assert_eq!(
        heads_sent(&h.wire_log),
        2,
        "stream 1's HEADERS follow its answer"
    );
    assert!(h.terminal(1).is_none(), "stream 1 is not failed");
    let seen = calls();
    let ones: Vec<&Seen> = seen.iter().filter(|c| c.stream == 1).collect();
    assert_eq!(ones.len(), 2, "the call and its resume, on one handle");
    assert_eq!(
        ones[0].names, ones[1].names,
        "the resume is called over the same head"
    );
    PEND_STREAM.store(0, Ordering::SeqCst);
    h.close();
}

/// THE SCHEME IS THE HOST'S (step 2, `BeginIn::scheme`): the view the auth is called over carries
/// the code the host declared at `begin`, never one the framer derives from its own dial (a
/// cleartext target the host declares secure is signed as secure); an undeclared scheme refuses
/// `begin` on either side, before anything is called or written.
#[test]
fn the_view_carries_the_hosts_scheme_and_a_zero_scheme_is_refused() {
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _ = calls();
    for declared in [SCHEME_PLAIN, SCHEME_SECURE] {
        let mut h = bound(POINT_HEAD, BOUND);
        h.scheme = declared;
        h.begin(SIDE_DIAL, "http://peer.test:50051", "", None);
        let c = h.encode("/t.T/Unary", &[], b"q");
        assert_eq!(h.emit(1, &c, true, 30 * SEC), Outcome::Ready);
        let seen = calls();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].scheme, declared, "the host's code, as declared");
        h.close();
    }

    for side in [SIDE_DIAL, SIDE_ACCEPT] {
        let mut h = bound(POINT_HEAD, BOUND);
        h.scheme = SCHEME_UNDECLARED;
        assert_eq!(
            h.try_begin(side, "http://peer.test:50051", "", None),
            Outcome::Refused,
            "side {side}: a zero scheme is refused at begin"
        );
        assert!(h.wire_log.is_empty(), "side {side}: nothing is written");
        h.close();
    }
    assert!(calls().is_empty(), "nothing is called on a refused begin");
}
