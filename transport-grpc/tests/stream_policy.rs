// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

mod common;

use std::cell::{Cell, RefCell};
use std::ffi::c_void;
use std::mem::size_of;

use busbar_contract::abi::host::service::{
    AuthAnswer, AuthRef, HostSlots, RefusalAnswer, ServiceOut, UnitHandInIn, UnitRef, UnitRefuseIn,
    FLOW_CONTINUE, FLOW_STOP, LINE_NONE, REFUSE_CHECK_FAILED, REFUSE_METHOD_MISS, REFUSE_NO_ROUTE,
    SCHEME_PLAIN, SERVICES,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, Field, InHead, OutHead, Outcome, RawOutcome, BLOB_OCTETS,
};
use busbar_contract::abi::mechanism::extensions;
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, CancelIn, CancelOut, OpenIn, OpenOut, ReleaseIn,
};
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables, Ticket};
use busbar_contract::abi::transport::guest_policy::{
    self, GuestLine, Open, EXT_GUEST_OPEN, EXT_GUEST_POLICY,
};
use busbar_contract::abi::transport::route::{METHOD_GET, METHOD_POST, PATH_EXACT};
use busbar_contract::abi::transport::{
    slot, BeginIn, FramePiece, FramerOut, FramerSink, HeadSlots, IngestIn, Ops, CANCEL_PARTIAL,
    PIECE_FIELDS, PIECE_STREAM_FAILED, SIDE_ACCEPT, SIDE_ACCEPT_STREAM, YIELD_MORE,
};
use common::{call, linked, s, z};

#[derive(Debug)]
struct Handed {
    auth: AuthRef,
    unit: UnitRef,
    line: u32,
    stream: u64,
    method: String,
    target: String,
    query: String,
    authority: String,
    scheme: u8,
}

thread_local! {
    static HANDED: RefCell<Vec<Handed>> = const { RefCell::new(Vec::new()) };
    static REFUSAL_MODE: Cell<u8> = const { Cell::new(0) };
    static REFUSAL_FIELD: RefCell<Option<Field>> = const { RefCell::new(None) };
    static FLOW: Cell<u32> = const { Cell::new(FLOW_CONTINUE) };
    static NO_UNIT: Cell<bool> = const { Cell::new(false) };
    static REFUSED: RefCell<Vec<(u32, u32, UnitRef)>> = const { RefCell::new(Vec::new()) };
}

fn text(value: AbiStr) -> String {
    if value.len == 0 {
        return String::new();
    }
    // SAFETY: the service caller lends this input string for the entire callback.
    String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(value.ptr, value.len) })
        .into_owned()
}

extern "C" fn hand_in(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: Services::unit_hand_in lends this complete input and its answer buffers.
    unsafe {
        let input = input.cast::<UnitHandInIn>().read_unaligned();
        HANDED.with(|seen| {
            seen.borrow_mut().push(Handed {
                auth: input.auth,
                unit: input.unit,
                line: input.line,
                stream: input.stream,
                method: text(input.request.method),
                target: text(input.request.target),
                query: text(input.request.query),
                authority: text(input.request.authority),
                scheme: input.request.scheme,
            })
        });
        input.answer.write_unaligned(AuthAnswer {
            size: size_of::<AuthAnswer>() as u32,
            flow: FLOW.with(Cell::get),
            unit: if NO_UNIT.with(Cell::get) {
                UnitRef::NONE
            } else {
                UnitRef {
                    id: u64::from(input.line),
                    mac: input.auth.mac,
                }
            },
        });
        (*out).outcome = RawOutcome::of(Outcome::Ready);
    }
    RawOutcome::of(Outcome::Ready)
}

extern "C" fn refuse(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: Services::unit_refuse lends the complete input and its answer buffers.
    unsafe {
        let input = input.cast::<UnitRefuseIn>().read_unaligned();
        REFUSED.with(|seen| {
            seen.borrow_mut()
                .push((input.cause, input.line, input.unit))
        });
        let mode = REFUSAL_MODE.with(Cell::get);
        let fields = REFUSAL_FIELD.with(|stored| {
            let mut stored = stored.borrow_mut();
            *stored = match mode {
                2 => Some(Field {
                    name: s("bad name"),
                    value: s("value"),
                }),
                3 => Some(Field {
                    name: s("x-refusal"),
                    value: s("bad\r\nvalue"),
                }),
                _ => None,
            };
            stored.as_ref().map_or(std::ptr::null(), std::ptr::from_ref)
        });
        input.answer.write_unaligned(RefusalAnswer {
            size: size_of::<RefusalAnswer>() as u32,
            status: if mode == 1 { 99 } else { 403 },
            fields,
            fields_len: usize::from(!fields.is_null()),
            body: Blob::of(b"denied-verbatim"),
        });
        (*out).outcome = RawOutcome::of(Outcome::Ready);
    }
    RawOutcome::of(Outcome::Ready)
}

fn ticket(slot: u32) -> Ticket {
    Ticket {
        slot,
        generation: 1,
    }
}

fn blob(bytes: &[u8]) -> Blob {
    Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    }
}

fn policy(generation: u64, line: u32, path: &str) -> Vec<u8> {
    policy_for_methods(generation, line, path, METHOD_POST)
}

fn policy_for_methods(generation: u64, line: u32, path: &str, methods: u32) -> Vec<u8> {
    policy_with_points(generation, line, path, methods, 0)
}

fn policy_with_points(
    generation: u64,
    line: u32,
    path: &str,
    methods: u32,
    points: u32,
) -> Vec<u8> {
    let line = GuestLine {
        line,
        points,
        auth: AuthRef {
            id: u64::from(line),
            mac: generation,
        },
        body_limit: 0,
        methods,
        path_form: PATH_EXACT,
        path: path.into(),
        fields: Vec::new(),
        rung: 0,
    };
    let value = guest_policy::encode(7, generation, &[line]).unwrap();
    extensions::encode(&[(EXT_GUEST_POLICY, &value)])
}

struct Answer {
    outcome: Outcome,
    flags: u32,
    wire: Vec<u8>,
    pieces: Vec<(FramePiece, Vec<u8>)>,
    open: Option<Open>,
    framing: u64,
    error: String,
}

struct Host {
    ops: &'static Ops,
    instance: *mut c_void,
    framing: u64,
    now_ns: u64,
    wire: Vec<u8>,
    frame: Vec<u8>,
    pieces: Vec<FramePiece>,
    heads: Vec<HeadSlots>,
    _slots: Box<HostSlots>,
    _tables: Box<HostTables>,
}

impl Host {
    fn new() -> Self {
        Self::on(linked())
    }

    fn on(ops: &'static Ops) -> Self {
        HANDED.with(|seen| seen.borrow_mut().clear());
        REFUSED.with(|seen| seen.borrow_mut().clear());
        FLOW.with(|flow| flow.set(FLOW_CONTINUE));
        NO_UNIT.with(|none| none.set(false));
        REFUSAL_MODE.with(|mode| mode.set(0));
        let mut slots: Box<HostSlots> = Box::new(z());
        slots.size = size_of::<HostSlots>() as u32;
        slots.slots = SERVICES;
        slots.unit_hand_in = Some(hand_in);
        slots.unit_refuse = Some(refuse);
        let mut tables: Box<HostTables> = Box::new(z());
        tables.size = size_of::<HostTables>() as u32;
        tables.services = &*slots;
        let mut input: OpenIn = z();
        input.host = &*tables;
        let mut out: OpenOut = z();
        assert_eq!(
            // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
            // and the door instance for this synchronous call; the selected slot and index agree.
            unsafe {
                call(
                    ops.head.open,
                    std::ptr::null_mut(),
                    &mut input,
                    &mut out,
                    life::OPEN,
                )
            },
            Outcome::Ready
        );
        Self {
            ops,
            instance: out.instance,
            framing: 0,
            now_ns: 7_000_000_000,
            wire: vec![0; 65536],
            frame: vec![0; 65536],
            pieces: vec![z(); 64],
            heads: vec![z(); 64],
            _slots: slots,
            _tables: tables,
        }
    }

    fn sink(&mut self) -> FramerSink {
        FramerSink {
            wire: self.wire.as_mut_ptr(),
            wire_cap: self.wire.len(),
            frame: self.frame.as_mut_ptr(),
            frame_cap: self.frame.len(),
            pieces: self.pieces.as_mut_ptr(),
            pieces_cap: self.pieces.len(),
            heads: self.heads.as_mut_ptr(),
            heads_cap: self.heads.len(),
            now_monotonic_ns: self.now_ns,
            now_unix_ns: 1_790_000_000_000_000_000,
        }
    }

    fn capture(&mut self, outcome: Outcome, out: FramerOut) -> Answer {
        let ext = if out.head.extensions.len == 0 {
            Vec::new()
        } else {
            // SAFETY: the door's answer lease owns these bytes until released below.
            unsafe { std::slice::from_raw_parts(out.head.extensions.ptr, out.head.extensions.len) }
                .to_vec()
        };
        let open = extensions::get(&ext, EXT_GUEST_OPEN).map(|value| Open::decode(value).unwrap());
        if open.is_some() {
            // A policy-open answer carries its open alone: the retained-input report rides only
            // answers that finished their drive.
            assert_eq!(
                busbar_contract::abi::sdk::transport::receive::decode(&ext),
                Ok(None),
                "a policy-open answer carries no retained-input report"
            );
        }
        let answer = Answer {
            outcome,
            flags: out.yielded.flags,
            wire: self.wire[..out.yielded.wire_len as usize].to_vec(),
            pieces: self.pieces[..out.yielded.pieces_len as usize]
                .iter()
                .map(|piece| {
                    (
                        *piece,
                        self.frame[piece.offset as usize..(piece.offset + piece.len) as usize]
                            .to_vec(),
                    )
                })
                .collect(),
            open,
            framing: out.framing,
            error: text(out.head.error),
        };
        if out.head.lease != 0 {
            let mut input: ReleaseIn = z();
            input.lease = out.head.lease;
            let mut released: OutHead = z();
            assert_eq!(
                // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
                // and the door instance for this synchronous call; the selected slot and index agree.
                unsafe {
                    call(
                        self.ops.head.release,
                        self.instance,
                        &mut input,
                        &mut released,
                        life::RELEASE,
                    )
                },
                Outcome::Ready
            );
        }
        answer
    }

    fn begin(&mut self, side: u32, ext: &[u8]) -> Answer {
        let value = b"application/grpc";
        let fields = [Field {
            name: s("content-type"),
            value: AbiStr {
                ptr: value.as_ptr(),
                len: value.len(),
            },
        }];
        let mut input: BeginIn = z();
        input.side = side;
        input.target = s("http://policy.test:50051");
        input.scheme = SCHEME_PLAIN;
        input.head.ticket = ticket(1);
        input.head.extensions = blob(ext);
        input.fields = fields.as_ptr();
        input.fields_len = fields.len();
        input.sink = self.sink();
        let mut out: FramerOut = z();
        // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
        // and the door instance for this synchronous call; the selected slot and index agree.
        let result = unsafe {
            call(
                self.ops.begin,
                self.instance,
                &mut input,
                &mut out,
                slot::BEGIN,
            )
        };
        self.framing = out.framing;
        self.capture(result, out)
    }

    fn ingest(&mut self, bytes: &[u8], ext: &[u8], ticket: Ticket) -> Answer {
        let mut input: IngestIn = z();
        input.framing = self.framing;
        input.head.ticket = ticket;
        input.head.extensions = blob(ext);
        input.bytes = bytes.as_ptr();
        input.len = bytes.len();
        input.sink = self.sink();
        let mut out: FramerOut = z();
        // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
        // and the door instance for this synchronous call; the selected slot and index agree.
        let result = unsafe {
            call(
                self.ops.ingest,
                self.instance,
                &mut input,
                &mut out,
                slot::INGEST,
            )
        };
        self.capture(result, out)
    }

    fn until_open(&mut self, bytes: &[u8], ticket: Ticket) -> (Answer, Vec<u8>) {
        let mut original = bytes.to_vec();
        let mut answer = self.ingest(&original, &[], ticket);
        for _ in 0..100 {
            assert_eq!(answer.outcome, Outcome::Ready);
            assert!(
                answer.pieces.is_empty(),
                "no head/body before the selected loan and hand-in"
            );
            if answer.open.is_some() {
                return (answer, original);
            }

            original.clear();
            answer = self.ingest(&[], &[], ticket);
        }
        panic!("the actual gRPC door did not request a policy before publishing the call")
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let mut input: InHead = z();
        let mut out: OutHead = z();
        // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
        // and the door instance for this synchronous call; the selected slot and index agree.
        let _ = unsafe {
            call(
                self.ops.head.close,
                self.instance,
                &mut input,
                &mut out,
                life::CLOSE,
            )
        };
    }
}

fn frame(kind: u8, flags: u8, stream: u32, body: &[u8]) -> Vec<u8> {
    let mut wire = vec![
        (body.len() >> 16) as u8,
        (body.len() >> 8) as u8,
        body.len() as u8,
        kind,
        flags,
    ];
    wire.extend_from_slice(&stream.to_be_bytes());
    wire.extend_from_slice(body);
    wire
}

fn opening() -> Vec<u8> {
    let mut wire = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    wire.extend(frame(4, 0, 0, &[]));
    wire
}

fn request(stream: u32, target: &str, body: &[u8], end: bool) -> Vec<u8> {
    let mut head = vec![0x83, 0x86];
    for (name, value) in [
        (":path", target),
        (":authority", "policy.test"),
        ("content-type", "application/grpc"),
    ] {
        head.extend([0, name.len() as u8]);
        head.extend_from_slice(name.as_bytes());
        head.push(value.len() as u8);
        head.extend_from_slice(value.as_bytes());
    }
    let mut wire = frame(1, 4, stream, &head);
    wire.extend(frame(0, u8::from(end), stream, body));
    wire
}

fn message(bytes: &[u8]) -> Vec<u8> {
    let mut framed = vec![0];
    framed.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    framed.extend_from_slice(bytes);
    framed
}

#[test]
fn every_multiplexed_request_uses_its_selected_loan_before_head_or_body_and_hands_in_once() {
    let mut host = Host::new();
    assert_eq!(
        host.begin(SIDE_ACCEPT, &policy(1, 11, "/initial")).outcome,
        Outcome::Ready
    );
    let first_message = message(b"first");
    let mut bytes = opening();
    bytes.extend(request(1, "/first?q=kept", &first_message[..3], false));
    bytes.extend(request(3, "/second", &message(b"second"), true));
    let (opening, original) = host.until_open(&bytes, ticket(2));
    assert_eq!(opening.open.unwrap().stream, 1);
    assert_eq!(opening.flags & YIELD_MORE, YIELD_MORE);
    assert!(opening.wire.is_empty());
    HANDED.with(|seen| assert!(seen.borrow().is_empty()));
    let mut answer = host.ingest(&original, &policy(2, 22, "/first"), ticket(2));
    let mut pieces = Vec::new();
    for _ in 0..100 {
        assert_eq!(answer.outcome, Outcome::Ready);
        pieces.extend(answer.pieces);
        if let Some(open) = answer.open {
            assert_eq!(open.stream, 2);
            assert!(answer.wire.is_empty());
            break;
        }
        answer = host.ingest(&[], &[], ticket(3));
    }
    let selected = host.ingest(&[], &policy(3, 33, "/second"), ticket(3));
    assert_eq!(selected.outcome, Outcome::Ready);
    pieces.extend(selected.pieces);
    let later = host.ingest(&frame(0, 1, 1, &first_message[3..]), &[], ticket(4));
    assert_eq!(later.outcome, Outcome::Ready);
    pieces.extend(later.pieces);
    for _ in 0..10 {
        pieces.extend(host.ingest(&[], &[], ticket(5)).pieces);
    }
    for (stream, expected) in [(1, &b"first"[..]), (2, &b"second"[..])] {
        let heads = pieces
            .iter()
            .filter(|(piece, _)| piece.stream == stream && piece.flags & PIECE_FIELDS != 0)
            .count();
        assert_eq!(heads, 1, "one admitted head per stream");
        let payload: Vec<_> = pieces
            .iter()
            .filter(|(piece, _)| piece.stream == stream && piece.flags & PIECE_FIELDS == 0)
            .flat_map(|(_, bytes)| bytes.iter().copied())
            .collect();
        assert_eq!(
            payload,
            message(expected),
            "the original DATA is consumed exactly once"
        );
    }
    HANDED.with(|seen| {
        let seen = seen.borrow();
        assert_eq!(seen.len(), 2);
        for (got, line, generation, stream, target) in [
            (&seen[0], 22, 2, 1, "/first"),
            (&seen[1], 33, 3, 2, "/second"),
        ] {
            assert_eq!(
                (got.line, got.auth.id, got.auth.mac, got.stream),
                (line, u64::from(line), generation, stream)
            );
            assert!(got.unit.is_none());
            assert_eq!(got.method, "POST");
            assert_eq!(got.target, target);
            assert_eq!(got.authority, "policy.test");
            assert_eq!(got.scheme, SCHEME_PLAIN);
        }
        assert_eq!(seen[0].query, "q=kept");
    });
}

#[test]
fn cancelling_a_policy_wait_drops_only_that_unadmitted_stream() {
    let mut host = Host::new();
    host.begin(SIDE_ACCEPT, &policy(1, 11, "/initial"));
    let mut bytes = opening();
    bytes.extend(request(1, "/first", &message(b"private"), false));
    host.until_open(&bytes, ticket(2));
    let mut input: CancelIn = z();
    input.ticket = ticket(2);
    let mut out: CancelOut = z();
    assert_eq!(
        // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
        // and the door instance for this synchronous call; the selected slot and index agree.
        unsafe {
            call(
                host.ops.head.cancel,
                host.instance,
                &mut input,
                &mut out,
                life::CANCEL,
            )
        },
        Outcome::Ready
    );
    assert_eq!(out.disposition, CANCEL_PARTIAL);
    HANDED.with(|seen| assert!(seen.borrow().is_empty()));
    let next = request(3, "/second", &message(b"second"), true);
    let (open, original) = host.until_open(&next, ticket(3));
    assert_eq!(open.open.unwrap().stream, 2);
    let admitted = host.ingest(&original, &policy(3, 33, "/second"), ticket(3));
    assert_eq!(admitted.outcome, Outcome::Ready);
    assert!(admitted.pieces.iter().all(|(piece, _)| piece.stream == 2));
    HANDED.with(|seen| assert_eq!(seen.borrow().len(), 1));
}

#[test]
fn a_peer_reset_while_waiting_reports_failure_without_handing_in_or_publishing_a_head() {
    let mut host = Host::new();
    host.begin(SIDE_ACCEPT, &policy(1, 11, "/initial"));
    let mut bytes = opening();
    bytes.extend(request(1, "/first", &[], false));
    host.until_open(&bytes, ticket(2));
    let reset = frame(3, 0, 1, &8_u32.to_be_bytes());
    let reset_result = host.ingest(&reset, &[], ticket(3));
    let mut failed = host.ingest(&[], &policy(2, 22, "/first"), ticket(2));
    failed.pieces.extend(reset_result.pieces);
    assert_eq!(failed.outcome, Outcome::Ready);
    assert!(failed
        .pieces
        .iter()
        .any(|(piece, _)| piece.stream == 1 && piece.flags & PIECE_STREAM_FAILED != 0));
    assert!(failed
        .pieces
        .iter()
        .all(|(piece, _)| piece.flags & PIECE_FIELDS == 0));
    HANDED.with(|seen| assert!(seen.borrow().is_empty()));
}

#[test]
fn a_malformed_stream_policy_never_reaches_admission_or_request_publication() {
    let mut host = Host::new();
    host.begin(SIDE_ACCEPT, &policy(1, 11, "/initial"));
    let mut bytes = opening();
    bytes.extend(request(1, "/first", &message(b"private"), true));
    let (_, original) = host.until_open(&bytes, ticket(2));
    let malformed = extensions::encode(&[(EXT_GUEST_POLICY, b"invalid")]);
    let failed = host.ingest(&original, &malformed, ticket(2));
    assert_eq!(failed.outcome, Outcome::Failed);
    assert!(failed.pieces.is_empty());
    HANDED.with(|seen| assert!(seen.borrow().is_empty()));
}

#[test]
fn the_already_admitted_body_only_adapter_needs_no_policy_or_host_admission() {
    let mut host = Host::new();
    let begin = host.begin(SIDE_ACCEPT_STREAM, &[]);
    assert_eq!(begin.outcome, Outcome::Ready);
    assert_ne!(begin.framing, 0);
    let got = host.ingest(&message(b"body"), &[], ticket(2));
    assert_eq!(got.outcome, Outcome::Ready);
    assert!(got.open.is_none());
    assert_eq!(got.pieces[0].1, b"body");
    HANDED.with(|seen| assert!(seen.borrow().is_empty()));
    let mut other = Host::new();
    let unexpected = other.begin(SIDE_ACCEPT_STREAM, &policy(1, 11, "/initial"));
    assert_eq!(unexpected.outcome, Outcome::Refused);
    assert_eq!(unexpected.framing, 0);
}

#[test]
fn a_host_stopped_hand_in_preserves_its_refusal_and_publishes_no_request() {
    let mut host = Host::new();
    host.begin(SIDE_ACCEPT, &policy(1, 11, "/initial"));
    let mut bytes = opening();
    bytes.extend(request(1, "/first", &message(b"private"), true));
    let (_, original) = host.until_open(&bytes, ticket(2));
    FLOW.with(|flow| flow.set(FLOW_STOP));
    let refused = host.ingest(&original, &policy(2, 22, "/first"), ticket(2));
    assert_eq!(refused.outcome, Outcome::Ready);
    assert!(refused
        .wire
        .windows(b"denied-verbatim".len())
        .any(|bytes| bytes == b"denied-verbatim"));
    assert!(refused
        .pieces
        .iter()
        .all(|(piece, _)| piece.flags & PIECE_FIELDS == 0));
    assert!(refused
        .pieces
        .iter()
        .any(|(piece, _)| piece.flags & PIECE_STREAM_FAILED != 0));
    REFUSED.with(|seen| {
        assert_eq!(
            seen.borrow().as_slice(),
            &[(REFUSE_CHECK_FAILED, 22, UnitRef { id: 22, mac: 2 })]
        )
    });
}

#[test]
fn the_actual_http_method_must_match_before_a_none_line_is_handed_in() {
    let (dropped, _library) = common::dropped();
    for ops in [linked(), dropped] {
        let mut host = Host::on(ops);
        host.begin(SIDE_ACCEPT, &policy(1, 11, "/initial"));
        let call = request(1, "/first", &[], true);
        let mut bytes = opening();
        bytes.extend(call);
        let (_, original) = host.until_open(&bytes, ticket(2));
        let refused = host.ingest(
            &original,
            &policy_for_methods(2, 22, "/first", METHOD_GET),
            ticket(2),
        );
        assert_eq!(refused.outcome, Outcome::Ready);
        assert!(refused
            .pieces
            .iter()
            .all(|(piece, _)| piece.flags & PIECE_FIELDS == 0));
        HANDED.with(|seen| assert!(seen.borrow().is_empty()));
        REFUSED.with(|seen| {
            assert_eq!(
                seen.borrow().as_slice(),
                &[(REFUSE_METHOD_MISS, 22, UnitRef::NONE)]
            )
        });
    }
}

#[test]
fn an_invalid_get_is_refused_before_requesting_policy_or_handing_in_a_none_line() {
    let (dropped, _library) = common::dropped();
    for ops in [linked(), dropped] {
        let mut host = Host::on(ops);
        assert_eq!(
            host.begin(SIDE_ACCEPT, &policy(1, 11, "/initial")).outcome,
            Outcome::Ready
        );
        let mut call = request(1, "/first", &[], true);
        assert_eq!(
            call[9], 0x83,
            "the encoded request starts with :method POST"
        );
        call[9] = 0x82;
        let mut bytes = opening();
        bytes.extend(call);
        let mut answer = host.ingest(&bytes, &[], ticket(2));
        let mut wire = Vec::new();
        let mut terminal = false;
        for _ in 0..100 {
            assert_eq!(answer.outcome, Outcome::Ready);
            assert!(
                answer.open.is_none(),
                "an invalid gRPC method never requests a policy loan"
            );
            assert!(
                answer.pieces.is_empty(),
                "no request head or body crosses the admission boundary"
            );
            HANDED.with(|seen| assert!(seen.borrow().is_empty()));
            REFUSED.with(|seen| {
                assert!(
                    seen.borrow().is_empty(),
                    "protocol refusal precedes any host none-line decision"
                )
            });
            wire.extend_from_slice(&answer.wire);
            let mut at = 0;
            while at + 9 <= wire.len() {
                let length = (usize::from(wire[at]) << 16)
                    | (usize::from(wire[at + 1]) << 8)
                    | usize::from(wire[at + 2]);
                if at + 9 + length > wire.len() {
                    break;
                }
                let stream =
                    u32::from_be_bytes(wire[at + 5..at + 9].try_into().unwrap()) & 0x7fff_ffff;
                if stream == 1 && matches!(wire[at + 3], 0 | 1) && wire[at + 4] & 1 != 0 {
                    terminal = true;
                }
                at += 9 + length;
            }
            if terminal {
                break;
            }
            answer = host.ingest(&[], &[], ticket(2));
        }
        assert!(
            terminal,
            "the actual door must send a terminal HTTP/2 refusal on the invalid request's stream"
        );
    }
}

#[test]
fn the_body_only_begin_declares_final_fields_once_across_tiny_wire_sinks_linked_and_dropped() {
    let (dropped, _image) = common::dropped();
    for (label, ops) in [("linked", linked()), ("dropped", dropped)] {
        for capacity in [1, 7, 65536] {
            let mut host = Host::on(ops);
            host.wire.resize(capacity, 0);
            let mut answer = host.begin(SIDE_ACCEPT_STREAM, &[]);
            assert_eq!(answer.outcome, Outcome::Ready, "{label}");
            let token = answer.framing;
            let mut declaration = answer.wire;
            for _ in 0..256 {
                if answer.flags & YIELD_MORE == 0 {
                    break;
                }
                let mut input: busbar_contract::abi::transport::FramingIn = z();
                input.framing = token;
                input.sink = host.sink();
                let mut out: FramerOut = z();
                // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
                // and the door instance for this synchronous call; the selected slot and index agree.
                let result = unsafe {
                    call(
                        host.ops.timer,
                        host.instance,
                        &mut input,
                        &mut out,
                        slot::TIMER,
                    )
                };
                answer = host.capture(result, out);
                assert_eq!(answer.outcome, Outcome::Ready, "{label}");
                declaration.extend_from_slice(&answer.wire);
            }
            assert_eq!(
                answer.flags & YIELD_MORE,
                0,
                "{label}: finite declaration drains"
            );
            assert_eq!(declaration,
                b"trailer: grpc-status, grpc-message, grpc-status-details-bin, grpc-accept-encoding\r\n",
                "{label}: Begin's wire is one complete initial field block");
            let mut input: busbar_contract::abi::transport::FramingIn = z();
            input.framing = token;
            input.sink = host.sink();
            let mut out: FramerOut = z();
            // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
            // and the door instance for this synchronous call; the selected slot and index agree.
            let result = unsafe {
                call(
                    host.ops.timer,
                    host.instance,
                    &mut input,
                    &mut out,
                    slot::TIMER,
                )
            };
            assert!(
                host.capture(result, out).wire.is_empty(),
                "declaration is not replayed"
            );
            let got = host.ingest(&message(b"body"), &[], ticket(2));
            assert_eq!(got.outcome, Outcome::Ready);
            assert!(
                got.wire.is_empty(),
                "initial fields never prefix payload output"
            );
            assert_eq!(got.pieces[0].1, b"body");
        }
    }
}

#[test]
fn unsupported_neutral_emit_kinds_refuse_before_consuming_in_every_grpc_mode() {
    use busbar_contract::abi::transport::{EmitIn, EMIT_TRAILERS, SIDE_DIAL};
    let (dropped, _image) = common::dropped();
    for (label, ops) in [("linked", linked()), ("dropped", dropped)] {
        for side in [SIDE_DIAL, SIDE_ACCEPT, SIDE_ACCEPT_STREAM] {
            let mut host = Host::on(ops);
            let begin = host.begin(side, &[]);
            assert_eq!(begin.outcome, Outcome::Ready);
            for flags in [EMIT_TRAILERS, 0x8000_0000] {
                let bytes = b"grpc-status: 0\r\n";
                let mut input: EmitIn = z();
                input.framing = host.framing;
                input.stream = 1;
                input.head.ticket = ticket(2);
                input.bytes = bytes.as_ptr();
                input.len = bytes.len();
                input.flags = flags;
                input.end_of_frame = 1;
                input.sink = host.sink();
                let mut out: FramerOut = z();
                // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
                // and the door instance for this synchronous call; the selected slot and index agree.
                let result = unsafe {
                    call(
                        host.ops.emit,
                        host.instance,
                        &mut input,
                        &mut out,
                        slot::EMIT,
                    )
                };
                let rejected = host.capture(result, out);
                assert_eq!(rejected.outcome, Outcome::Refused, "{label}: side {side}");
                assert!(rejected.wire.is_empty() && rejected.pieces.is_empty());
            }
            if side == SIDE_ACCEPT_STREAM {
                let mut input: EmitIn = z();
                input.framing = host.framing;
                input.stream = 1;
                input.bytes = b"reply".as_ptr();
                input.len = 5;
                input.end_of_frame = 1;
                input.sink = host.sink();
                let mut out: FramerOut = z();
                // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
                // and the door instance for this synchronous call; the selected slot and index agree.
                let result = unsafe {
                    call(
                        host.ops.emit,
                        host.instance,
                        &mut input,
                        &mut out,
                        slot::EMIT,
                    )
                };
                let reply = host.capture(result, out);
                assert_eq!(reply.outcome, Outcome::Ready);
                assert_eq!(
                    reply.wire,
                    message(b"reply"),
                    "rejected trailer bytes did not enter the body"
                );
            }
        }
    }
}

#[test]
fn invalid_host_refusals_retire_the_stream_and_leave_the_connection_usable() {
    use busbar_contract::abi::transport::EmitIn;
    for mode in [1, 2, 3] {
        let mut host = Host::new();
        host.begin(SIDE_ACCEPT, &policy(1, 11, "/initial"));
        let mut bytes = opening();
        bytes.extend(request(1, "/first", &[], true));
        let (_, original) = host.until_open(&bytes, ticket(2));
        FLOW.with(|flow| flow.set(FLOW_STOP));
        REFUSAL_MODE.with(|value| value.set(mode));
        let failed = host.ingest(&original, &policy(2, 22, "/first"), ticket(2));
        assert_eq!(
            failed.outcome,
            Outcome::Failed,
            "invalid refusal mode {mode}"
        );
        let mut input: EmitIn = z();
        input.framing = host.framing;
        input.stream = 1;
        input.head.ticket = ticket(4);
        input.end_of_frame = 1;
        input.sink = host.sink();
        let mut out: FramerOut = z();
        // SAFETY: the matching ABI frames and sink buffers remain live through the call.
        let outcome = unsafe {
            call(
                host.ops.emit,
                host.instance,
                &mut input,
                &mut out,
                slot::EMIT,
            )
        };
        assert_eq!(
            host.capture(outcome, out).outcome,
            Outcome::Ready,
            "late emit is dropped"
        );
        FLOW.with(|flow| flow.set(FLOW_CONTINUE));
        REFUSAL_MODE.with(|value| value.set(0));
        let (open, original) = host.until_open(&request(3, "/second", &[], true), ticket(3));
        assert_eq!(open.open.unwrap().stream, 2);
        let admitted = host.ingest(&original, &policy(3, 33, "/second"), ticket(3));
        assert_eq!(admitted.outcome, Outcome::Ready);
        assert!(admitted
            .pieces
            .iter()
            .any(|(piece, _)| piece.stream == 2 && piece.flags & PIECE_FIELDS != 0));
    }
}

/// Expiry cancels a pending policy but must not turn its resume into a fresh ingest.
#[test]
fn an_expired_policy_resume_never_replays_its_original_input() {
    let mut host = Host::new();
    host.begin(SIDE_ACCEPT, &policy(1, 11, "/initial"));
    assert_eq!(
        host.ingest(&opening(), &[], ticket(10)).outcome,
        Outcome::Ready
    );
    for _ in 0..4 {
        assert_eq!(host.ingest(&[], &[], ticket(10)).outcome, Outcome::Ready);
    }
    let mut bytes = request(1, "/first", &message(b"private"), true);
    let length =
        (usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2]);
    let timeout = b"\x00\x0cgrpc-timeout\x021m";
    bytes.splice(9 + length..9 + length, timeout.iter().copied());
    let length = length + timeout.len();
    bytes[..3].copy_from_slice(&[(length >> 16) as u8, (length >> 8) as u8, length as u8]);
    let (opening, original) = host.until_open(&bytes, ticket(2));
    assert_eq!(opening.open.unwrap().stream, 1);
    assert!(
        !original.is_empty(),
        "resume retains the already consumed HTTP2 input"
    );
    host.now_ns += 1_000_000;
    let expired = host.ingest(&original, &policy(2, 22, "/first"), ticket(2));
    assert_eq!(expired.outcome, Outcome::Ready);
    assert!(expired
        .pieces
        .iter()
        .any(|(piece, _)| piece.stream == 1 && piece.flags & PIECE_STREAM_FAILED != 0));
    HANDED.with(|seen| assert!(seen.borrow().is_empty()));
    let next = request(3, "/second", &message(b"second"), true);
    let (opening, original) = host.until_open(&next, ticket(3));
    assert_eq!(opening.open.unwrap().stream, 2);
    let admitted = host.ingest(&original, &policy(3, 33, "/second"), ticket(3));
    assert_eq!(admitted.outcome, Outcome::Ready);
    HANDED.with(|seen| assert_eq!(seen.borrow().len(), 1));
}

/// A CONNECTION THAT BROKE ADMITS NOTHING MORE: with one request admitted and another parked for
/// its policy, the far end breaks the connection (a DATA frame on stream 0); the parked request is
/// failed with the connection's streams, never opens a policy and is never handed in, and the
/// framing fails once the host has taken what it owes (its GOAWAY).
#[test]
fn a_broken_connection_admits_none_of_its_parked_requests() {
    let mut host = Host::new();
    host.begin(SIDE_ACCEPT, &policy(1, 11, "/initial"));
    let mut bytes = opening();
    bytes.extend(request(1, "/first", &message(b"first"), true));
    bytes.extend(request(3, "/second", &message(b"second"), true));
    let (opening, original) = host.until_open(&bytes, ticket(2));
    assert_eq!(opening.open.unwrap().stream, 1);
    let admitted = host.ingest(&original, &policy(2, 22, "/first"), ticket(2));
    assert_eq!(admitted.outcome, Outcome::Ready);
    assert!(admitted.open.is_none(), "the second waits for a later op");
    let mut answer = host.ingest(&frame(0, 0, 0, &[0]), &[], ticket(3));
    let mut failed = false;
    for n in 4..20 {
        assert!(
            answer.open.is_none(),
            "no policy opens on a broken connection"
        );
        if answer.outcome == Outcome::Failed {
            failed = true;
            break;
        }
        answer = host.ingest(&[], &[], ticket(n));
    }
    assert!(failed, "the broken connection fails");
    HANDED.with(|seen| assert_eq!(seen.borrow().len(), 1, "only the first was handed in"));
}

/// A request whose head names its authority by a `host` field, not an `:authority` pseudo-field.
fn request_with_host(stream: u32, target: &str, host: &str) -> Vec<u8> {
    let mut head = vec![0x83, 0x86];
    for (name, value) in [
        (":path", target),
        ("host", host),
        ("content-type", "application/grpc"),
    ] {
        head.extend([0, name.len() as u8]);
        head.extend_from_slice(name.as_bytes());
        head.push(value.len() as u8);
        head.extend_from_slice(value.as_bytes());
    }
    let mut wire = frame(1, 4, stream, &head);
    wire.extend(frame(0, 1, stream, &[]));
    wire
}

#[test]
fn a_request_without_an_authority_is_handed_in_under_its_host_field() {
    let mut host = Host::new();
    host.begin(SIDE_ACCEPT, &policy(1, 11, "/initial"));
    let mut bytes = opening();
    bytes.extend(request_with_host(1, "/first", "hostfield.test"));
    let (_, original) = host.until_open(&bytes, ticket(2));
    let admitted = host.ingest(&original, &policy(2, 22, "/first"), ticket(2));
    assert_eq!(admitted.outcome, Outcome::Ready);
    HANDED.with(|seen| {
        let seen = seen.borrow();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].target, "/first");
        assert_eq!(seen[0].authority, "hostfield.test");
    });
}

/// A host answer the door cannot honour fails the framing in words, retires only that stream, and
/// leaves the connection admitting the next request.
#[test]
fn a_hand_in_the_door_cannot_honour_fails_in_words_and_leaves_the_connection_usable() {
    use busbar_contract::abi::auth::POINT_HEAD;
    for (points, no_unit, words) in [
        (
            POINT_HEAD,
            false,
            "gRPC offers no inbound authentication points",
        ),
        (0, true, "unit.hand_in: Broken"),
    ] {
        let mut host = Host::new();
        host.begin(SIDE_ACCEPT, &policy(1, 11, "/initial"));
        let mut bytes = opening();
        bytes.extend(request(1, "/first", &[], true));
        let (_, original) = host.until_open(&bytes, ticket(2));
        NO_UNIT.with(|none| none.set(no_unit));
        let failed = host.ingest(
            &original,
            &policy_with_points(2, 22, "/first", METHOD_POST, points),
            ticket(2),
        );
        assert_eq!(failed.outcome, Outcome::Failed, "{words}");
        assert!(failed.error.contains(words), "{}", failed.error);
        assert!(failed
            .pieces
            .iter()
            .all(|(piece, _)| piece.flags & PIECE_FIELDS == 0));
        NO_UNIT.with(|none| none.set(false));
        // The retired stream is failed to the host before the next request opens its policy.
        let second = request(3, "/second", &[], true);
        let mut pieces = failed.pieces;
        let mut answer = host.ingest(&second, &[], ticket(3));
        let mut opened = None;
        for _ in 0..100 {
            assert_eq!(answer.outcome, Outcome::Ready);
            pieces.extend(answer.pieces);
            if let Some(open) = answer.open {
                opened = Some(open);
                break;
            }
            answer = host.ingest(&[], &[], ticket(3));
        }
        assert_eq!(opened.expect("the next request opens").stream, 2, "{words}");
        assert!(
            pieces
                .iter()
                .any(|(piece, _)| piece.stream == 1 && piece.flags & PIECE_STREAM_FAILED != 0),
            "{words}: the retired stream is reported failed"
        );
        let original = second;
        let admitted = host.ingest(&original, &policy(3, 33, "/second"), ticket(3));
        assert_eq!(admitted.outcome, Outcome::Ready);
        assert!(admitted
            .pieces
            .iter()
            .any(|(piece, _)| piece.stream == 2 && piece.flags & PIECE_FIELDS != 0));
    }
}

#[test]
fn a_path_no_policy_line_names_is_refused_as_no_route_and_never_handed_in() {
    let mut host = Host::new();
    host.begin(SIDE_ACCEPT, &policy(1, 11, "/initial"));
    let mut bytes = opening();
    bytes.extend(request(1, "/first", &[], true));
    let (_, original) = host.until_open(&bytes, ticket(2));
    let refused = host.ingest(&original, &policy(2, 22, "/elsewhere"), ticket(2));
    assert_eq!(refused.outcome, Outcome::Ready);
    assert!(refused
        .wire
        .windows(b"denied-verbatim".len())
        .any(|bytes| bytes == b"denied-verbatim"));
    assert!(refused
        .pieces
        .iter()
        .all(|(piece, _)| piece.flags & PIECE_FIELDS == 0));
    HANDED.with(|seen| assert!(seen.borrow().is_empty()));
    REFUSED.with(|seen| {
        assert_eq!(
            seen.borrow().as_slice(),
            &[(REFUSE_NO_ROUTE, LINE_NONE, UnitRef::NONE)]
        )
    });
}
