// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Ordinary tests of this product's actual linked door and independently built cdylib.
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, InHead};
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, OpenIn, RefreshIn, TickIn, TickOut, ValidateIn,
};
use busbar_plugin_loader::dispatch::{in_head, load_dropped, load_linked, out_head};
use serde_json::Value;
use std::sync::atomic::Ordering;

fn input<T: InFrame>() -> T {
    // SAFETY: ABI frames contain only zero-valid plain C data and begin with InHead.
    let mut v: T = unsafe { std::mem::zeroed() };
    unsafe { std::ptr::addr_of_mut!(v).cast::<InHead>().write(in_head()) };
    v
}
fn output<T: OutFrame>() -> T {
    // SAFETY: ABI frames contain only zero-valid plain C data and begin with OutHead.
    let mut v: T = unsafe { std::mem::zeroed() };
    unsafe {
        std::ptr::addr_of_mut!(v)
            .cast::<OutHead>()
            .write(out_head())
    };
    v
}
fn abi_bytes(b: &(impl AsRef<[u8]> + ?Sized)) -> AbiStr {
    AbiStr {
        ptr: b.as_ref().as_ptr(),
        len: b.as_ref().len(),
    }
}
fn count(p: &Plugin<Transport>) -> u64 {
    p.inner.crossings.load(Ordering::SeqCst) - p.inner.resumes.load(Ordering::SeqCst)
}
use busbar_contract::abi::mechanism::call::{Field, OutHead, Outcome};
use busbar_contract::abi::transport::{
    slot, AcceptIn, AcceptOut, AdoptIn, ArrivalIn, ArrivalOut, BeginIn, ConnIn, ConnOut, DialIn,
    EmitIn, EncodeIn, FinishIn, FramePiece, FramerOut, FramerSink, FramingIn, IngestIn, IoOut,
    ListenIn, ListenOut, LocateIn, LocateOut, ReadIn, RefuseIn, ShutIn, WriteIn,
    PIECE_END_OF_FRAME, SIDE_ACCEPT, SIDE_DIAL, YIELD_ENDED, YIELD_HAS_DEADLINE, YIELD_MORE,
};

use busbar_plugin_loader::dispatch::kinds::transport::Transport;
use busbar_plugin_loader::dispatch::{Called, Frame, InFrame, OutFrame, Plugin};

const TIGHT_WIRE: usize = 4;

const TIGHT_FRAME: usize = 3;

const AMPLE: usize = 4096;

const MAX_REDRIVE: usize = 4096;

fn text(v: &serde_json::Value, what: &str) -> Vec<u8> {
    match v {
        serde_json::Value::String(s) => s.as_bytes().to_vec(),
        serde_json::Value::Null => panic!("conformance.json: transport.{what} is missing"),
        serde_json::Value::Object(o) if o.len() == 1 && o.contains_key("hex") => o["hex"]
            .as_str()
            .and_then(unhex)
            .unwrap_or_else(|| panic!("conformance.json: transport.{what}.hex is not hex")),
        other => other.to_string().into_bytes(),
    }
}

fn unhex(hex: &str) -> Option<Vec<u8>> {
    let digits = hex.as_bytes();
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    digits
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

fn opt_text(v: &serde_json::Value, what: &str) -> Vec<u8> {
    if v.is_null() {
        Vec::new()
    } else {
        text(v, what)
    }
}

fn texts(v: &serde_json::Value, what: &str) -> Vec<Vec<u8>> {
    v.as_array()
        .unwrap_or_else(|| panic!("conformance.json: transport.{what} must be an array"))
        .iter()
        .map(|x| text(x, what))
        .collect()
}

fn lossy(b: &[u8]) -> String {
    match std::str::from_utf8(b) {
        Ok(text) if !text.starts_with('\u{e000}') => text.to_owned(),
        _ => format!(
            "\u{e000}{}",
            b.iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ),
    }
}

fn sinkfuls(len: usize, cap: usize) -> u64 {
    len.div_ceil(cap).max(1) as u64
}

fn frame_sinkfuls(frames: &[Vec<u8>]) -> u64 {
    frames
        .iter()
        .map(|f| f.len().div_ceil(TIGHT_FRAME).max(1) as u64)
        .sum::<u64>()
        .max(1)
}

struct Sink {
    wire: Vec<u8>,
    frame: Vec<u8>,
    pieces: Vec<FramePiece>,
    /// The host's framing context the ops cross in, as the connector's own scoped crossing
    /// provides it: (the framing token it was made for, the context).
    scope: Option<(
        u64,
        std::sync::Arc<busbar_plugin_loader::dispatch::framing_context::FramingContext>,
    )>,
}

impl Sink {
    fn new(wire: usize, frame: usize, pieces: usize) -> Self {
        let piece = FramePiece {
            stream: 0,
            offset: 0,
            len: 0,
            code: 0,
            status_class: 0,
            fault: 0,
            flags: 0,
            retry_after_secs: 0,
            declared_len: 0,
        };
        Self {
            wire: vec![0; wire],
            frame: vec![0; frame],
            pieces: vec![piece; pieces],
            scope: None,
        }
    }

    fn tight() -> Self {
        Self::new(TIGHT_WIRE, TIGHT_FRAME, 1)
    }

    fn ample() -> Self {
        Self::new(AMPLE, AMPLE, 16)
    }

    fn raw(&mut self) -> FramerSink {
        FramerSink {
            wire: self.wire.as_mut_ptr(),
            wire_cap: self.wire.len(),
            frame: self.frame.as_mut_ptr(),
            frame_cap: self.frame.len(),
            pieces: self.pieces.as_mut_ptr(),
            pieces_cap: self.pieces.len(),
            now_monotonic_ns: 1,
            now_unix_ns: 1,
            heads: std::ptr::null_mut(),
            heads_cap: 0,
        }
    }
}

/// What a (re-driven) framer op answered, gathered across its calls.
#[derive(Default)]
struct Yielded {
    /// The last call's outcome and error text.
    last: String,
    outcome: Option<Outcome>,
    wire: Vec<u8>,
    /// Whole frames (their last piece carried `PIECE_END_OF_FRAME`), and the piece flags seen.
    frames: Vec<Vec<u8>>,
    /// A frame begun and not ended.
    partial: Vec<u8>,
    /// Frame bytes answered with no piece (what `detach` hands back).
    raw: Vec<u8>,
    flags: u32,
    framing: u64,
}

impl Yielded {
    fn take(&mut self, c: &Called, o: &FramerOut, sink: &Sink) {
        let text = c.error.as_deref().map(lossy).unwrap_or_default();
        self.last = format!("{:?} lease={} err={text:?}", c.outcome, c.lease != 0);
        self.outcome = Some(c.outcome);
        self.flags = o.yielded.flags;
        if o.framing != 0 {
            self.framing = o.framing;
        }
        if c.outcome != Outcome::Ready {
            return;
        }

        let wire_len = o.yielded.wire_len as usize;
        assert!(wire_len <= sink.wire.len(), "door over-reported wire bytes");
        self.wire.extend_from_slice(&sink.wire[..wire_len]);
        let frame_len = o.yielded.frame_len as usize;
        assert!(
            frame_len <= sink.frame.len(),
            "door over-reported frame bytes"
        );
        let pieces = o.yielded.pieces_len as usize;
        assert!(pieces <= sink.pieces.len(), "door over-reported pieces");
        if pieces == 0 {
            self.raw.extend_from_slice(&sink.frame[..frame_len]);
        }
        for p in &sink.pieces[..pieces] {
            let at = p.offset as usize;
            let bytes = sink.frame[..frame_len]
                .get(
                    at..at
                        .checked_add(p.len as usize)
                        .expect("piece length overflow"),
                )
                .unwrap_or_else(|| panic!("a piece past the frame bytes: {p:?}"));
            self.partial.extend_from_slice(bytes);
            if p.flags & PIECE_END_OF_FRAME != 0 {
                self.frames.push(std::mem::take(&mut self.partial));
            }
        }
    }

    fn ready(&self) -> bool {
        self.outcome == Some(Outcome::Ready)
    }

    fn line(&self) -> String {
        let frames: Vec<String> = self.frames.iter().map(|f| lossy(f)).collect();
        format!(
            "{} wire={:?} frames={frames:?} partial={:?} raw={:?} flags={} framing={}",
            self.last,
            lossy(&self.wire),
            lossy(&self.partial),
            lossy(&self.raw),
            self.flags,
            self.framing != 0
        )
    }
}

/// One framer op, by what it carries.
#[derive(Clone, Copy)]
enum Op<'a> {
    Begin(u32, &'a [u8]),
    Ingest(&'a [u8], bool),
    Emit(&'a [u8], bool),
    Refuse(&'a [u8]),
    Encode(&'a [u8], &'a [Field]),
    Adopt(&'a [u8]),
    Finish,
    Detach,
    Timer,
}

impl Op<'_> {
    fn again(self) -> Self {
        match self {
            Op::Ingest(_, end) => Op::Ingest(&[], end),

            Op::Emit(..) => Op::Emit(&[], false),
            Op::Refuse(_) => Op::Refuse(&[]),
            Op::Begin(..) => Op::Timer,
            other => other,
        }
    }
}

fn go<I: InFrame, O: OutFrame>(p: &Plugin<Transport>, s: u32, i: I) -> (Called, O) {
    let mut f = Frame::new(i, output::<O>());
    let c = p.call(s, &mut f);
    (c, f.out)
}

fn cross(p: &Plugin<Transport>, framing: u64, op: Op<'_>, sink: &mut Sink) -> (Called, FramerOut) {
    if framing == 0
        || sink
            .scope
            .as_ref()
            .is_none_or(|(token, _)| *token != framing)
    {
        sink.scope = Some((
            framing,
            busbar_plugin_loader::dispatch::framing_context::FramingContext::new(
                p.instance().0,
                0,
                framing,
                None,
            )
            .expect("actual product framing context"),
        ));
    }
    let scope = sink.scope.as_ref().map(|(_, scope)| {
        scope.clone() as std::sync::Arc<dyn busbar_contract::framing_scope::FramingScope>
    });
    let raw = sink.raw();
    busbar_plugin_loader::dispatch::framing_context::with_context(scope, || match op {
        Op::Begin(side, target) => {
            let mut i: BeginIn = input();
            (i.side, i.sink, i.target) = (side, raw, abi_bytes(target));

            i.scheme = busbar_contract::abi::host::service::SCHEME_PLAIN;
            go(p, slot::BEGIN, i)
        }
        Op::Ingest(bytes, end) => {
            let mut i: IngestIn = input();
            (i.framing, i.bytes, i.len, i.end, i.sink) =
                (framing, bytes.as_ptr(), bytes.len(), u32::from(end), raw);
            go(p, slot::INGEST, i)
        }
        Op::Emit(bytes, end) => {
            let mut i: EmitIn = input();
            (i.framing, i.bytes, i.len, i.end_of_frame, i.sink) =
                (framing, bytes.as_ptr(), bytes.len(), u32::from(end), raw);
            go(p, slot::EMIT, i)
        }
        Op::Refuse(bytes) => {
            let mut i: RefuseIn = input();
            (i.framing, i.bytes, i.len, i.sink) = (framing, bytes.as_ptr(), bytes.len(), raw);
            go(p, slot::REFUSE, i)
        }
        Op::Encode(body, fields) => {
            let mut i: EncodeIn = input();
            (i.body, i.body_len, i.sink) = (body.as_ptr(), body.len(), raw);
            (i.fields, i.fields_len) = (fields.as_ptr(), fields.len());
            go(p, slot::ENCODE, i)
        }
        Op::Adopt(leftover) => {
            let mut i: AdoptIn = input();
            (i.side, i.leftover, i.leftover_len, i.sink) =
                (SIDE_ACCEPT, leftover.as_ptr(), leftover.len(), raw);
            go(p, slot::ADOPT, i)
        }
        Op::Finish => {
            let mut i: FinishIn = input();
            (i.framing, i.sink) = (framing, raw);
            go(p, slot::FINISH, i)
        }
        Op::Detach | Op::Timer => {
            let mut i: FramingIn = input();
            (i.framing, i.sink) = (framing, raw);
            let s = if matches!(op, Op::Detach) {
                slot::DETACH
            } else {
                slot::TIMER
            };
            go(p, s, i)
        }
    })
}

fn once(p: &Plugin<Transport>, framing: u64, op: Op<'_>, sink: &mut Sink) -> Yielded {
    let mut y = Yielded::default();
    let (c, o) = cross(p, framing, op, sink);
    y.take(&c, &o, sink);
    y
}

fn pump(p: &Plugin<Transport>, framing: u64, op: Op<'_>, sink: &mut Sink) -> Yielded {
    let mut y = Yielded::default();
    let (c, o) = cross(p, framing, op, sink);
    y.take(&c, &o, sink);
    let framing = if framing == 0 { y.framing } else { framing };
    let mut n = 0;
    while y.ready() && y.flags & YIELD_MORE != 0 {
        n += 1;
        assert!(n < MAX_REDRIVE, "a framer answered YIELD_MORE {n} times");
        let (c, o) = cross(p, framing, op.again(), sink);
        y.take(&c, &o, sink);
    }
    y
}

fn carrier_ops(p: &Plugin<Transport>) -> [Outcome; 8] {
    [
        go::<_, ListenOut>(p, slot::LISTEN, input::<ListenIn>())
            .0
            .outcome,
        go::<_, AcceptOut>(p, slot::ACCEPT, input::<AcceptIn>())
            .0
            .outcome,
        go::<_, ConnOut>(p, slot::DIAL, input::<DialIn>()).0.outcome,
        go::<_, IoOut>(p, slot::READ, input::<ReadIn>()).0.outcome,
        go::<_, IoOut>(p, slot::WRITE, input::<WriteIn>()).0.outcome,
        go::<_, OutHead>(p, slot::FLUSH, input::<ConnIn>())
            .0
            .outcome,
        go::<_, OutHead>(p, slot::SHUT, input::<ShutIn>()).0.outcome,
        go::<_, ArrivalOut>(p, slot::ARRIVAL, input::<ArrivalIn>())
            .0
            .outcome,
    ]
}

fn locate(
    p: &Plugin<Transport>,
    target: &[u8],
    cap: usize,
) -> (
    String,
    Option<(busbar_plugin_loader::dispatch::Recall, u64)>,
) {
    locate_on(p, target, cap, None)
}

fn locate_on(
    p: &Plugin<Transport>,
    target: &[u8],
    cap: usize,
    recall: Option<busbar_plugin_loader::dispatch::Recall>,
) -> (
    String,
    Option<(busbar_plugin_loader::dispatch::Recall, u64)>,
) {
    let (mut authority, mut name, mut alpn) =
        (vec![0_u8; cap], vec![0_u8; AMPLE], vec![0_u8; AMPLE]);
    let mut i: LocateIn = input();
    i.target = abi_bytes(target);
    (i.authority_buf, i.authority_cap) = (authority.as_mut_ptr(), authority.len());
    (i.name_buf, i.name_cap) = (name.as_mut_ptr(), name.len());
    (i.alpn_buf, i.alpn_cap) = (alpn.as_mut_ptr(), alpn.len());

    let mut defaults = vec![0_u8; AMPLE];
    (i.defaults_buf, i.defaults_cap) = (defaults.as_mut_ptr(), defaults.len());
    let mut f: Frame<LocateIn, LocateOut> = Frame::new(i, output());
    let c = match recall {
        Some(token) => p.recall(token, slot::LOCATE, &mut f),
        None => p.call(slot::LOCATE, &mut f),
    };
    let (o, text) = (&f.out, c.error.as_deref().map(lossy));
    let written = (o.authority_written as usize).min(authority.len());
    let authority = if c.outcome == Outcome::Ready {
        lossy(&authority[..written])
    } else {
        String::new()
    };
    let line = format!(
        "{:?} err={:?} authority={authority:?} secure={} has_name={} short={}",
        c.outcome,
        text.unwrap_or_default(),
        o.secure != 0,
        o.has_name != 0,
        c.recall.is_some()
    );
    let needed = o.authority_needed;
    (line, c.recall.map(|r| (r, needed)))
}

fn ready_locate(authority: &[u8], secure: bool, has_name: bool) -> String {
    format!(
        "Ready err=\"\" authority={:?} secure={secure} has_name={has_name} short=false",
        lossy(authority)
    )
}
/// A connection framing's READY answer: every one leases its retained-input report
/// (`framer.retained_input`); `encode`, which drives no framing, leases nothing.
fn yielded_line(wire: &[u8], frames: &[Vec<u8>], raw: &[u8], flags: u32, framing: bool) -> String {
    answer_line(true, wire, frames, raw, flags, framing)
}

fn answer_line(
    lease: bool,
    wire: &[u8],
    frames: &[Vec<u8>],
    raw: &[u8],
    flags: u32,
    framing: bool,
) -> String {
    let frames: Vec<String> = frames.iter().map(|f| lossy(f)).collect();
    format!(
        "Ready lease={lease} err=\"\" wire={:?} frames={frames:?} partial=\"\" raw={:?} flags={flags} framing={framing}",
        lossy(wire),
        lossy(raw)
    )
}

fn exercise(p: &Plugin<Transport>, d: &busbar_plugin_loader::dispatch::Dispatcher) -> Vec<String> {
    let mut transcript = Vec::new();
    let inputs: Value = serde_json::from_str(include_str!("../conformance.json")).unwrap();
    let k = &inputs["transport"];
    let facts = p
        .context::<busbar_plugin_loader::dispatch::kinds::transport::TransportFacts>()
        .expect("transport tail");
    assert_eq!(facts.role, busbar_contract::abi::transport::ROLE_FRAMER);
    assert!(!facts.datagram);
    transcript.push(format!("facts {facts:?}"));
    let begin = || once(p, 0, Op::Begin(SIDE_DIAL, b""), &mut Sink::ample()).line();
    let before = count(p);
    let answer = begin();
    assert!(answer.starts_with("Refused "));
    transcript.push(format!("begin unopened: {answer}"));
    assert_eq!(count(p) - before, 0);
    let before = count(p);
    let mut i: ValidateIn = input();
    i.settings = Blob::json(b"{}");
    let (c, _): (_, OutHead) = go(p, life::VALIDATE, i);
    assert_eq!(c.outcome, Outcome::Ready);
    transcript.push(format!(
        "lifecycle Ready lease={} err={:?}",
        c.lease != 0,
        c.error
    ));
    assert_eq!(count(p) - before, 1);
    let before = count(p);
    let mut i: OpenIn = input();
    i.settings = Blob::json(b"{}");
    i.generation = 1;
    let (c, _): (_, busbar_contract::abi::mechanism::lifecycle::OpenOut) = go(p, life::OPEN, i);
    assert_eq!(c.outcome, Outcome::Ready);
    transcript.push(format!(
        "lifecycle Ready lease={} err={:?}",
        c.lease != 0,
        c.error
    ));
    assert_eq!(count(p) - before, 1);
    let before = count(p);
    let answer = p.ready(d, std::time::Duration::from_secs(30));
    assert!(answer.is_ok());
    transcript.push(format!("ready has_ready={} {answer:?}", p.has_ready()));
    assert_eq!(count(p) - before, u64::from(p.has_ready()));
    let before = count(p);
    assert_eq!(carrier_ops(p), [Outcome::Refused; 8]);
    assert_eq!(count(p) - before, 8);
    {
        let l = &k["locate"];
        let reads = l["reads"]
            .as_array()
            .expect("conformance.json: transport.locate.reads must be an array");
        assert!(!reads.is_empty(), "transport.locate.reads is empty");
        for (n, read) in reads.iter().enumerate() {
            let target = text(&read["target"], "locate.reads.target");
            let authority = text(&read["authority"], "locate.reads.authority");
            let secure = read["secure"].as_bool().unwrap_or(false);
            let has_name = read["has_name"].as_bool().unwrap_or(false);
            let want = ready_locate(&authority, secure, has_name);
            {
                let label = &format!("locate #{n}");

                let before = count(p);
                let value = locate(p, &target, AMPLE).0;
                assert_eq!(count(p) - before, 1, "{label} crossings");
                let answer = value;
                assert_eq!(answer, want, "{label}");
                transcript.push(format!("{label}: {answer}"));
            };
        }
        let target = text(&reads[0]["target"], "locate.reads.target");
        let authority = text(&reads[0]["authority"], "locate.reads.authority");
        let secure = reads[0]["secure"].as_bool().unwrap_or(false);
        let has_name = reads[0]["has_name"].as_bool().unwrap_or(false);
        assert!(
            authority.len() > 1,
            "transport.locate.reads[0].authority must be longer than one byte"
        );
        let want = format!(
            "needed={} then {}",
            authority.len(),
            ready_locate(&authority, secure, has_name)
        );

        {
            let label = "locate short";

            let before = count(p);
            let value = (|| {
                let (first, token) = locate(p, &target, 1);
                let Some((token, needed)) = token else {
                    return format!("{first} (no re-call)");
                };
                let again = locate_on(p, &target, needed as usize, Some(token)).0;
                format!("needed={needed} then {again}")
            })();
            assert_eq!(count(p) - before, 2, "{label} crossings");
            let answer = value;
            assert_eq!(answer, want, "{label}");
            transcript.push(format!("{label}: {answer}"));
        };
        for (n, t) in texts(&l["refuses"], "locate.refuses").iter().enumerate() {
            {
                let label = &format!("locate refused #{n}");
                let before = count(p);
                let value = locate(p, t, AMPLE).0;
                assert_eq!(count(p) - before, 1, "{label} crossings");
                let answer = value;
                assert!(answer.starts_with("Failed "), "{label}: {answer}");
                transcript.push(format!("{label}: {answer}"));
            };
        }
    }

    let dial = &k["dial"];
    let wire = text(&dial["wire"], "dial.wire");
    let (ingest, frames) = (
        text(&dial["ingest"], "dial.ingest"),
        texts(&dial["frames"], "dial.frames"),
    );
    let target = opt_text(&dial["target"], "dial.target");
    let opening = opt_text(&dial["opening"], "dial.opening");
    let mut tight = Sink::tight();

    let armed = |step: &str| -> u32 {
        let on = match &dial["deadline"] {
            Value::Array(a) => a.iter().any(|v| v.as_str() == Some(step)),
            _ => false,
        };
        if on {
            YIELD_HAS_DEADLINE
        } else {
            0
        }
    };

    let want = begin_dial_want(dial, armed("begin"));
    let pinned = sinkfuls(opening.len(), TIGHT_WIRE);
    let token = {
        let label = "begin dial";

        let before = count(p);
        let value = {
            let y = pump(p, 0, Op::Begin(SIDE_DIAL, &target), &mut tight);
            (y.line(), y.framing)
        };
        assert_eq!(count(p) - before, pinned, "{label} crossings");
        let (answer, result) = value;
        assert_eq!(answer, want, "{label}");
        transcript.push(format!("{label}: {answer}"));
        result
    };

    let emit = text(&dial["emit"], "dial.emit");
    let want = yielded_line(&wire, &[], &[], armed("emit"), false);
    {
        let label = "emit";

        let before = count(p);
        let value = pump(p, token, Op::Emit(&emit, true), &mut tight).line();
        assert_eq!(
            count(p) - before,
            sinkfuls(wire.len(), TIGHT_WIRE),
            "{label} crossings"
        );
        let answer = value;
        assert_eq!(answer, want, "{label}");
        transcript.push(format!("{label}: {answer}"));
    };

    let answered = opt_text(&dial["ingest_wire"], "dial.ingest_wire");
    let ingest_calls = sinkfuls(answered.len(), TIGHT_WIRE).max(frame_sinkfuls(&frames));

    let ends = !dial["ingest_wire"].is_null() && dial["ingest_ends"].as_bool().unwrap_or(true);
    let ingest_flags = armed("ingest") | if ends { YIELD_ENDED } else { 0 };
    let want = yielded_line(&answered, &frames, &[], ingest_flags, false);
    {
        let label = "ingest";

        let before = count(p);
        let value = pump(p, token, Op::Ingest(&ingest, false), &mut tight).line();
        assert_eq!(count(p) - before, ingest_calls, "{label} crossings");
        let answer = value;
        assert_eq!(answer, want, "{label}");
        transcript.push(format!("{label}: {answer}"));
    };
    let want = yielded_line(&[], &[], &[], YIELD_ENDED, false);
    {
        let label = "ingest end";

        let before = count(p);
        let value = pump(p, token, Op::Ingest(&[], true), &mut tight).line();
        assert_eq!(count(p) - before, 1, "{label} crossings");
        let answer = value;
        assert_eq!(answer, want, "{label}");
        transcript.push(format!("{label}: {answer}"));
    };
    let want = answer_line(false, &[], &[], &[], YIELD_ENDED, false);
    {
        let label = "finish";

        let before = count(p);
        let value = pump(p, token, Op::Finish, &mut tight).line();
        assert_eq!(
            count(p) - before,
            sinkfuls(0, TIGHT_WIRE),
            "{label} crossings"
        );
        let answer = value;
        assert_eq!(answer, want, "{label}");
        transcript.push(format!("{label}: {answer}"));
    };
    {
        let label = "finish again";
        let before = count(p);
        let value = once(p, token, Op::Finish, &mut tight).line();
        assert_eq!(count(p) - before, 1, "{label} crossings");
        let answer = value;
        assert!(answer.starts_with("Failed "), "{label}: {answer}");
        transcript.push(format!("{label}: {answer}"));
    };

    let cases = k["encode"]
        .as_array()
        .expect("conformance.json: transport.encode must be an array");
    for (n, case) in cases.iter().enumerate() {
        let body = text(&case["body"], "encode.body");
        let named: Vec<(Vec<u8>, Vec<u8>)> = case["fields"]
            .as_array()
            .map(|fs| {
                fs.iter()
                    .map(|f| {
                        (
                            text(&f[0], "encode.fields name"),
                            text(&f[1], "encode.fields value"),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        let fields: Vec<Field> = named
            .iter()
            .map(|(n, v)| Field {
                name: abi_bytes(n),
                value: abi_bytes(v),
            })
            .collect();
        let want = answer_line(
            false,
            &text(&case["wire"], "encode.wire"),
            &[],
            &[],
            0,
            false,
        );
        {
            let label = &format!("encode #{n}");

            let before = count(p);
            let value = once(p, 0, Op::Encode(&body, &fields), &mut Sink::ample()).line();
            assert_eq!(count(p) - before, 1, "{label} crossings");
            let answer = value;
            assert_eq!(answer, want, "{label}");
            transcript.push(format!("{label}: {answer}"));
        };
    }

    {
        let refuse = &k["refuse"];
        assert_eq!(refuse["refused"], true, "this door refuses a refusal");
        let bytes = text(&refuse["bytes"], "refuse.bytes");

        let accept_opening = opt_text(&refuse["begin"], "refuse.begin");
        let want = yielded_line(&accept_opening, &[], &[], 0, true);
        let pinned = sinkfuls(accept_opening.len(), TIGHT_WIRE);
        let token = {
            let label = "begin accept";

            let before = count(p);
            let value = {
                let y = pump(p, 0, Op::Begin(SIDE_ACCEPT, b""), &mut tight);
                (y.line(), y.framing)
            };
            assert_eq!(count(p) - before, pinned, "{label} crossings");
            let (answer, result) = value;
            assert_eq!(answer, want, "{label}");
            transcript.push(format!("{label}: {answer}"));
            result
        };

        {
            let label = "refuse";

            let before = count(p);
            let value = pump(p, token, Op::Refuse(&bytes), &mut tight).line();
            assert_eq!(count(p) - before, 1, "{label} crossings");
            let answer = value;
            assert!(answer.starts_with("Refused "), "{label}: {answer}");
            transcript.push(format!("{label}: {answer}"));
        };
        let want = yielded_line(&[], &[], &[], 0, false);
        {
            let label = "timer";

            let before = count(p);
            let value = pump(p, token, Op::Timer, &mut tight).line();
            assert_eq!(count(p) - before, 1, "{label} crossings");
            let answer = value;
            assert_eq!(answer, want, "{label}");
            transcript.push(format!("{label}: {answer}"));
        };
        {
            let label = "finish refused";
            let before = count(p);
            let value = once(p, token, Op::Finish, &mut tight).line();
            assert_eq!(count(p) - before, 1, "{label} crossings");
            let answer = value;
            assert!(answer.starts_with("Ready "), "{label}: {answer}");
            transcript.push(format!("{label}: {answer}"));
        };

        let token = {
            let label = "begin upgrade";
            let before = count(p);
            let value = {
                let y = once(p, 0, Op::Begin(SIDE_ACCEPT, b""), &mut tight);
                (y.line(), y.framing)
            };
            assert_eq!(count(p) - before, 1, "{label} crossings");
            let (answer, result) = value;
            assert!(answer.starts_with("Ready "), "{label}: {answer}");
            transcript.push(format!("{label}: {answer}"));
            result
        };
        upgrade(&mut transcript, p, k, token);
    }
    {
        let label = "ingest on no framing";
        let before = count(p);
        let value = once(p, u64::MAX, Op::Ingest(b"x", false), &mut tight).line();
        assert_eq!(count(p) - before, 1, "{label} crossings");
        let answer = value;
        assert!(answer.starts_with("Failed "), "{label}: {answer}");
        transcript.push(format!("{label}: {answer}"));
    };

    let before = count(p);
    let mut i: TickIn = input();
    i.now_ns = 1;
    let (c, o): (_, TickOut) = go(p, life::TICK, i);
    assert_eq!(c.outcome, Outcome::Ready, "tick crossing");
    assert_eq!(o.next_tick_ns, 0, "the door wants no further tick");
    transcript.push(format!(
        "tick {:?} lease={} err={:?} next={}",
        c.outcome,
        c.lease != 0,
        c.error,
        o.next_tick_ns
    ));
    assert_eq!(count(p) - before, 1);
    let before = count(p);
    let mut i: RefreshIn = input();
    i.settings = Blob::json(b"{}");
    i.generation = 2;
    let (c, _): (_, OutHead) = go(p, life::REFRESH, i);
    assert_eq!(c.outcome, Outcome::Ready);
    transcript.push(format!(
        "lifecycle Ready lease={} err={:?}",
        c.lease != 0,
        c.error
    ));
    assert_eq!(count(p) - before, 1);
    let before = count(p);
    let (c, _): (_, OutHead) = go(p, life::CLOSE, input::<InHead>());
    assert_eq!(c.outcome, Outcome::Ready);
    transcript.push(format!(
        "lifecycle Ready lease={} err={:?}",
        c.lease != 0,
        c.error
    ));
    assert_eq!(count(p) - before, 1);
    let before = count(p);
    let answer = begin();
    assert!(answer.starts_with("Fault "));
    transcript.push(format!("begin after close: {answer}"));
    assert_eq!(count(p) - before, 0);
    transcript
}

#[test]
fn the_linked_and_the_dropped_in_door_are_one_plugin() {
    let d = busbar_plugin_loader::dispatch::Dispatcher::new(Default::default());
    let path = super::cdylib();
    let (dropped_address, dropped_ops) =
        busbar_plugin_loader::dispatch::load::door_addresses_of_library(&path)
            .expect("actual library reads")
            .expect("actual door export");
    assert_eq!(
        busbar_plugin_loader::dispatch::load::rendering_of_library(&path)
            .expect("actual Statement reads")
            .expect("actual door export"),
        super::row().statement,
        "actual images state the same Statement"
    );
    let linked_address = (super::row().door)();
    assert!(!linked_address.is_null());
    // SAFETY: the validated actual product door is immutable and static.
    let linked_ops =
        unsafe { busbar_contract::abi::mechanism::door::Door::read_parts(linked_address) }.ops
            as usize;
    assert_ne!(
        dropped_address, linked_address as usize,
        "independent loaded image"
    );
    assert_ne!(dropped_ops, linked_ops, "independent operation table");
    let linked: Plugin<Transport> =
        load_linked(&super::row(), super::bind(&d)).expect("linked product");
    let dropped: Plugin<Transport> =
        load_dropped(&super::cdylib(), &super::row().statement, super::bind(&d))
            .expect("real dropped product");
    assert_eq!(linked.name(), dropped.name());
    let linked_transcript = exercise(&linked, &d);
    let dropped_transcript = exercise(&dropped, &d);
    assert_eq!(linked_transcript, dropped_transcript);
}
fn upgrade(transcript: &mut Vec<String>, p: &Plugin<Transport>, k: &Value, token: u64) {
    let mut tight = Sink::tight();
    assert!(
        refused(&k["detach"]) && refused(&k["adopt"]),
        "a framer hands nothing off"
    );
    {
        let label = "detach";
        let before = count(p);
        let value = once(p, token, Op::Detach, &mut tight).line();
        assert_eq!(count(p) - before, 1, "{label} crossings");
        let answer = value;
        assert!(answer.starts_with("Refused "), "{label}: {answer}");
        transcript.push(format!("{label}: {answer}"));
    };
    {
        let label = "finish upgrade";
        let before = count(p);
        let value = once(p, token, Op::Finish, &mut tight).line();
        assert_eq!(count(p) - before, 1, "{label} crossings");
        let answer = value;
        assert!(answer.starts_with("Ready "), "{label}: {answer}");
        transcript.push(format!("{label}: {answer}"));
    };
    {
        let label = "adopt";
        let before = count(p);
        let value = once(p, 0, Op::Adopt(b"conformance"), &mut Sink::tight()).line();
        assert_eq!(count(p) - before, 1, "{label} crossings");
        let answer = value;
        assert!(answer.starts_with("Refused "), "{label}: {answer}");
        transcript.push(format!("{label}: {answer}"));
    };
}

fn refused(v: &Value) -> bool {
    v.as_str() == Some("refused")
}
fn begin_dial_want(dial: &Value, flags: u32) -> String {
    yielded_line(
        &opt_text(&dial["opening"], "dial.opening"),
        &[],
        &[],
        flags,
        true,
    )
}
