// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `grpc` DOOR: this transport as a FRAMER on the transport kind's table
//! (`busbar_contract::abi::transport`), compiled in or dropped in through the one door.
//!
//! A framer frames; it does not dial. The connector owns the socket and connection security; this
//! framer tells it, at `locate`, where a target is, whether it asks for security (`https`) and what
//! to offer in the handshake (`h2`, alone: gRPC is HTTP/2 only). A cleartext target is HTTP/2 by
//! prior knowledge. From there each op is one step of [`transport::Conn`], on either side:
//!
//! * `begin` opens a dialled connection (the HTTP/2 preface and settings are owed first) or an
//!   accepted one;
//! * `encode` renders an envelope (the target head word naming the method — or, where the host
//!   states none, a `path` field — the call's metadata as fields, one message as the body) as a head
//!   block and that message in its length-prefixed form; `emit` takes that on a stream — on a
//!   dialled connection it is a call, on an accepted one the answer to one;
//! * `refuse` on an accepted stream ends the call with its trailer block (`grpc-status`, ...);
//! * `ingest` takes what the far end sent, `timer` is the host's clock reaching a deadline this
//!   framer asked for, and `finish` drops the connection.
//!
//! One stream (`SIDE_ACCEPT_STREAM`): a framing begun on that side frames one call
//! whose connection and head the host's own framer carries, and its `finish` closes the call with
//! the final status the unit stated (the close's final tail), rendered here alone
//! (`crate::stream`).
//!
//! What a stream carries each way, and how `grpc-status` reaches the host (the terminal piece's
//! code, in the `grpc` numbering this door's status rows class), is the framer's module note (`transport.rs`).
//!
//! No op pends. Every slot is a `SafeSlot` on the SDK's safe surface: this crate holds no `unsafe`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::hyper_io::{fill, mark_stream_full, Owed};
use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
use busbar_contract::abi::mechanism::door::Statement;
use busbar_contract::abi::sdk::door::statement;
use busbar_contract::abi::sdk::life::{self, Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{self as sdk, Lent, Out, Safe, SafeSlot};
use busbar_contract::abi::transport::{
    AcceptIn, AcceptOut, AdoptIn, ArrivalIn, ArrivalOut, BeginIn, ConnIn, ConnOut, DialIn, EmitIn,
    EncodeIn, FinishIn, FramerOut, FramerSink, FramingIn, IngestIn, IoOut, ListenIn, ListenOut,
    LocateIn, LocateOut, Ops, ReadIn, RefuseIn, ShutIn, WriteIn, CANCEL_NOTHING_MOVED, SIDE_ACCEPT,
    SIDE_ACCEPT_STREAM, SIDE_DIAL, YIELD_ENDED,
};
use busbar_contract::transport::registry::{
    DEFAULT_REQUEST_BODY_MAX_BYTES, DEFAULT_REQUEST_TIMEOUT_SECS,
};

use crate::msg;
use crate::stream::StreamCall;
use crate::transport::{self, Conn, Posture};

use crate::claims::CLAIM_NAMES;
use crate::meta::{class_of, fault_of, TAIL};
pub use crate::meta::{setting, KEY};

busbar_contract::statement_extensions!(
    /// The Statement's extensions: this plugin's whole `declares` document.
    EXTENSIONS: [(
        busbar_contract::abi::mechanism::extensions::EXT_DECLARES,
        include_bytes!("../declares.json")
    )]
);

/// The door's Statement: the `grpc` framer.
pub const STATEMENT: Statement = {
    let mut s = statement(KEY, env!("CARGO_PKG_VERSION"), 64)
        .with_kind_tail(&TAIL)
        .with_claims(CLAIM_NAMES);
    s.extensions = EXTENSIONS;
    s
};

/// The protocol offer on a secured connection, in the handshake's ProtocolNameList encoding.
const OFFER_H2: &[u8] = b"\x02h2";

/// What `open` read from the settings, and the framings it holds.
pub struct Instance {
    posture: Posture,
    framings: Mutex<HashMap<u64, Arc<Mutex<Conn>>>>,
    /// The one-stream framings (`SIDE_ACCEPT_STREAM`), by the same token space.
    calls: Mutex<HashMap<u64, Arc<Mutex<StreamCall>>>>,
    next: AtomicU64,
}

/// The settings blob's bytes, parsed; `Err` names the first one that is not what its declaration
/// says. An absent blob reads as `{}`.
fn read_settings(bytes: &[u8]) -> Result<Posture, &'static str> {
    let text: &[u8] = if bytes.is_empty() { b"{}" } else { bytes };
    let v: serde_json::Value = serde_json::from_slice(text).map_err(|_| "settings: not JSON")?;
    let count = |k: &'static str, d: u64| match v.get(k) {
        None => Ok(d),
        Some(x) => x
            .as_u64()
            .ok_or("settings: a value is not of its declared kind"),
    };
    let secs = count(setting::REQUEST_TIMEOUT_SECS, DEFAULT_REQUEST_TIMEOUT_SECS)?;
    let max = count(
        setting::BODY_MAX_BYTES,
        DEFAULT_REQUEST_BODY_MAX_BYTES as u64,
    )?;
    Ok(Posture {
        keep_alive_interval: Some(Duration::from_secs(30)),
        keep_alive_timeout: Duration::from_secs(10),
        adaptive_window: true,
        timeout: Duration::from_secs(secs),
        max_message_bytes: usize::try_from(max).unwrap_or(usize::MAX),
    })
}

/// What every slot reads: the SDK's lifecycle state over [`Instance`].
type State = Held<Instance>;

/// This framer's instance, where the op has one open.
fn mine<'a>(p: &sdk::Instance<'a, State>) -> Option<&'a Instance> {
    p.get().map(Held::life)
}

/// One slot body on the SDK's safe surface, over this framer's [`Instance`].
macro_rules! slot {
    ($(#[$doc:meta])* $name:ident, $in:ty, $out:ty,
     |$inst:pat_param, $input:pat_param, $o:ident| $body:block) => {
        $(#[$doc])*
        pub struct $name;
        impl SafeSlot for $name {
            type In = $in;
            type Out = $out;
            type State = State;
            fn call(
                $inst: sdk::Instance<'_, State>,
                $input: Lent<'_, $in>,
                #[allow(unused_mut)] mut $o: Out<'_, $out>,
            ) -> Outcome $body
        }
    };
}

macro_rules! answer {
    ($name:ident, $in:ty, $out:ty, $outcome:expr) => {
        slot!(
            #[doc = concat!("`", stringify!($name), "`.")]
            $name,
            $in,
            $out,
            |_, _, _out| { $outcome }
        );
    };
}

impl Life for Instance {
    /// No framer op pends, so nothing is ever in flight to cancel.
    const CANCEL: u32 = CANCEL_NOTHING_MOVED;

    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        read_settings(settings).map(|_| ()).map_err(Refusal::failed)
    }

    fn open(settings: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Self {
            posture: read_settings(settings).map_err(Refusal::failed)?,
            framings: Mutex::new(HashMap::new()),
            calls: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
        })
    }

    fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        Ok(Refreshed::default())
    }
}

slot!(
    /// `close`: answering READY, the SDK drops the instance.
    Close, InHead, OutHead, |_, _, _out| { Outcome::Ready }
);

// A framer is not a carrier: every carrier op is refused. Nothing detaches from, or adopts onto, a
// gRPC connection.
answer!(Listen, ListenIn, ListenOut, Outcome::Refused);
answer!(Accept, AcceptIn, AcceptOut, Outcome::Refused);
answer!(Dial, DialIn, ConnOut, Outcome::Refused);
answer!(Read, ReadIn, IoOut, Outcome::Refused);
answer!(Write, WriteIn, IoOut, Outcome::Refused);
answer!(Flush, ConnIn, OutHead, Outcome::Refused);
answer!(Shut, ShutIn, OutHead, Outcome::Refused);
answer!(Arrival, ArrivalIn, ArrivalOut, Outcome::Refused);
answer!(Detach, FramingIn, FramerOut, Outcome::Refused);
answer!(Adopt, AdoptIn, FramerOut, Outcome::Refused);

slot!(
    /// `locate`: where a dialled target is and the offer its handshake makes, with the framer's
    /// own head lines for a request to it (`DEFAULT_LINES`); or, asked for an ACCEPTING
    /// listener (`LocateIn::accept`), the offer that listener makes: `h2` alone, the protocol a
    /// gRPC client negotiates over TLS. A listener names no far end, so no target is read and no
    /// authority, name or head line is stated.
    Locate, LocateIn, LocateOut, |_, i, o| {
        if i.accept() != 0 {
            let mut alpn = i.alpn_buf();
            alpn.extend(OFFER_H2);
            let short = !alpn.fits();
            let (pw, pnd) = alpn.settle(short);
            o.set(|x| &x.alpn_written, pw as u64);
            o.set(|x| &x.alpn_needed, pnd as u64);
            if short {
                o.error("locate: a host buffer is too small");
                return Outcome::Failed;
            }
            return Outcome::Ready;
        }
        let Some(uri) = std::str::from_utf8(i.target().bytes())
            .ok()
            .and_then(|t| t.parse::<http::Uri>().ok())
        else {
            o.error("locate: the target is not a URL");
            return Outcome::Failed;
        };
        let secure = match uri.scheme_str() {
            Some("https") => true,
            Some("http") => false,
            _ => {
                o.error("locate: the target's scheme is not http or https");
                return Outcome::Failed;
            }
        };
        let Some(host) = uri.host() else {
            o.error("locate: the target names no host");
            return Outcome::Failed;
        };
        let port = uri.port_u16().unwrap_or(if secure { 443 } else { 80 });
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let authority = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        // The offer exists only where a handshake does: on a secured connection.
        let offer: &[u8] = if secure { OFFER_H2 } else { &[] };
        o.set(|x| &x.secure, u32::from(secure));
        o.set(|x| &x.has_name, 1);
        let (mut a, mut n, mut l) = (i.authority_buf(), i.name_buf(), i.alpn_buf());
        let mut d = i.defaults_buf();
        a.extend(authority.as_bytes());
        n.extend(host.as_bytes());
        l.extend(offer);
        // A host that lends no defaults buffer predates it: no line is stated, and the dial writes
        // its own as before (the contract's `LocateIn::defaults_buf`).
        if i.defaults_cap() != 0 {
            d.extend(DEFAULT_LINES.as_bytes());
        }
        // One short answer for every buffer, each at its full size. The framer's own lines are
        // owed to every call, so a lent defaults buffer too small for them is a short answer too.
        let short = !(a.fits() && n.fits() && l.fits() && d.fits());
        let (aw, and) = a.settle(short);
        let (nw, nnd) = n.settle(short);
        let (lw, lnd) = l.settle(short);
        let (dw, dnd) = d.settle(short);
        o.set(|x| &x.authority_written, aw as u64);
        o.set(|x| &x.authority_needed, and as u64);
        o.set(|x| &x.name_written, nw as u64);
        o.set(|x| &x.name_needed, nnd as u64);
        o.set(|x| &x.alpn_written, lw as u64);
        o.set(|x| &x.alpn_needed, lnd as u64);
        o.set(|x| &x.defaults_written, dw as u64);
        o.set(|x| &x.defaults_needed, dnd as u64);
        if short {
            o.error("locate: a host buffer is too small");
            return Outcome::Failed;
        }
        Outcome::Ready
    }
);

/// The framer's own head lines on a dialled call (`LocateIn::defaults_buf`): the lines gRPC's
/// wire carries on every request, stated so the host adds each the call does not carry BEFORE the
/// auth signs the head, and the dial then sends them as signed: the content
/// type and `te: trailers`, in the order the dial writes them. No `grpc-timeout`: none goes
/// upstream.
const DEFAULT_LINES: &str = "content-type: application/grpc\r\nte: trailers\r\n";

slot!(
    /// `begin`.
    Begin, BeginIn, FramerOut, |p, i, o| {
        let Some(inst) = mine(&p) else {
            return Outcome::Failed;
        };
        if i.side() == SIDE_ACCEPT_STREAM {
            let fields = i.fields();
            let opened = StreamCall::open(
                fields
                    .iter()
                    .map(|f| (f.name().bytes(), f.value().bytes())),
                inst.posture.max_message_bytes,
            );
            let mut call = match opened {
                Ok(call) => call,
                Err(e) => return o.fail(Refusal::refused(e.0)),
            };
            let token = inst.next.fetch_add(1, Ordering::Relaxed);
            o.set(|x| &x.framing, token);
            fill(&mut call, i.sink(), &mut o, class_of, fault_of);
            inst.calls
                .lock()
                .expect("calls")
                .insert(token, Arc::new(Mutex::new(call)));
            return Outcome::Ready;
        }
        let agreed = i
            .facts()
            .map_or(&[][..], |f| f.agreed_protocol().bytes());
        // `h2` agreed, or no agreement at all (cleartext: HTTP/2 by prior knowledge).
        if !(agreed.is_empty() || agreed == b"h2") {
            o.error("begin: gRPC needs h2, and another protocol was agreed");
            return Outcome::Refused;
        }
        let now = i.sink().now_monotonic_ns();
        let conn = match i.side() {
            SIDE_DIAL => {
                let Ok(target) = std::str::from_utf8(i.target().bytes()) else {
                    o.error("begin: the target is not text");
                    return Outcome::Failed;
                };
                match Conn::dial(target, inst.posture, now) {
                    Ok(c) => c,
                    Err(_) => {
                        o.error("begin: the target is not a URL");
                        return Outcome::Failed;
                    }
                }
            }
            SIDE_ACCEPT => Conn::accept(inst.posture, now),
            _ => {
                o.error("begin: the side is neither accept nor dial");
                return Outcome::Failed;
            }
        };
        let token = inst.next.fetch_add(1, Ordering::Relaxed);
        let held = Arc::new(Mutex::new(conn));
        inst.framings
            .lock()
            .expect("framings")
            .insert(token, held.clone());
        o.set(|x| &x.framing, token);
        let mut h = held.lock().expect("framing");
        step(&mut h, i.sink(), &mut o, |_| Ok(()))
    }
);

slot!(
    /// `ingest`.
    Ingest, IngestIn, FramerOut, |p, i, o| {
        let bytes = i.bytes();
        if let Some(call) = one_stream(&p, i.framing()) {
            let end = i.end() != 0;
            return on_stream(&call, i.sink(), &mut o, |c| c.ingest(bytes, end));
        }
        with(&p, i.framing(), i.sink(), &mut o, |c| {
            c.ingest(bytes, i.end() != 0);
            Ok(())
        })
    }
);

slot!(
    /// `emit`.
    Emit, EmitIn, FramerOut, |p, i, o| {
        let bytes = i.bytes();
        let (now, deadline, end) = (i.sink().now_monotonic_ns(), i.deadline_ns(), i.end_of_frame() != 0);
        if let Some(call) = one_stream(&p, i.framing()) {
            return on_stream(&call, i.sink(), &mut o, |c| {
                c.emit(bytes, end);
                Ok(())
            });
        }
        // A STREAM'S OWN BACKPRESSURE: an emit that leaves its stream's queue at the high-water
        // mark is answered `YIELD_STREAM_FULL` (after the fill, as the SDK states).
        let stream = i.stream();
        with_then(
            &p,
            i.framing(),
            i.sink(),
            &mut o,
            |c| c.emit(stream, bytes, end, deadline, now),
            |c, o| {
                if c.announce_full(stream) {
                    mark_stream_full(o);
                }
            },
        )
    }
);

slot!(
    /// `refuse`: on an accepted stream, the call's end with its trailer block, or with the
    /// refusal's neutral status mapped when the block states no `grpc-status`. A connection is
    /// never refused whole, and a dialled call is never answered.
    Refuse, RefuseIn, FramerOut, |p, i, o| {
        if i.has_stream() == 0 {
            o.error("refuse: gRPC refuses a call, never a connection");
            return Outcome::Refused;
        }
        let bytes = i.bytes();
        if let Some(call) = one_stream(&p, i.framing()) {
            let (status, head_sent) = (i.status(), i.head_sent() != 0);
            return on_stream(&call, i.sink(), &mut o, |c| c.refuse(bytes, status, head_sent));
        }
        with(&p, i.framing(), i.sink(), &mut o, |c| c.end_call(i.stream(), bytes, i.status()))
    }
);

slot!(
    /// `timer`.
    Timer, FramingIn, FramerOut, |p, i, o| {
        if let Some(call) = one_stream(&p, i.framing()) {
            // One stream asks for no timer (it enforces no deadline): a call only fills.
            return on_stream(&call, i.sink(), &mut o, |_| Ok(()));
        }
        with(&p, i.framing(), i.sink(), &mut o, |_| Ok(()))
    }
);

slot!(
    /// `finish`: the connection is dropped, with every call on it. A one-stream framing's finish
    /// closes its call with the final status the close states (its final tail), as trailers.
    Finish, FinishIn, FramerOut, |p, i, o| {
        let call = mine(&p)
            .and_then(|inst| inst.calls.lock().expect("calls").remove(&i.framing()));
        if let Some(call) = call {
            let all = i.final_bytes();
            let at = |s: busbar_contract::abi::mechanism::call::Span| {
                let start = s.offset as usize;
                all.get(start..start.saturating_add(s.len as usize))
                    .unwrap_or_default()
            };
            let (message, details) = (at(i.final_message()), at(i.final_details()));
            let status = i.final_status();
            let answered = on_stream(&call, i.sink(), &mut o, |c| {
                c.finish(status, message, details)
            });
            // A close the sink could not take whole stays until the host's re-call drains it, and a
            // close that failed stays for the host's fallback refusal to close the call.
            let keep = {
                let c = call.lock().expect("stream");
                c.wire_pending() || !c.ended()
            };
            if keep {
                if let Some(inst) = mine(&p) {
                    inst.calls.lock().expect("calls").insert(i.framing(), call);
                }
            }
            return answered;
        }
        let removed = mine(&p)
            .and_then(|inst| inst.framings.lock().expect("framings").remove(&i.framing()));
        if removed.is_some() {
            o.set(|x| &x.yielded.flags, YIELD_ENDED);
            Outcome::Ready
        } else {
            o.error("finish: no such framing");
            Outcome::Failed
        }
    }
);

slot!(
    /// `encode`: a head block (the envelope's fields and the message's length) and the body as
    /// one length-prefixed message, into the wire buffer.
    Encode, EncodeIn, FramerOut, |_, i, o| {
        let fields = i.fields();
        let mut pairs = Vec::with_capacity(fields.len() + 1);
        // The target head word, where the host states one, names the method: it leads, so it wins
        // over a same-named envelope field. gRPC's method word is always POST: a method word is
        // not read.
        let word = i.target().bytes();
        if !word.is_empty() {
            pairs.push(("path", word));
        }
        for f in fields.iter() {
            let Ok(name) = f.name().as_str() else {
                o.error("encode: a field name is not text");
                return Outcome::Failed;
            };
            if !word.is_empty() && name.eq_ignore_ascii_case("path") {
                continue;
            }
            pairs.push((name, f.value().bytes()));
        }
        let body = i.body();
        let Ok(bytes) = msg::render_head(&pairs, Some(msg::PREFIX + body.len())) else {
            o.error("encode: the envelope cannot be expressed on this wire");
            return Outcome::Failed;
        };
        let mut wire = i.sink().wire();
        if bytes.len() + msg::PREFIX + body.len() > wire.cap() {
            o.error("encode: the rendered call is larger than the wire buffer");
            return Outcome::Failed;
        }
        wire.extend(&bytes);
        wire.extend(&msg::prefix(body.len()));
        wire.extend(body);
        o.set(|x| &x.yielded.wire_len, wire.written() as u64);
        Outcome::Ready
    }
);

/// The one-stream framing `token` names, where it names one.
fn one_stream(p: &sdk::Instance<'_, State>, token: u64) -> Option<Arc<Mutex<StreamCall>>> {
    mine(p).and_then(|inst| inst.calls.lock().expect("calls").get(&token).cloned())
}

/// Run `f` on a one-stream framing, then fill the sink with what it owes.
fn on_stream(
    call: &Mutex<StreamCall>,
    sink: Lent<'_, FramerSink>,
    o: &mut Out<'_, FramerOut>,
    f: impl FnOnce(&mut StreamCall) -> Result<(), transport::Failure>,
) -> Outcome {
    let mut c = call.lock().expect("stream");
    if let Err(e) = f(&mut c) {
        return o.fail(Refusal::failed(e.0));
    }
    fill(&mut *c, sink, o, class_of, fault_of);
    Outcome::Ready
}

/// Run `f` on framing `token`, then drive it and fill the sink.
fn with(
    p: &sdk::Instance<'_, State>,
    token: u64,
    sink: Lent<'_, FramerSink>,
    o: &mut Out<'_, FramerOut>,
    f: impl FnOnce(&mut Conn) -> Result<(), transport::Failure>,
) -> Outcome {
    with_then(p, token, sink, o, f, |_, _| {})
}

/// [`with`], then `then` on the framing and the answer, where the op answered READY.
fn with_then(
    p: &sdk::Instance<'_, State>,
    token: u64,
    sink: Lent<'_, FramerSink>,
    o: &mut Out<'_, FramerOut>,
    f: impl FnOnce(&mut Conn) -> Result<(), transport::Failure>,
    then: impl FnOnce(&Conn, &mut Out<'_, FramerOut>),
) -> Outcome {
    let held =
        mine(p).and_then(|inst| inst.framings.lock().expect("framings").get(&token).cloned());
    let Some(held) = held else {
        o.error("no such framing");
        return Outcome::Failed;
    };
    let mut h = held.lock().expect("framing");
    let outcome = step(&mut h, sink, o, f);
    if matches!(outcome, Outcome::Ready) {
        then(&h, o);
    }
    outcome
}

fn step(
    c: &mut Conn,
    sink: Lent<'_, FramerSink>,
    o: &mut Out<'_, FramerOut>,
    f: impl FnOnce(&mut Conn) -> Result<(), transport::Failure>,
) -> Outcome {
    if let Err(e) = f(c) {
        return o.fail(Refusal::failed(e.0));
    }
    c.drive(sink.now_monotonic_ns());
    let pending = c.wire_pending() || !c.pieces().is_empty();
    if let Some(e) = c.failure().cloned() {
        if !pending {
            return o.fail(Refusal::failed(e.0));
        }
    }
    fill(c, sink, o, class_of, fault_of);
    Outcome::Ready
}

busbar_contract::plugin_door! {
    ops: Ops,
    statement: STATEMENT,
    lifecycle: {
        validate: Safe<life::Validate<Instance>>,
        open: Safe<life::Open<Instance>>,
        refresh: Safe<life::Refresh<Instance>>,
        retire: Safe<life::Retire<Instance>>,
        tick: Safe<life::Tick<Instance>>,
        drive: Safe<life::Drive<Instance>>,
        cancel: Safe<life::Cancel<Instance>>,
        release: Safe<life::Release<Instance>>,
        close: Safe<Close>,
    },
    kind_ops: {
        listen: Safe<Listen>,
        accept: Safe<Accept>,
        dial: Safe<Dial>,
        read: Safe<Read>,
        write: Safe<Write>,
        flush: Safe<Flush>,
        shut: Safe<Shut>,
        arrival: Safe<Arrival>,
        locate: Safe<Locate>,
        begin: Safe<Begin>,
        ingest: Safe<Ingest>,
        emit: Safe<Emit>,
        encode: Safe<Encode>,
        refuse: Safe<Refuse>,
        finish: Safe<Finish>,
        detach: Safe<Detach>,
        adopt: Safe<Adopt>,
        timer: Safe<Timer>,
    },
}

#[cfg(test)]
#[path = "tests/door_tests.rs"]
mod tests;
