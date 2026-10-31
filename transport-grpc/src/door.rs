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
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use crate::hyper_io::{fill, mark_stream_full, Owed};
use busbar_contract::abi::mechanism::call::{OutHead, Outcome};
use busbar_contract::abi::mechanism::door::Statement;
use busbar_contract::abi::sdk::door::statement;
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::transport::settings_reading;
use busbar_contract::abi::sdk::transport::DEFAULT_BODY_MAX;
use busbar_contract::abi::sdk::{self as sdk, Lent, Out, Safe, SafeSlot};
use busbar_contract::abi::transport::{
    AcceptIn, AcceptOut, AdoptIn, ArrivalIn, ArrivalOut, BeginIn, ConnIn, ConnOut, DialIn, EmitIn,
    EncodeIn, FinishIn, FramerOut, FramerSink, FramingIn, IngestIn, IoOut, ListenIn, ListenOut,
    LocateIn, LocateOut, Ops, ReadIn, RefuseIn, ShutIn, WriteIn, CANCEL_NOTHING_MOVED, SIDE_ACCEPT,
    SIDE_ACCEPT_STREAM, SIDE_DIAL, YIELD_ENDED,
};

use crate::msg;
use crate::stream::StreamCall;
use crate::transport::{self, Conn, Posture};

use crate::claims::CLAIM_NAMES;
use crate::meta::{class_of, decimal, fault_of, DEFAULT_TIMEOUT, TAIL};
pub use crate::meta::{setting, KEY};

/// THE AUTH POINTS THIS DOOR OFFERS: none (ruling R2). It makes no auth call on either side (no
/// op pends), so it states an empty record: boot refuses a guest line whose auth needs a point on
/// it, rather than read the default `{Head, HeadBody}` it would not honour.
const OFFERED_POINTS: [u8; 4] = 0u32.to_le_bytes();

busbar_contract::statement_extensions!(
    /// The Statement's extensions: this plugin's whole `declares` document, and the auth points
    /// it offers.
    EXTENSIONS: [
        (
            busbar_contract::abi::mechanism::extensions::EXT_DECLARES,
            include_bytes!("../declares.json")
        ),
        (
            busbar_contract::abi::transport::EXT_OFFERED_POINTS,
            &OFFERED_POINTS
        ),
    ]
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
    /// The settings in force: what `open` read, or the last good `refresh`, copied by each `begin`
    /// (a framing keeps the posture it began under).
    posture: Mutex<Posture>,
    framings: Mutex<HashMap<u64, Arc<Mutex<Conn>>>>,
    /// The one-stream framings (`SIDE_ACCEPT_STREAM`), by the same token space.
    calls: Mutex<HashMap<u64, Arc<Mutex<StreamCall>>>>,
    next: AtomicU64,
}

/// HTTP/2 keep-alive on a dialled connection: a PING this often (fixed here, not an operator
/// setting), so a far end gone silent is found while a call waits on it.
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// How long a keep-alive PING may go unanswered before the dialled connection is failed.
const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// HTTP/2's adaptive flow-control window, both sides (fixed here, not an operator setting).
const ADAPTIVE_WINDOW: bool = true;

/// The settings blob's bytes, parsed; `Err` names the first one that is not what its declaration
/// says. An absent blob reads as `{}`.
fn read_settings(bytes: &[u8]) -> Result<Posture, Refusal> {
    let v = settings_reading(
        bytes,
        &[setting::REQUEST_TIMEOUT_SECS, setting::BODY_MAX_BYTES],
    )?;
    // A count above 0, by its key and its unit (`settings: <key> must be a count of <unit> above
    // 0`, http's words); an absent one reads as the default its declaration states (`SETTINGS`):
    // one source.
    let count = |k: &'static str, unit: &str, declared: &str| match v.get(k) {
        None => Ok(decimal(declared)),
        Some(x) => x.as_u64().filter(|n| *n > 0).ok_or_else(|| {
            Refusal::failed(format!("settings: {k} must be a count of {unit} above 0"))
        }),
    };
    let secs = count(setting::REQUEST_TIMEOUT_SECS, "seconds", DEFAULT_TIMEOUT)?;
    let max = count(setting::BODY_MAX_BYTES, "bytes", DEFAULT_BODY_MAX)?;
    Ok(Posture {
        keep_alive_interval: Some(KEEP_ALIVE_INTERVAL),
        keep_alive_timeout: KEEP_ALIVE_TIMEOUT,
        adaptive_window: ADAPTIVE_WINDOW,
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

impl Life for Instance {
    /// No framer op pends, so nothing is ever in flight to cancel.
    const CANCEL: u32 = CANCEL_NOTHING_MOVED;

    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        read_settings(settings).map(|_| ())
    }

    fn open(settings: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Self {
            posture: Mutex::new(read_settings(settings)?),
            framings: Mutex::new(HashMap::new()),
            calls: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
        })
    }

    /// The new settings, read with `validate`'s texts. A bad blob is FAILED and the settings in
    /// force stay; good ones apply to every framing begun after it.
    fn refresh(&self, settings: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        let posture = read_settings(settings)?;
        *self.posture.lock().unwrap_or_else(PoisonError::into_inner) = posture;
        Ok(Refreshed::default())
    }
}

busbar_contract::not_served! {
    state: State, role: "grpc framer";
    Listen(ListenIn => ListenOut) "listen";
    Accept(AcceptIn => AcceptOut) "accept";
    Dial(DialIn => ConnOut) "dial";
    Read(ReadIn => IoOut) "read";
    Write(WriteIn => IoOut) "write";
    Flush(ConnIn => OutHead) "flush";
    Shut(ShutIn => OutHead) "shut";
    Arrival(ArrivalIn => ArrivalOut) "arrival";
    Detach(FramingIn => FramerOut) "detach";
    Adopt(AdoptIn => FramerOut) "adopt";
}

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
        if carries_userinfo(&uri) {
            o.error("locate: the target carries userinfo; credentials never ride a URL");
            return Outcome::Failed;
        }
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

/// Whether `uri`'s authority carries userinfo (`user:pass@`): a credential, which never rides a URL
/// (refused outright, never read on, never echoed), as http and ws refuse it.
fn carries_userinfo(uri: &http::Uri) -> bool {
    uri.authority().is_some_and(|a| a.as_str().contains('@'))
}

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
            o.error("begin: no open instance");
            return Outcome::Failed;
        };
        let posture = *inst.posture.lock().unwrap_or_else(PoisonError::into_inner);
        if i.side() == SIDE_ACCEPT_STREAM {
            let fields = i.fields();
            let opened = StreamCall::open(
                fields
                    .iter()
                    .map(|f| (f.name().bytes(), f.value().bytes())),
                posture.max_message_bytes,
            );
            let mut call = match opened {
                Ok(call) => call,
                Err(e) => return o.fail(Refusal::refused(e.0)),
            };
            let token = inst.next.fetch_add(1, Ordering::Relaxed);
            o.set(|x| &x.framing, token);
            fill(&mut call, i.sink(), &mut o, class_of, fault_of);
            inst.calls
                .lock().unwrap_or_else(PoisonError::into_inner)
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
                if target.parse::<http::Uri>().is_ok_and(|u| carries_userinfo(&u)) {
                    o.error("begin: the target carries userinfo; credentials never ride a URL");
                    return Outcome::Failed;
                }
                match Conn::dial(target, posture, now) {
                    Ok(c) => c,
                    Err(_) => {
                        o.error("begin: the target is not a URL");
                        return Outcome::Failed;
                    }
                }
            }
            SIDE_ACCEPT => Conn::accept(posture, now),
            _ => {
                o.error("begin: the side is neither accept nor dial");
                return Outcome::Failed;
            }
        };
        let token = inst.next.fetch_add(1, Ordering::Relaxed);
        let held = Arc::new(Mutex::new(conn));
        inst.framings
            .lock().unwrap_or_else(PoisonError::into_inner)
            .insert(token, held.clone());
        o.set(|x| &x.framing, token);
        let mut h = held.lock().unwrap_or_else(PoisonError::into_inner);
        step("begin", &mut h, i.sink(), &mut o, |_| Ok(()))
    }
);

slot!(
    /// `ingest`.
    Ingest, IngestIn, FramerOut, |p, i, o| {
        let bytes = i.bytes();
        if let Some(call) = one_stream(&p, i.framing()) {
            let end = i.end() != 0;
            return on_stream("ingest", &call, i.sink(), &mut o, |c| c.ingest(bytes, end));
        }
        with("ingest", &p, i.framing(), i.sink(), &mut o, |c| {
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
        // A STREAM'S OWN BACKPRESSURE, on one stream as on a connection's: an emit that leaves its
        // stream's queue at the high-water mark is answered `YIELD_STREAM_FULL` (after the fill, as
        // the SDK states).
        if let Some(call) = one_stream(&p, i.framing()) {
            let outcome = on_stream("emit", &call, i.sink(), &mut o, |c| c.emit(bytes, end));
            if matches!(outcome, Outcome::Ready) && call.lock().unwrap_or_else(PoisonError::into_inner).announce_full() {
                mark_stream_full(&mut o);
            }
            return outcome;
        }
        let stream = i.stream();
        with_then(
            "emit",
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
            return on_stream("refuse", &call, i.sink(), &mut o, |c| {
                c.refuse(bytes, status, head_sent)
            });
        }
        with("refuse", &p, i.framing(), i.sink(), &mut o, |c| {
            c.end_call(i.stream(), bytes, i.status())
        })
    }
);

slot!(
    /// `timer`.
    Timer, FramingIn, FramerOut, |p, i, o| {
        if let Some(call) = one_stream(&p, i.framing()) {
            // One stream asks for no timer (it enforces no deadline): a call only fills.
            return on_stream("timer", &call, i.sink(), &mut o, |_| Ok(()));
        }
        with("timer", &p, i.framing(), i.sink(), &mut o, |_| Ok(()))
    }
);

slot!(
    /// `finish`: the connection is dropped, with every call on it. A one-stream framing's finish
    /// closes its call with the final status the close states (its final tail), as trailers.
    Finish, FinishIn, FramerOut, |p, i, o| {
        let call = mine(&p)
            .and_then(|inst| inst.calls.lock().unwrap_or_else(PoisonError::into_inner).remove(&i.framing()));
        if let Some(call) = call {
            let all = i.final_bytes();
            // A span of no bytes (absent among them) is none; any other must lie inside the bytes.
            let at = |s: busbar_contract::abi::mechanism::call::Span| {
                if s.len == 0 {
                    return Some(&[][..]);
                }
                let start = s.offset as usize;
                all.get(start..start.checked_add(s.len as usize)?)
            };
            let (message, details) = match (at(i.final_message()), at(i.final_details())) {
                (Some(m), Some(d)) => (m, d),
                (m, _) => {
                    // Refused, and the call kept for the host's fallback refusal to close.
                    if let Some(inst) = mine(&p) {
                        inst.calls.lock().unwrap_or_else(PoisonError::into_inner).insert(i.framing(), call);
                    }
                    o.error(if m.is_none() {
                        "finish: the final message lies outside the close's bytes"
                    } else {
                        "finish: the final details lie outside the close's bytes"
                    });
                    return Outcome::Failed;
                }
            };
            let status = i.final_status();
            let answered = on_stream("finish", &call, i.sink(), &mut o, |c| {
                c.finish(status, message, details)
            });
            // A close the sink could not take whole stays until the host's re-call drains it, and a
            // close that failed stays for the host's fallback refusal to close the call.
            let keep = {
                let c = call.lock().unwrap_or_else(PoisonError::into_inner);
                c.wire_pending() || !c.ended()
            };
            if keep {
                if let Some(inst) = mine(&p) {
                    inst.calls.lock().unwrap_or_else(PoisonError::into_inner).insert(i.framing(), call);
                }
            }
            return answered;
        }
        let Some(inst) = mine(&p) else {
            o.error("finish: no open instance");
            return Outcome::Failed;
        };
        let removed = inst.framings.lock().unwrap_or_else(PoisonError::into_inner).remove(&i.framing());
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
        let Some(prefix) = msg::prefix(body.len()) else {
            o.error("encode: the message is longer than a gRPC length prefix states");
            return Outcome::Failed;
        };
        // The rendered head (the envelope's fields, an auth's lines among them) is wiped once it is
        // copied into the host's wire buffer.
        let Ok(bytes) = msg::render_head(&pairs, Some(msg::PREFIX + body.len()))
            .map(zeroize::Zeroizing::new)
        else {
            o.error("encode: the envelope cannot be expressed on this wire");
            return Outcome::Failed;
        };
        let mut wire = i.sink().wire();
        if bytes.len() + msg::PREFIX + body.len() > wire.cap() {
            o.error("encode: the rendered call is larger than the wire buffer");
            return Outcome::Failed;
        }
        wire.extend(&bytes);
        wire.extend(&prefix);
        wire.extend(body);
        o.set(|x| &x.yielded.wire_len, wire.written() as u64);
        Outcome::Ready
    }
);

/// The one-stream framing `token` names, where it names one.
fn one_stream(p: &sdk::Instance<'_, State>, token: u64) -> Option<Arc<Mutex<StreamCall>>> {
    mine(p).and_then(|inst| {
        inst.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&token)
            .cloned()
    })
}

/// Run `f` on a one-stream framing, then fill the sink with what it owes. A failure is `op`'s,
/// in its words (`<op>: <reason>`).
fn on_stream(
    op: &'static str,
    call: &Mutex<StreamCall>,
    sink: Lent<'_, FramerSink>,
    o: &mut Out<'_, FramerOut>,
    f: impl FnOnce(&mut StreamCall) -> Result<(), transport::Failure>,
) -> Outcome {
    let mut c = call.lock().unwrap_or_else(PoisonError::into_inner);
    if let Err(e) = f(&mut c) {
        return o.fail(op_failed(op, &e));
    }
    fill(&mut *c, sink, o, class_of, fault_of);
    Outcome::Ready
}

/// `op`'s refusal for the framing's failure `e`: `<op>: <reason>`.
fn op_failed(op: &str, e: &transport::Failure) -> Refusal {
    Refusal::failed(format!("{op}: {}", e.0))
}

/// Run `f` on framing `token`, then drive it and fill the sink, as `op`.
fn with(
    op: &'static str,
    p: &sdk::Instance<'_, State>,
    token: u64,
    sink: Lent<'_, FramerSink>,
    o: &mut Out<'_, FramerOut>,
    f: impl FnOnce(&mut Conn) -> Result<(), transport::Failure>,
) -> Outcome {
    with_then(op, p, token, sink, o, f, |_, _| {})
}

/// [`with`], then `then` on the framing and the answer, where the op answered READY.
fn with_then(
    op: &'static str,
    p: &sdk::Instance<'_, State>,
    token: u64,
    sink: Lent<'_, FramerSink>,
    o: &mut Out<'_, FramerOut>,
    f: impl FnOnce(&mut Conn) -> Result<(), transport::Failure>,
    then: impl FnOnce(&Conn, &mut Out<'_, FramerOut>),
) -> Outcome {
    let Some(inst) = mine(p) else {
        return o.fail(Refusal::failed(format!("{op}: no open instance")));
    };
    let held = inst
        .framings
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&token)
        .cloned();
    let Some(held) = held else {
        return o.fail(Refusal::failed(format!("{op}: no such framing")));
    };
    let mut h = held.lock().unwrap_or_else(PoisonError::into_inner);
    let outcome = step(op, &mut h, sink, o, f);
    if matches!(outcome, Outcome::Ready) {
        then(&h, o);
    }
    outcome
}

/// Run `f` on `c`, drive it and fill the sink, as `op`: a failure is `op`'s, in its words.
fn step(
    op: &'static str,
    c: &mut Conn,
    sink: Lent<'_, FramerSink>,
    o: &mut Out<'_, FramerOut>,
    f: impl FnOnce(&mut Conn) -> Result<(), transport::Failure>,
) -> Outcome {
    if let Err(e) = f(c) {
        return o.fail(op_failed(op, &e));
    }
    c.drive(sink.now_monotonic_ns());
    let pending = c.wire_pending() || !c.pieces().is_empty();
    if let Some(e) = c.failure().cloned() {
        if !pending {
            return o.fail(op_failed(op, &e));
        }
    }
    fill(c, sink, o, class_of, fault_of);
    Outcome::Ready
}

busbar_contract::plugin_door! {
    ops: Ops,
    statement: STATEMENT,
    lifecycle: life(Instance),
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
