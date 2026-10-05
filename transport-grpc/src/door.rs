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
//! What a stream carries each way, and how `grpc-status` reaches the host (the terminal piece's
//! code, in the `grpc` numbering this door's status rows class), is the framer's module note (`transport.rs`).
//!
//! No op pends. Every slot is a `SafeSlot` on the SDK's safe surface: this crate holds no `unsafe`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::hyper_io::{fill, Owed};
use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
use busbar_contract::abi::mechanism::lifecycle::{
    CancelIn, CancelOut, DriveIn, GenIn, OpenIn, OpenOut, RefreshIn, ReleaseIn, TickIn, TickOut,
    ValidateIn,
};
use busbar_contract::abi::sdk::door::statement;
use busbar_contract::abi::sdk::life::Refusal;
use busbar_contract::abi::sdk::{self as sdk, Lent, Out, Safe, SafeSlot};
use busbar_contract::abi::transport::{
    AcceptIn, AcceptOut, AdoptIn, ArrivalIn, ArrivalOut, BeginIn, ConnIn, ConnOut, DialIn, EmitIn,
    EncodeIn, FinishIn, FramerOut, FramerSink, FramingIn, IngestIn, IoOut, ListenIn, ListenOut,
    LocateIn, LocateOut, Ops, ReadIn, RefuseIn, ShutIn, TransportTail, WriteIn,
    CANCEL_NOTHING_MOVED, SIDE_ACCEPT, SIDE_DIAL, YIELD_ENDED,
};
use busbar_contract::transport::registry::{
    DEFAULT_REQUEST_BODY_MAX_BYTES, DEFAULT_REQUEST_TIMEOUT_SECS,
};

use crate::msg;
use crate::transport::{self, Conn, Posture};

// ── the statement ────────────────────────────────────────────────────────────────────────────────

use crate::claims::CLAIM_NAMES;
use crate::meta::{class_of, TAIL};
pub use crate::meta::{setting, KEY};

/// The door's Statement: the `grpc` framer.
pub const STATEMENT: Statement = Statement {
    kind_tail: (&TAIL as *const TransportTail).cast::<KindTailHead>(),
    claims: CLAIM_NAMES.as_ptr(),
    claims_len: CLAIM_NAMES.len(),
    ..statement(KEY, env!("CARGO_PKG_VERSION"), 64)
};

/// The protocol offer on a secured connection, in the handshake's ProtocolNameList encoding.
const OFFER_H2: &[u8] = b"\x02h2";

// ── the instance ─────────────────────────────────────────────────────────────────────────────────

/// What `open` read from the settings, and the framings it holds.
pub struct Instance {
    posture: Posture,
    framings: Mutex<HashMap<u64, Arc<Mutex<Held>>>>,
    next: AtomicU64,
}

/// One framing.
struct Held {
    conn: Conn,
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

/// One slot body on the SDK's safe surface, over this framer's [`Instance`].
macro_rules! slot {
    ($(#[$doc:meta])* $name:ident, $in:ty, $out:ty,
     |$inst:pat_param, $input:pat_param, $o:ident| $body:block) => {
        $(#[$doc])*
        pub struct $name;
        impl SafeSlot for $name {
            type In = $in;
            type Out = $out;
            type State = Instance;
            fn call(
                $inst: sdk::Instance<'_, Instance>,
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

// ── the lifecycle ────────────────────────────────────────────────────────────────────────────────

slot!(
    /// `validate`.
    Validate, ValidateIn, OutHead, |_, i, o| {
        match read_settings(i.field(|x| &x.settings).bytes()) {
            Ok(_) => Outcome::Ready,
            Err(e) => {
                o.error(e);
                Outcome::Failed
            }
        }
    }
);

slot!(
    /// `open`.
    Open, OpenIn, OpenOut, |instance, i, o| {
        match read_settings(i.field(|x| &x.settings).bytes()) {
            Ok(posture) => {
                instance.open(Instance {
                    posture,
                    framings: Mutex::new(HashMap::new()),
                    next: AtomicU64::new(1),
                });
                Outcome::Ready
            }
            Err(e) => {
                o.error(e);
                Outcome::Failed
            }
        }
    }
);

slot!(
    /// `close`: answering READY, the SDK drops the instance.
    Close, InHead, OutHead, |_, _, _out| { Outcome::Ready }
);

slot!(
    /// `cancel`: no framer op pends, so nothing is ever in flight to cancel.
    Cancel, CancelIn, CancelOut, |_, _, o| {
        o.set(|x| &x.disposition, CANCEL_NOTHING_MOVED);
        Outcome::Ready
    }
);

answer!(Tick, TickIn, TickOut, Outcome::Ready);
answer!(Refresh, RefreshIn, OutHead, Outcome::Ready);
answer!(Retire, GenIn, OutHead, Outcome::Ready);
answer!(Drive, DriveIn, OutHead, Outcome::Ready);
answer!(Release, ReleaseIn, OutHead, Outcome::Ready);

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

// ── the framer ───────────────────────────────────────────────────────────────────────────────────

slot!(
    /// `locate`.
    Locate, LocateIn, LocateOut, |_, i, o| {
        let Some(uri) = std::str::from_utf8(i.field(|x| &x.target).bytes())
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
        let (mut a, mut n, mut p) = (i.authority_buf(), i.name_buf(), i.alpn_buf());
        a.extend(authority.as_bytes());
        n.extend(host.as_bytes());
        p.extend(offer);
        // One short answer for every buffer, each at its full size.
        let short = !(a.fits() && n.fits() && p.fits());
        let (aw, and) = a.settle(short);
        let (nw, nnd) = n.settle(short);
        let (pw, pnd) = p.settle(short);
        o.set(|x| &x.authority_written, aw as u64);
        o.set(|x| &x.authority_needed, and as u64);
        o.set(|x| &x.name_written, nw as u64);
        o.set(|x| &x.name_needed, nnd as u64);
        o.set(|x| &x.alpn_written, pw as u64);
        o.set(|x| &x.alpn_needed, pnd as u64);
        if short {
            o.error("locate: a host buffer is too small");
            return Outcome::Failed;
        }
        Outcome::Ready
    }
);

slot!(
    /// `begin`.
    Begin, BeginIn, FramerOut, |p, i, o| {
        let Some(inst) = p.get() else {
            return Outcome::Failed;
        };
        let agreed = i
            .facts()
            .map_or(&[][..], |f| f.field(|x| &x.agreed_protocol).bytes());
        // `h2` agreed, or no agreement at all (cleartext: HTTP/2 by prior knowledge).
        if !(agreed.is_empty() || agreed == b"h2") {
            o.error("begin: gRPC needs h2, and another protocol was agreed");
            return Outcome::Refused;
        }
        let now = i.sink.now_monotonic_ns;
        let conn = match i.side {
            SIDE_DIAL => {
                let Ok(target) = std::str::from_utf8(i.field(|x| &x.target).bytes()) else {
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
        let held = Arc::new(Mutex::new(Held { conn }));
        inst.framings
            .lock()
            .expect("framings")
            .insert(token, held.clone());
        o.set(|x| &x.framing, token);
        let mut h = held.lock().expect("framing");
        step(&mut h, i.field(|x| &x.sink), &mut o, |_| Ok(()))
    }
);

slot!(
    /// `ingest`.
    Ingest, IngestIn, FramerOut, |p, i, o| {
        let bytes = i.bytes();
        with(&p, i.framing, i.field(|x| &x.sink), &mut o, |c| {
            c.ingest(bytes, i.end != 0);
            Ok(())
        })
    }
);

slot!(
    /// `emit`.
    Emit, EmitIn, FramerOut, |p, i, o| {
        let bytes = i.bytes();
        let (now, deadline, end) = (i.sink.now_monotonic_ns, i.deadline_ns, i.end_of_frame != 0);
        with(&p, i.framing, i.field(|x| &x.sink), &mut o, |c| {
            c.emit(i.stream, bytes, end, deadline, now)
        })
    }
);

slot!(
    /// `refuse`: on an accepted stream, the call's end with its trailer block, or with the
    /// refusal's neutral status mapped when the block states no `grpc-status`. A connection is
    /// never refused whole, and a dialled call is never answered.
    Refuse, RefuseIn, FramerOut, |p, i, o| {
        if i.has_stream == 0 {
            o.error("refuse: gRPC refuses a call, never a connection");
            return Outcome::Refused;
        }
        let bytes = i.bytes();
        with(&p, i.framing, i.field(|x| &x.sink), &mut o, |c| c.end_call(i.stream, bytes, i.status))
    }
);

slot!(
    /// `timer`.
    Timer, FramingIn, FramerOut, |p, i, o| {
        with(&p, i.framing, i.field(|x| &x.sink), &mut o, |_| Ok(()))
    }
);

slot!(
    /// `finish`: the connection is dropped, with every call on it.
    Finish, FinishIn, FramerOut, |p, i, o| {
        let removed = p
            .get()
            .and_then(|inst| inst.framings.lock().expect("framings").remove(&i.framing));
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
        let word = i.field(|x| &x.target).bytes();
        if !word.is_empty() {
            pairs.push(("path", word));
        }
        for f in fields.iter() {
            let Ok(name) = f.field(|x| &x.name).as_str() else {
                o.error("encode: a field name is not text");
                return Outcome::Failed;
            };
            if !word.is_empty() && name.eq_ignore_ascii_case("path") {
                continue;
            }
            pairs.push((name, f.field(|x| &x.value).bytes()));
        }
        let message = msg::frame(i.body());
        let Ok(mut bytes) = msg::render_head(&pairs, Some(message.len())) else {
            o.error("encode: the envelope cannot be expressed on this wire");
            return Outcome::Failed;
        };
        bytes.extend_from_slice(&message);
        let mut wire = i.field(|x| &x.sink).wire();
        if bytes.len() > wire.cap() {
            o.error("encode: the rendered call is larger than the wire buffer");
            return Outcome::Failed;
        }
        wire.extend(&bytes);
        o.set(|x| &x.yielded.wire_len, wire.written() as u64);
        Outcome::Ready
    }
);

/// Run `f` on framing `token`, then drive it and fill the sink.
fn with(
    p: &sdk::Instance<'_, Instance>,
    token: u64,
    sink: Lent<'_, FramerSink>,
    o: &mut Out<'_, FramerOut>,
    f: impl FnOnce(&mut Conn) -> Result<(), transport::Failure>,
) -> Outcome {
    let held = p
        .get()
        .and_then(|inst| inst.framings.lock().expect("framings").get(&token).cloned());
    let Some(held) = held else {
        o.error("no such framing");
        return Outcome::Failed;
    };
    let mut h = held.lock().expect("framing");
    step(&mut h, sink, o, f)
}

fn step(
    h: &mut Held,
    sink: Lent<'_, FramerSink>,
    o: &mut Out<'_, FramerOut>,
    f: impl FnOnce(&mut Conn) -> Result<(), transport::Failure>,
) -> Outcome {
    if let Err(e) = f(&mut h.conn) {
        return o.fail(Refusal::failed(e.0));
    }
    h.conn.drive(sink.now_monotonic_ns);
    let pending = h.conn.wire_pending() || !h.conn.pieces().is_empty();
    if let Some(e) = h.conn.failure().cloned() {
        if !pending {
            return o.fail(Refusal::failed(e.0));
        }
    }
    fill(&mut h.conn, sink, o, class_of);
    Outcome::Ready
}

busbar_contract::plugin_door! {
    ops: Ops,
    statement: STATEMENT,
    lifecycle: {
        validate: Safe<Validate>,
        open: Safe<Open>,
        refresh: Safe<Refresh>,
        retire: Safe<Retire>,
        tick: Safe<Tick>,
        drive: Safe<Drive>,
        cancel: Safe<Cancel>,
        release: Safe<Release>,
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
