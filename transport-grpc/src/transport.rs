// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ENGINE, as the kind's entry file (`BUSBAR-1.6.0.md` THE DESIGN, §2: meta, claims, and the
//! kind-named entry): gRPC over `hyper`'s HTTP/2, both sides, run as a sans-IO framer.
//!
//! One [`Conn`] is one connection. Its HTTP/2 machine is `hyper`'s own — `client::conn::http2`
//! on a dialled connection, `server::conn::http2` on an accepted one — driven over the host's
//! bytes by the contract's drive (`busbar_contract::hyper_io!`, expanded at the crate root): no
//! socket, no thread, no runtime, no clock of its own. This file adds the gRPC layer on top: the
//! head block, the length-prefixed messages, the deadline and `grpc-status`.
//!
//! DIALLED. The host `emit`s a stream's head block and its messages; the head's `path` names the
//! method. The request carries `content-type: application/grpc` (or the caller's `+proto`/`+json`
//! form), `te: trailers` and the stream's remaining deadline as `grpc-timeout`, and its body ENDS
//! (END_STREAM) once the head's `content-length` bytes are in, or on an `emit` that ends the frame:
//! a unary server waits for exactly that. The answer comes back as frames (HEAD-FIELDS, GRPC-DOOR
//! rulings): the HEAD, always first, a field block with no status code; one frame per message; the
//! TRAILERS, a field block carrying `grpc-status` as its code; then the terminal piece, empty when
//! the status is `OK`, else a failure whose bytes are the decoded `grpc-message`. A trailers-only
//! answer (status in the head) yields the same three. An answer that is not gRPC fails the stream
//! with its HTTP status mapped the way gRPC maps it. At the deadline the stream is reset and fails
//! `DEADLINE_EXCEEDED`.
//!
//! SIGNED (ruling 23: nothing is added to a head after its auth runs). A dialled connection whose
//! binding has an auth at the head ([`Conn::signing`]) builds each stream's request whole —
//! `:method`, `:scheme`, `:authority`, `:path`, then `content-type`, `te`, `grpc-timeout` and the
//! head block's lines — and calls the auth over exactly that ([`RequestHead`]; at
//! [`SignAt::HeadBody`] over the whole body too, the head waiting for it). Its answer goes first
//! among the field lines, replacing every line of its name, and its query keys join `:path`'s query
//! ([`signed_request`]); the request goes to HTTP/2 as it stands, and nothing is added after. A
//! pending answer parks that stream alone ([`Conn::emit_signed`]).
//!
//! ACCEPTED. Each call the far end opens is a stream: its head (a field block, with the call's
//! method, target and authority in the stream's head slots, never as fields), one frame per
//! message, and the end piece (`PIECE_END`) when the far end has sent its last. `te` is checked as 1.5.5's
//! server checked it, by HTTP/2 itself: a `te` other than `trailers` resets the stream with
//! `PROTOCOL_ERROR` before it is a call, and a missing one is served; it is then dropped as
//! hop-by-hop. The host answers on the same stream: `emit` a head block (the answer's metadata) and
//! messages; `refuse` with the trailer block (`grpc-status`, `grpc-message`, ...) ends the call —
//! trailers-only when nothing was emitted first. A call that is not gRPC is answered `415` here and
//! never reaches the host.
//!
//! A STREAM ENDS ONCE. A far end that resets an accepted call (before or after its last message,
//! before or after the host's answer began) fails the stream `CANCELLED`, and nothing more is
//! queued for it. A dialled stream that ended is remembered: an `emit` that arrives after its
//! terminal piece is dropped, never a second call on the same stream.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use crate::hyper_io::{field_block, HeadWords, HostIo, Owed, Piece};
use busbar_contract::abi::transport::fields::hop_by_hop;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode};
use http_body::{Body, Frame};
use hyper::body::Incoming;
use hyper::client::conn::http2 as client;
use hyper::rt::{Executor, Sleep};
use hyper::server::conn::http2 as server;

use zeroize::Zeroizing;

use crate::msg::{self, Head, Messages};

/// The connection posture every framing carries.
#[derive(Debug, Clone, Copy)]
pub struct Posture {
    /// HTTP/2 keep-alive ping interval on a dialled connection (`None` = no pings).
    pub keep_alive_interval: Option<Duration>,
    /// How long a keep-alive ping may go unanswered.
    pub keep_alive_timeout: Duration,
    /// HTTP/2 adaptive flow-control window.
    pub adaptive_window: bool,
    /// A dialled call's deadline when the host states none.
    pub timeout: Duration,
    /// The largest message payload carried, either way.
    pub max_message_bytes: usize,
}

/// Why a framing failed; the op that finds it answers FAILED with this text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure(pub String);

// ── the binding's auth (ruling 23) ───────────────────────────────────────────────────────────────

/// Where a dialled connection's binding auth is called on each stream's request
/// (`BeginIn::points`): over the head, or over the head and the whole body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignAt {
    /// `POINT_HEAD`.
    Head,
    /// `POINT_HEAD_BODY`.
    HeadBody,
}

/// THE REQUEST HEAD AS IT GOES ON THE WIRE, before the auth's answer joins it: what the binding's
/// auth is called over, borrowed from the request HTTP/2 encodes. `:method` is `method`, `:path`
/// is `target` (and `?query`), `:authority` is `authority`; `fields` are every other line, in the
/// order the HEADERS frame carries them. `:scheme` is the binding's target's own.
pub struct RequestHead<'a> {
    /// The method: gRPC's is always `POST`.
    pub method: &'a str,
    /// The path, without its query.
    pub target: &'a str,
    /// The query, without `?`; `None` = none.
    pub query: Option<&'a str>,
    /// The authority.
    pub authority: &'a str,
    /// Every field line, in wire order: gRPC's own (`content-type`, `te`, `grpc-timeout`), then
    /// the head block's.
    pub fields: &'a [(&'a str, &'a [u8])],
}

/// One line the binding's auth answered: a field line of the head, or (`query`) a key of the
/// path's query. Its value is credential material, wiped when dropped.
pub struct AuthLine {
    /// The name.
    pub name: String,
    /// The value.
    pub value: Zeroizing<Vec<u8>>,
    /// A query key, never a field line.
    pub query: bool,
}

/// The binding's auth, called once per stream over its request exactly as it goes on the wire
/// (and, at [`SignAt::HeadBody`], its whole body). [`Poll::Pending`]: the answer is not ready (the
/// host stores it on the call's handle); the stream parks and the same call is made again when the
/// op resumes. An error refuses the stream.
pub type Signer<'s> =
    &'s mut dyn FnMut(&RequestHead<'_>, Option<&[u8]>) -> Poll<Result<Vec<AuthLine>, Failure>>;

/// Why a dialled stream failed at its `emit`: the reason, and the gRPC status it ends with.
type StreamFault = (String, u16);

/// The framing's own failures end a stream `INTERNAL`.
fn internal(why: impl Into<String>) -> StreamFault {
    (why.into(), msg::INTERNAL)
}

type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;

// ── a body the host feeds ────────────────────────────────────────────────────────────────────────

#[derive(Default)]
struct ChanState {
    frames: VecDeque<Frame<Bytes>>,
    ended: bool,
    /// The connection let go of the body before its end: the far end reset the stream. Nothing is
    /// queued for it again.
    gone: bool,
    /// The stream was failed: the connection resets it rather than end it, so a far end never
    /// takes a cut-short body for a whole one.
    reset: bool,
    /// The payload bytes queued and not yet taken by the connection.
    queued: usize,
    /// An `emit` was answered `YIELD_STREAM_FULL` for this stream, and no writable piece has
    /// followed yet.
    announced: bool,
    waker: Option<Waker>,
}

/// A STREAM'S OWN BACKPRESSURE (the transport ABI): the payload bytes one stream may queue for
/// the far end, framer-side, before the `emit` that reaches it is answered `YIELD_STREAM_FULL`.
pub(crate) const STREAM_HIGH_WATER: usize = 1 << 20;

/// A stream answered full that has drained to this many queued bytes is writable again
/// (`PIECE_WRITABLE`).
pub(crate) const STREAM_LOW_WATER: usize = 256 * 1024;

/// Why a stream whose host emitted past its bound (the high-water mark and one whole message
/// more) failed: the framer bounds what it holds for a far end that is not reading.
const OVER_BOUND: &str = "the stream's queue is past its bound: the far end is not reading";

/// The feeding end of a [`ChanBody`].
#[derive(Clone, Default)]
struct Chan(Arc<Mutex<ChanState>>);

impl Chan {
    fn push(&self, f: Frame<Bytes>) {
        let mut s = self.0.lock().expect("chan");
        if s.ended || s.gone {
            return;
        }
        if let Some(d) = f.data_ref() {
            s.queued += d.len();
        }
        s.frames.push_back(f);
        if let Some(w) = s.waker.take() {
            w.wake();
        }
    }
    /// The payload bytes queued and not yet taken.
    fn queued(&self) -> usize {
        self.0.lock().expect("chan").queued
    }
    /// Drop every frame queued and not yet taken.
    fn drop_queued(&self) {
        let mut s = self.0.lock().expect("chan");
        s.frames.clear();
        s.queued = 0;
    }
    /// Fail the stream: drop what is queued, and have the connection reset it.
    fn reset(&self) {
        let mut s = self.0.lock().expect("chan");
        s.reset = true;
        s.frames.clear();
        s.queued = 0;
        if let Some(w) = s.waker.take() {
            w.wake();
        }
    }
    /// Whether the queue stands at its high-water mark; if so, the host is being told (the
    /// stream is answered full), and it hears when the queue drains ([`Chan::take_writable`]).
    fn announce_full(&self) -> bool {
        let mut s = self.0.lock().expect("chan");
        let full = s.queued >= STREAM_HIGH_WATER;
        s.announced |= full;
        full
    }
    /// Whether a stream answered full has drained to its low-water mark: once per announcement.
    fn take_writable(&self) -> bool {
        let mut s = self.0.lock().expect("chan");
        let writable = s.announced && s.queued <= STREAM_LOW_WATER;
        if writable {
            s.announced = false;
        }
        writable
    }
    fn end(&self) {
        let mut s = self.0.lock().expect("chan");
        s.ended = true;
        if let Some(w) = s.waker.take() {
            w.wake();
        }
    }
    fn ended(&self) -> bool {
        self.0.lock().expect("chan").ended
    }
    /// The body was let go of before its end (see [`ChanState::gone`]).
    fn gone(&self) -> bool {
        self.0.lock().expect("chan").gone
    }
    /// Nobody will read this body again: drop what is queued and take no more.
    fn let_go(&self) {
        let mut s = self.0.lock().expect("chan");
        if !(s.ended && s.frames.is_empty()) {
            s.gone = true;
            s.frames.clear();
            s.queued = 0;
        }
    }
    fn body(&self) -> ChanBody {
        ChanBody(self.clone())
    }
}

/// A body whose frames the host hands in: data, then (on an answer) the trailers.
struct ChanBody(Chan);

impl Body for ChanBody {
    type Data = Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        let mut s = self.0 .0.lock().expect("chan");
        if s.reset {
            // The connection resets the stream on a body's error.
            return Poll::Ready(Some(Err(std::io::Error::other(OVER_BOUND))));
        }
        if let Some(f) = s.frames.pop_front() {
            if let Some(d) = f.data_ref() {
                s.queued -= d.len();
            }
            return Poll::Ready(Some(Ok(f)));
        }
        if s.ended {
            return Poll::Ready(None);
        }
        s.waker = Some(cx.waker().clone());
        Poll::Pending
    }
    fn is_end_stream(&self) -> bool {
        let s = self.0 .0.lock().expect("chan");
        s.ended && s.frames.is_empty()
    }
}

impl Drop for ChanBody {
    /// The connection drops a body it read to its end, or one whose stream the far end reset; the
    /// second is the one the host has to hear about.
    fn drop(&mut self) {
        self.0.let_go();
    }
}

// ── the connection ───────────────────────────────────────────────────────────────────────────────

/// One connection's gRPC machine.
pub struct Conn {
    io: HostIo,
    out: VecDeque<Piece>,
    conn_err: Arc<Mutex<Option<String>>>,
    conn_done: Arc<AtomicBool>,
    failed: Option<Failure>,
    posture: Posture,
    side: Side,
}

enum Side {
    Dial(Dial),
    Accept(Accept),
}

impl Owed for Conn {
    fn take_wire(&mut self, cap: usize) -> Vec<u8> {
        self.io.take_wire(cap)
    }
    fn wire_pending(&self) -> bool {
        self.io.wire_pending()
    }
    fn pieces(&mut self) -> &mut VecDeque<Piece> {
        &mut self.out
    }
    fn next_deadline(&self) -> Option<u64> {
        self.io.next_deadline()
    }
    fn ended(&self) -> bool {
        self.conn_done.load(Ordering::Acquire)
    }
}

fn watch<F>(
    exec: &impl Executor<BoxFut<()>>,
    conn: F,
    err: &Arc<Mutex<Option<String>>>,
    done: &Arc<AtomicBool>,
) where
    F: Future<Output = hyper::Result<()>> + Send + 'static,
{
    let (err, done) = (err.clone(), done.clone());
    exec.execute(Box::pin(async move {
        if let Err(e) = conn.await {
            *err.lock().expect("err") = Some(e.to_string());
        }
        done.store(true, Ordering::Release);
    }));
}

impl Conn {
    /// Open a dialled connection to `target` (an `http`/`https` URL: its scheme and authority are
    /// every call's), at host time `now_ns`.
    ///
    /// # Errors
    ///
    /// `target` is not a URL with a host.
    pub fn dial(target: &str, posture: Posture, now_ns: u64) -> Result<Self, Failure> {
        let uri: http::Uri = target
            .parse()
            .map_err(|_| Failure(format!("not a target: {target}")))?;
        let (Some(scheme), Some(authority)) = (uri.scheme(), uri.authority()) else {
            return Err(Failure(format!("not a target: {target}")));
        };
        let base = format!("{scheme}://{authority}");
        let io = HostIo::new(now_ns);
        let conn_err = Arc::new(Mutex::new(None));
        let conn_done = Arc::new(AtomicBool::new(false));
        let mut b = client::Builder::new(io.exec());
        b.timer(io.timer()).adaptive_window(posture.adaptive_window);
        if let Some(every) = posture.keep_alive_interval {
            b.keep_alive_interval(every)
                .keep_alive_timeout(posture.keep_alive_timeout);
        }
        let (exec, err, done, stream) =
            (io.exec(), conn_err.clone(), conn_done.clone(), io.stream());
        let handshake: BoxFut<hyper::Result<client::SendRequest<ChanBody>>> =
            Box::pin(async move {
                let (s, c) = b.handshake(stream).await?;
                watch(&exec, c, &err, &done);
                Ok(s)
            });
        Ok(Self {
            io,
            out: VecDeque::new(),
            conn_err,
            conn_done,
            failed: None,
            posture,
            side: Side::Dial(Dial {
                handshake: Some(handshake),
                sender: None,
                base,
                calls: Vec::new(),
                ended: Ended::default(),
                sign_at: None,
            }),
        })
    }

    /// This dialled connection's binding has an auth at the head (`BeginIn::points`): every
    /// stream's request is signed at `at` before its HEADERS go out (ruling 23). A no-op on an
    /// accepted connection.
    #[must_use]
    pub fn signing(mut self, at: SignAt) -> Self {
        if let Side::Dial(d) = &mut self.side {
            d.sign_at = Some(at);
        }
        self
    }

    /// Open an accepted connection, at host time `now_ns`.
    #[must_use]
    pub fn accept(posture: Posture, now_ns: u64) -> Self {
        let io = HostIo::new(now_ns);
        let conn_err = Arc::new(Mutex::new(None));
        let conn_done = Arc::new(AtomicBool::new(false));
        let arrivals = Arc::new(Mutex::new(Arrivals::default()));
        let svc_arrivals = arrivals.clone();
        let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
            let reply = Reply::default();
            {
                let mut a = svc_arrivals.lock().expect("arrivals");
                a.next += 1;
                let id = a.next;
                a.new.push_back((id, req, reply.clone()));
            }
            ReplyFut {
                reply,
                answered: false,
            }
        });
        let mut b = server::Builder::new(io.exec());
        b.timer(io.timer()).adaptive_window(posture.adaptive_window);
        let conn = b.serve_connection(io.stream(), svc);
        watch(&io.exec(), conn, &conn_err, &conn_done);
        Self {
            io,
            out: VecDeque::new(),
            conn_err,
            conn_done,
            failed: None,
            posture,
            side: Side::Accept(Accept {
                arrivals,
                calls: Vec::new(),
                #[cfg(test)]
                seen: Vec::new(),
            }),
        }
    }

    /// The far side sent `bytes` (`end` = and then ended).
    pub fn ingest(&mut self, bytes: &[u8], end: bool) {
        self.io.ingest(bytes, end);
    }

    /// Bytes for `stream` (`end` = they end the frame). `deadline_ns` is the attempt's deadline on
    /// a dialled stream's first `emit` (`0` = none stated), `now_ns` the host's time.
    ///
    /// # Errors
    ///
    /// No such accepted stream.
    pub fn emit(
        &mut self,
        stream: u64,
        bytes: &[u8],
        end: bool,
        deadline_ns: u64,
        now_ns: u64,
    ) -> Result<(), Failure> {
        // A connection whose binding has no auth never calls one.
        let mut unsigned =
            |_: &RequestHead<'_>, _: Option<&[u8]>| -> Poll<Result<Vec<AuthLine>, Failure>> {
                Poll::Ready(Err(Failure(
                    "the binding's auth has no caller on this emit".into(),
                )))
            };
        match self.emit_signed(stream, bytes, end, deadline_ns, now_ns, &mut unsigned) {
            Poll::Ready(r) => r,
            Poll::Pending => Ok(()),
        }
    }

    /// [`Conn::emit`] on a connection whose binding may have an auth at the head
    /// ([`Conn::signing`]): a dialled stream's request is built whole, `sign` is called over it
    /// exactly as it goes on the wire, and only then is it queued (ruling 23). [`Poll::Pending`]:
    /// the auth's answer is not ready; THIS STREAM parks (its bytes taken, its head built and
    /// kept, so the answer that comes back signs these bytes), every other stream on the
    /// connection keeps flowing, and the resumed `emit` on it (the same op, the same bytes)
    /// re-issues the same call.
    ///
    /// # Errors
    ///
    /// As [`Conn::emit`].
    pub fn emit_signed(
        &mut self,
        stream: u64,
        bytes: &[u8],
        end: bool,
        deadline_ns: u64,
        now_ns: u64,
        sign: Signer<'_>,
    ) -> Poll<Result<(), Failure>> {
        // A re-call after `YIELD_MORE` carries no new bytes, and the frame's end was taken with
        // the bytes: every step below is idempotent on it.
        let max = self.posture.max_message_bytes.saturating_add(64 * 1024);
        // A host that keeps emitting past the high-water mark (one whole message more) has the
        // stream failed: the framer bounds what it holds for a far end that is not reading.
        let bound = STREAM_HIGH_WATER.saturating_add(max);
        match &mut self.side {
            Side::Dial(d) => {
                if d.ended.contains(stream) {
                    // LATE: the stream already ended (an early answer, a failure, its deadline).
                    // Its terminal piece is out; these bytes have nowhere to go.
                    return Poll::Ready(Ok(()));
                }
                let timer = self.io.timer();
                let fallback = now_ns.saturating_add(
                    u64::try_from(self.posture.timeout.as_nanos()).unwrap_or(u64::MAX),
                );
                let idx = match d.calls.iter().position(|(s, _)| *s == stream) {
                    Some(i) => i,
                    None => {
                        let at = if deadline_ns == 0 {
                            fallback
                        } else {
                            deadline_ns
                        };
                        d.calls
                            .push((stream, DialStream::new(at, timer.sleep_until_ns(at))));
                        d.calls.len() - 1
                    }
                };
                let base = d.base.clone();
                let at = d.sign_at;
                let s = &mut d.calls[idx].1;
                let taken = match s.take(&base, bytes, end, now_ns, max, at, sign) {
                    // PARKED: this stream alone waits for its auth's answer.
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(taken) => taken,
                };
                if let Err((why, code)) = taken {
                    s.stage = DStage::Done;
                    self.out.push_back(Piece {
                        status: Some(code),
                        ..Piece::failure(stream, &why)
                    });
                } else if s.chan.queued() > bound {
                    // Reset, never ended: the far end must not take the cut upload for a whole one.
                    s.chan.reset();
                    s.stage = DStage::Done;
                    self.out.push_back(Piece {
                        status: Some(msg::RESOURCE_EXHAUSTED),
                        ..Piece::failure(stream, OVER_BOUND)
                    });
                }
                d.sweep();
                Poll::Ready(Ok(()))
            }
            Side::Accept(a) => {
                let Some((_, s)) = a.calls.iter_mut().find(|(s, _)| *s == stream) else {
                    return Poll::Ready(Err(Failure(format!("no such stream: {stream}"))));
                };
                if bytes.is_empty() || s.reply_over {
                    return Poll::Ready(Ok(()));
                }
                if !s.head_sent {
                    s.head_buf.extend_from_slice(bytes);
                    match msg::read_head(&s.head_buf, max) {
                        Ok(None) => return Poll::Ready(Ok(())),
                        Err(why) => {
                            s.fail_reply(msg::INTERNAL, why.as_bytes());
                            // The stream ends once, and the host learns it, as the over-bound
                            // branch below tells it.
                            self.out.push_back(Piece {
                                status: Some(msg::INTERNAL),
                                ..Piece::failure(stream, &why)
                            });
                            return Poll::Ready(Ok(()));
                        }
                        Ok(Some((head, took))) => {
                            let rest = s.head_buf.split_off(took);
                            s.head_buf.clear();
                            s.send_head(&head, None);
                            if !rest.is_empty() {
                                s.reply.chan.push(Frame::data(Bytes::from(rest)));
                            }
                        }
                    }
                } else {
                    s.reply
                        .chan
                        .push(Frame::data(Bytes::copy_from_slice(bytes)));
                }
                if s.reply.chan.queued() > bound {
                    s.reply.chan.drop_queued();
                    s.body = None;
                    s.fail_reply(msg::RESOURCE_EXHAUSTED, OVER_BOUND.as_bytes());
                    self.out.push_back(Piece {
                        status: Some(msg::RESOURCE_EXHAUSTED),
                        ..Piece::failure(stream, OVER_BOUND)
                    });
                }
                Poll::Ready(Ok(()))
            }
        }
    }

    /// Whether `stream`'s queue stands at its high-water mark after an `emit`: the answer is then
    /// `YIELD_STREAM_FULL`, and the stream hands a writable piece once it drains to its low-water
    /// mark (the transport ABI's "A STREAM'S OWN BACKPRESSURE").
    #[must_use]
    pub fn announce_full(&self, stream: u64) -> bool {
        match &self.side {
            Side::Dial(d) => d
                .calls
                .iter()
                .find(|(id, _)| *id == stream)
                .is_some_and(|(_, s)| !s.over() && s.chan.announce_full()),
            Side::Accept(a) => a
                .calls
                .iter()
                .find(|(id, _)| *id == stream)
                .is_some_and(|(_, s)| !s.reply_over && s.reply.chan.announce_full()),
        }
    }

    /// End accepted `stream` with `trailers` (a block of `name: value` lines). A block that does
    /// not state `grpc-status` ends the call with the refusal's neutral `status` mapped
    /// ([`msg::status_of_refusal`], with [`msg::refusal_message`]); with no status stated either
    /// (`0`), `UNKNOWN` with the bytes as its message.
    ///
    /// # Errors
    ///
    /// This is a dialled connection, or no such stream.
    pub fn end_call(&mut self, stream: u64, trailers: &[u8], status: u32) -> Result<(), Failure> {
        let Side::Accept(a) = &mut self.side else {
            return Err(Failure("a dialled call is not answered".into()));
        };
        let Some((_, s)) = a.calls.iter_mut().find(|(s, _)| *s == stream) else {
            return Err(Failure(format!("no such stream: {stream}")));
        };
        if s.reply_over {
            return Ok(());
        }
        let mut block = trailers.to_vec();
        if !block.ends_with(b"\r\n\r\n") {
            if !block.ends_with(b"\r\n") && !block.is_empty() {
                block.extend_from_slice(b"\r\n");
            }
            block.extend_from_slice(b"\r\n");
        }
        match msg::read_head(&block, usize::MAX) {
            Ok(Some((h, _))) if h.get(msg::GRPC_STATUS).is_some() => s.finish(&h),
            _ if status != 0 => s.fail_reply(
                msg::status_of_refusal(status),
                msg::refusal_message(status).as_bytes(),
            ),
            _ => s.fail_reply(msg::UNKNOWN, trailers),
        }
        Ok(())
    }

    /// Drive the connection at host time `now_ns` until nothing inside it has more to do.
    pub fn drive(&mut self, now_ns: u64) {
        self.io.set_time(now_ns);
        if self.failed.is_some() {
            return;
        }
        let io = self.io.clone();
        let max = self.posture.max_message_bytes;
        let r = io.rounds(|cx| match &mut self.side {
            Side::Dial(d) => d.step(&mut self.out, max, cx),
            Side::Accept(a) => {
                a.step(&mut self.out, max, &io, cx);
                Ok(())
            }
        });
        if let Err(f) = r {
            self.failed = Some(f);
            return;
        }
        let err = self.conn_err.lock().expect("err").clone();
        if let Some(e) = err {
            let busy = match &self.side {
                Side::Dial(d) => !d.calls.is_empty(),
                Side::Accept(_) => false,
            };
            if busy {
                self.failed = Some(Failure(e));
            }
        }
    }

    /// Every request an accepted connection's far end sent, as HTTP/2 decoded it off the wire.
    #[cfg(test)]
    pub(crate) fn seen(&self) -> &[(http::Method, http::Uri, HeaderMap)] {
        match &self.side {
            Side::Accept(a) => &a.seen,
            Side::Dial(_) => &[],
        }
    }

    /// Why this framing failed, once it has.
    #[must_use]
    pub fn failure(&self) -> Option<&Failure> {
        self.failed.as_ref()
    }
}

// ── the dialled side ─────────────────────────────────────────────────────────────────────────────

struct Dial {
    handshake: Option<BoxFut<hyper::Result<client::SendRequest<ChanBody>>>>,
    sender: Option<client::SendRequest<ChanBody>>,
    base: String,
    calls: Vec<(u64, DialStream)>,
    /// Streams that have ended (their terminal piece is out). An `emit` on one is late and is
    /// dropped: it never opens a second call under the same stream.
    ended: Ended,
    /// Where the binding's auth signs each stream's request; `None` = the binding has none.
    sign_at: Option<SignAt>,
}

/// A set of stream ids kept as runs: `start -> end` (inclusive) for each run of consecutive ids. A
/// host that numbers a connection's streams in order (the connector's lines do) leaves one run, so
/// remembering every ended stream costs nothing per call.
#[derive(Default)]
struct Ended(std::collections::BTreeMap<u64, u64>);

impl Ended {
    fn contains(&self, id: u64) -> bool {
        self.0
            .range(..=id)
            .next_back()
            .is_some_and(|(_, &end)| id <= end)
    }

    fn insert(&mut self, id: u64) {
        if self.contains(id) {
            return;
        }
        let before = self
            .0
            .range(..id)
            .next_back()
            .filter(|(_, &end)| end.checked_add(1) == Some(id))
            .map(|(&start, _)| start);
        let after = id
            .checked_add(1)
            .and_then(|next| self.0.get(&next).copied().map(|end| (next, end)));
        let start = before.unwrap_or(id);
        let end = match after {
            Some((next, end)) => {
                self.0.remove(&next);
                end
            }
            None => id,
        };
        self.0.insert(start, end);
    }
}

impl Dial {
    /// Drop the streams that are over, remembering each one's id.
    fn sweep(&mut self) {
        let ended = &mut self.ended;
        self.calls.retain(|(id, s)| {
            if s.over() {
                ended.insert(*id);
            }
            !s.over()
        });
    }
}

enum DStage {
    /// The head block, still arriving.
    Head(Vec<u8>),
    /// The request built whole, waiting for the binding's auth (ruling 23).
    Signing(Box<Signing>),
    /// A request, waiting for the connection to take it.
    Queued(Request<ChanBody>),
    /// Sent; waiting for the answer's head.
    Asked(BoxFut<hyper::Result<Response<Incoming>>>),
    /// The answer's messages.
    Body(Incoming, Messages),
    /// Answered in full, or failed.
    Done,
}

/// A dialled stream's request, built whole and waiting for its binding's auth: the head exactly as
/// it goes on the wire, and the body taken meanwhile.
struct Signing {
    /// `:scheme`, `:authority` and `:path` (with its query).
    uri: http::Uri,
    /// Every other line, in the order the HEADERS frame carries them.
    lines: HeaderMap,
    /// The body taken while the head waits (at [`SignAt::HeadBody`], the whole of it).
    body: Vec<u8>,
    /// The body is whole: its stated length is in, or a frame ended a body of none.
    whole: bool,
    /// The auth's answer pended: the next `emit` on this stream is the op's resume, re-issuing the
    /// same call; its bytes were taken already.
    parked: bool,
}

struct DialStream {
    stage: DStage,
    chan: Chan,
    /// Bytes of the message stream still to come, when the head stated its length.
    left: Option<usize>,
    deadline_ns: u64,
    sleep: Pin<Box<dyn Sleep>>,
}

/// THE OPENING BODY'S LENGTH, where the emit carrying the head states it: the one place the
/// framer reads it. The head block's `content-length` (`encode` writes the length of the message
/// stream it renders); a streamed body states none.
fn body_len(head: &Head) -> Option<usize> {
    head.content_length
}

impl DialStream {
    fn new(deadline_ns: u64, sleep: Pin<Box<dyn Sleep>>) -> Self {
        Self {
            stage: DStage::Head(Vec::new()),
            chan: Chan::default(),
            left: None,
            deadline_ns,
            sleep,
        }
    }

    fn over(&self) -> bool {
        matches!(self.stage, DStage::Done)
    }

    /// Take `bytes` the host emitted on this stream. With `at` (the binding's auth at the head),
    /// the request's HEADERS wait for `sign`'s answer; [`Poll::Pending`] parks this stream.
    #[allow(clippy::too_many_arguments)]
    fn take(
        &mut self,
        base: &str,
        bytes: &[u8],
        end: bool,
        now_ns: u64,
        max: usize,
        at: Option<SignAt>,
        sign: Signer<'_>,
    ) -> Poll<Result<(), StreamFault>> {
        let body: Vec<u8> = match &mut self.stage {
            DStage::Head(buf) => {
                buf.extend_from_slice(bytes);
                let read = match msg::read_head(buf, max) {
                    Ok(read) => read,
                    Err(why) => return Poll::Ready(Err(internal(why))),
                };
                let Some((head, took)) = read else {
                    if end {
                        return Poll::Ready(Err(internal("the frame ended inside the head block")));
                    }
                    return Poll::Ready(Ok(()));
                };
                let rest = buf.split_off(took);
                let (uri, lines) = match self.head_lines(base, &head, now_ns) {
                    Ok(built) => built,
                    Err(why) => return Poll::Ready(Err(internal(why))),
                };
                self.left = body_len(&head);
                let Some(at) = at else {
                    self.stage = DStage::Queued(self.request(uri, lines));
                    return Poll::Ready(self.queue(rest, end));
                };
                self.stage = DStage::Signing(Box::new(Signing {
                    uri,
                    lines,
                    body: Vec::new(),
                    whole: false,
                    parked: false,
                }));
                if let Err(fault) = self.hold(&rest, end, max) {
                    return Poll::Ready(Err(fault));
                }
                return self.sign(at, sign);
            }
            DStage::Signing(s) => {
                // A PARKED stream's emit is its op's resume: the same bytes, taken already.
                if !s.parked {
                    if let Err(fault) = self.hold(bytes, end, max) {
                        return Poll::Ready(Err(fault));
                    }
                }
                return self.sign(at.unwrap_or(SignAt::Head), sign);
            }
            DStage::Done => return Poll::Ready(Ok(())),
            _ => bytes.to_vec(),
        };
        Poll::Ready(self.queue(body, end))
    }

    /// Queue body bytes for the far end, counting them against the head's stated length; the
    /// last one ends the request.
    fn queue(&mut self, body: Vec<u8>, end: bool) -> Result<(), StreamFault> {
        if !body.is_empty() {
            if let Some(left) = self.left.as_mut() {
                if body.len() > *left {
                    return Err(internal(
                        "more message bytes than the head's content-length",
                    ));
                }
                *left -= body.len();
            }
            self.chan.push(Frame::data(Bytes::from(body)));
        }
        if self.left == Some(0) || (end && self.left.is_none()) {
            // The request's last byte: END_STREAM follows it.
            self.chan.end();
        }
        Ok(())
    }

    /// Hold body bytes that arrive while the head waits for its auth, counted as [`Self::queue`]
    /// counts them, and bounded: a body the auth signs is held whole.
    fn hold(&mut self, bytes: &[u8], end: bool, max: usize) -> Result<(), StreamFault> {
        let DStage::Signing(s) = &mut self.stage else {
            return Ok(());
        };
        if let Some(left) = self.left.as_mut() {
            if bytes.len() > *left {
                return Err(internal(
                    "more message bytes than the head's content-length",
                ));
            }
            *left -= bytes.len();
        }
        s.body.extend_from_slice(bytes);
        if s.body.len() > max {
            return Err((
                "the body the binding's auth signs is past its bound".into(),
                msg::RESOURCE_EXHAUSTED,
            ));
        }
        s.whole |= self.left == Some(0) || (end && self.left.is_none());
        Ok(())
    }

    /// CALL THE BINDING'S AUTH over the request as built (ruling 23): once the body it signs is
    /// whole, over exactly the lines HTTP/2 encodes; its answer joins the head
    /// ([`signed_request`]) and the request is queued, the body held meanwhile behind it. Nothing
    /// is added after. A pending answer parks this stream; a stop, a refusal, or an answer the
    /// request cannot carry fails it, and its HEADERS never go out.
    fn sign(&mut self, at: SignAt, sign: Signer<'_>) -> Poll<Result<(), StreamFault>> {
        let DStage::Signing(s) = &mut self.stage else {
            return Poll::Ready(Ok(()));
        };
        if at == SignAt::HeadBody && !s.whole {
            // The auth signs the whole body: the head waits for the rest of it.
            return Poll::Ready(Ok(()));
        }
        let called = {
            let fields: Vec<(&str, &[u8])> = s
                .lines
                .iter()
                .map(|(n, v)| (n.as_str(), v.as_bytes()))
                .collect();
            let head = RequestHead {
                method: "POST",
                target: s.uri.path(),
                query: s.uri.query(),
                authority: s.uri.authority().map_or("", http::uri::Authority::as_str),
                fields: &fields,
            };
            let body = (at == SignAt::HeadBody).then_some(s.body.as_slice());
            sign(&head, body)
        };
        let answer = match called {
            Poll::Pending => {
                s.parked = true;
                return Poll::Pending;
            }
            Poll::Ready(Err(Failure(why))) => {
                return Poll::Ready(Err((why, msg::UNAUTHENTICATED)));
            }
            Poll::Ready(Ok(answer)) => answer,
        };
        let (uri, lines) = match signed_request(&s.uri, &s.lines, &answer) {
            Ok(signed) => signed,
            Err(why) => return Poll::Ready(Err(internal(why))),
        };
        let held = std::mem::take(&mut s.body);
        let whole = s.whole;
        self.stage = DStage::Queued(self.request(uri, lines));
        if !held.is_empty() {
            self.chan.push(Frame::data(Bytes::from(held)));
        }
        if whole {
            // The request's last byte: END_STREAM follows it.
            self.chan.end();
        }
        Poll::Ready(Ok(()))
    }

    /// The request's target and lines, gRPC's own first, as HTTP/2 encodes them.
    fn head_lines(
        &self,
        base: &str,
        head: &Head,
        now_ns: u64,
    ) -> Result<(http::Uri, HeaderMap), String> {
        let path = head.get("path").ok_or("the head names no path")?;
        if !path.starts_with(b"/") {
            return Err("the head's path is not absolute".into());
        }
        let uri: http::Uri = format!("{base}{}", String::from_utf8_lossy(path))
            .parse()
            .map_err(|_| "request: the head's path is not a target")?;
        let content_type = match head.get("content-type") {
            Some(ct) if msg::is_grpc_content_type(ct) => {
                HeaderValue::from_bytes(ct).map_err(|_| "content-type is not a field value")?
            }
            Some(_) => return Err("content-type is not a gRPC content type".into()),
            None => HeaderValue::from_static(msg::CONTENT_TYPE),
        };
        let mut lines = HeaderMap::new();
        lines.append(http::header::CONTENT_TYPE, content_type);
        lines.append(http::header::TE, HeaderValue::from_static("trailers"));
        let left = Duration::from_nanos(self.deadline_ns.saturating_sub(now_ns));
        lines.append(
            msg::GRPC_TIMEOUT,
            HeaderValue::from_str(&msg::timeout_value(left))
                .map_err(|_| "grpc-timeout is not a field value")?,
        );
        for (name, value) in &head.fields {
            if RESERVED_ON_REQUEST.contains(&name.as_str()) || hop_by_hop(name, []) {
                continue;
            }
            let n = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| format!("`{name}` is not a field name"))?;
            let v = HeaderValue::from_bytes(value)
                .map_err(|_| format!("`{name}`'s value is not a field value"))?;
            lines.append(n, v);
        }
        Ok((uri, lines))
    }

    /// The request HTTP/2 encodes: `:method` `POST`, `:scheme`, `:authority` and `:path` from
    /// `uri`, then `lines` in their order, and nothing else.
    fn request(&self, uri: http::Uri, lines: HeaderMap) -> Request<ChanBody> {
        let mut req = Request::new(self.chan.body());
        *req.method_mut() = http::Method::POST;
        *req.uri_mut() = uri;
        *req.version_mut() = http::Version::HTTP_2;
        *req.headers_mut() = lines;
        req
    }
}

/// Fields this layer owns on a request, beside the hop-by-hop ones HTTP/2 forbids: a head block's
/// own are dropped.
const RESERVED_ON_REQUEST: &[&str] = &[
    "path",
    "method",
    "authority",
    "content-type",
    msg::GRPC_TIMEOUT,
    "content-length",
    "host",
];

/// Whether an auth's answer may carry a field line of `name` (lowercase): never one of gRPC's own
/// (its pseudo-fields, `content-type`, `te`, a `grpc-` line), nor one HTTP/2 forbids.
fn auth_may_carry(name: &str) -> bool {
    !(name.starts_with(':')
        || name == "te"
        || name.starts_with("grpc-")
        || RESERVED_ON_REQUEST.contains(&name)
        || hop_by_hop(name, []))
}

/// A query key or value an auth answered: visible ASCII that neither ends the path (`#`, a space)
/// nor splits its pairs (`&`); a key carries no `=` and is not empty.
fn query_safe(bytes: &[u8], key: bool) -> bool {
    (!key || !bytes.is_empty())
        && bytes
            .iter()
            .all(|&b| b.is_ascii_graphic() && b != b'#' && b != b'&' && !(key && b == b'='))
}

/// THE SIGNED REQUEST (ruling 23): `uri` and `lines` are the request exactly as the auth was
/// called over it; each field line it answers goes FIRST among the field lines (the 1.5.5 HTTP/2
/// egress head's order, `egress.auth__h2__bearer`: the pseudo-fields, the auth's lines, then the
/// rest), replacing every line of the same name; each query key it answers joins the path's query,
/// replacing any pair of the same key. Nothing else is added. A line or key the request cannot
/// carry refuses the stream.
fn signed_request(
    uri: &http::Uri,
    lines: &HeaderMap,
    answer: &[AuthLine],
) -> Result<(http::Uri, HeaderMap), String> {
    let cannot =
        |what: &str| format!("the binding's auth answered {what} the request cannot carry");
    let mut signed = HeaderMap::new();
    let mut keys: Vec<(&str, &[u8])> = Vec::new();
    for line in answer {
        if line.query {
            if !query_safe(line.name.as_bytes(), true) || !query_safe(&line.value, false) {
                return Err(cannot("a query key"));
            }
            keys.push((line.name.as_str(), line.value.as_slice()));
            continue;
        }
        let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(line.name.as_bytes()),
            HeaderValue::from_bytes(&line.value),
        ) else {
            return Err(cannot("a line"));
        };
        if !auth_may_carry(name.as_str()) {
            return Err(cannot("a line of gRPC's own"));
        }
        signed.append(name, value);
    }
    for (name, value) in lines {
        let replaced = answer
            .iter()
            .any(|l| !l.query && l.name.eq_ignore_ascii_case(name.as_str()));
        if !replaced {
            signed.append(name.clone(), value.clone());
        }
    }
    if keys.is_empty() {
        return Ok((uri.clone(), signed));
    }
    let mut target = uri.path().to_owned();
    let mut sep = '?';
    for pair in uri.query().into_iter().flat_map(|q| q.split('&')) {
        let key = pair.split('=').next().unwrap_or(pair);
        if keys.iter().any(|(k, _)| *k == key) {
            continue;
        }
        target.push(sep);
        target.push_str(pair);
        sep = '&';
    }
    for (key, value) in &keys {
        target.push(sep);
        target.push_str(key);
        target.push('=');
        target.push_str(&String::from_utf8_lossy(value));
        sep = '&';
    }
    let mut parts = uri.clone().into_parts();
    parts.path_and_query = Some(
        target
            .parse::<http::uri::PathAndQuery>()
            .map_err(|_| cannot("a query key"))?,
    );
    let uri = http::Uri::from_parts(parts).map_err(|_| cannot("a query key"))?;
    Ok((uri, signed))
}

impl Dial {
    fn step(
        &mut self,
        out: &mut VecDeque<Piece>,
        max: usize,
        cx: &mut Context<'_>,
    ) -> Result<(), Failure> {
        if let Some(h) = self.handshake.as_mut() {
            if let Poll::Ready(r) = h.as_mut().poll(cx) {
                self.handshake = None;
                self.sender = Some(r.map_err(|e| Failure(e.to_string()))?);
            }
        }
        for (id, s) in &mut self.calls {
            if let Err((why, code, conn)) = advance(*id, s, &mut self.sender, out, max, cx) {
                if conn {
                    return Err(Failure(why));
                }
                s.stage = DStage::Done;
                out.push_back(Piece {
                    status: Some(code),
                    ..Piece::failure(*id, &why)
                });
            } else if !s.over() && s.chan.take_writable() {
                out.push_back(Piece::writable(*id));
            }
        }
        self.sweep();
        Ok(())
    }
}

/// Move one dialled stream as far as it goes this round. `Err((why, code, true))` is the
/// connection's failure (the sender refused), `Err((why, code, false))` the stream's own.
fn advance(
    id: u64,
    s: &mut DialStream,
    sender: &mut Option<client::SendRequest<ChanBody>>,
    out: &mut VecDeque<Piece>,
    max: usize,
    cx: &mut Context<'_>,
) -> Result<(), (String, u16, bool)> {
    if !s.over() && s.sleep.as_mut().poll(cx).is_ready() {
        // Dropping the exchange resets the stream on the wire.
        return Err(("deadline exceeded".into(), msg::DEADLINE_EXCEEDED, false));
    }
    loop {
        match &mut s.stage {
            DStage::Head(_) | DStage::Signing(_) | DStage::Done => return Ok(()),
            DStage::Queued(_) => {
                let Some(snd) = sender.as_mut() else {
                    return Ok(());
                };
                match snd.poll_ready(cx) {
                    Poll::Pending => return Ok(()),
                    Poll::Ready(r) => r.map_err(|e| (e.to_string(), msg::UNAVAILABLE, true))?,
                }
                let DStage::Queued(req) = std::mem::replace(&mut s.stage, DStage::Done) else {
                    unreachable!("matched above")
                };
                s.stage = DStage::Asked(Box::pin(snd.send_request(req)));
            }
            DStage::Asked(f) => match f.as_mut().poll(cx) {
                Poll::Pending => return Ok(()),
                Poll::Ready(r) => {
                    let r = r.map_err(|e| (e.to_string(), msg::UNAVAILABLE, false))?;
                    if r.status() != StatusCode::OK {
                        // A BARE HTTP STATUS IS AN ANSWER: a member (or a proxy or auth wall in
                        // front of it) answered the call without gRPC. Its status is the gRPC
                        // status that HTTP status stands for (`http-grpc-status-mapping.md`),
                        // handed up as a trailers-only answer is: the head, then the status
                        // block and its text. A failed stream would read as no answer at all,
                        // and a member refusing its credential would never trip hard.
                        let code = r.status().as_u16();
                        out.push_back(Piece::fields(
                            id,
                            Bytes::from(field_block(r.headers(), STATUS_FIELDS)),
                        ));
                        let mut status = HeaderMap::new();
                        status.insert(
                            msg::GRPC_STATUS,
                            HeaderValue::from(msg::status_of_http(code)),
                        );
                        status.insert(
                            msg::GRPC_MESSAGE,
                            HeaderValue::from_str(&format!("HTTP status {code}"))
                                .expect("digits and spaces are a field value"),
                        );
                        // Its fault is the HTTP status's own reading (1.5.5's bands), not the
                        // mapped code's: a bare 400 maps to INTERNAL but is the caller's.
                        let [block, text] = trailers(id, &HeaderMap::new(), &status);
                        out.push_back(Piece {
                            fault: Some(crate::meta::fault_of_http(code)),
                            ..block
                        });
                        out.push_back(text);
                        s.stage = DStage::Done;
                        return Ok(());
                    }
                    let ct = r.headers().get(http::header::CONTENT_TYPE);
                    if !ct.is_some_and(|v| msg::is_grpc_content_type(v.as_bytes())) {
                        return Err(("the answer is not gRPC".into(), msg::UNKNOWN, false));
                    }
                    out.push_back(Piece::fields(
                        id,
                        Bytes::from(field_block(r.headers(), STATUS_FIELDS)),
                    ));
                    if r.headers().contains_key(msg::GRPC_STATUS) {
                        // Trailers-only: the status is in the head, and the body is empty.
                        out.extend(trailers(id, &HeaderMap::new(), r.headers()));
                        s.stage = DStage::Done;
                        return Ok(());
                    }
                    s.stage = DStage::Body(r.into_body(), Messages::new(max));
                }
            },
            DStage::Body(b, msgs) => match Pin::new(&mut *b).poll_frame(cx) {
                Poll::Pending => return Ok(()),
                Poll::Ready(Some(Err(e))) => return Err((e.to_string(), msg::INTERNAL, false)),
                Poll::Ready(Some(Ok(fr))) => match fr.into_data() {
                    Ok(d) => {
                        let got = msgs
                            .push(&d)
                            .map_err(|e| (e.to_string(), e.status(), false))?;
                        out.extend(got.into_iter().map(|m| Piece::data(id, m)));
                    }
                    Err(other) => {
                        if let Ok(t) = other.into_trailers() {
                            msgs.end()
                                .map_err(|e| (e.to_string(), msg::INTERNAL, false))?;
                            out.extend(trailers(id, &t, &t));
                            s.stage = DStage::Done;
                            return Ok(());
                        }
                    }
                },
                Poll::Ready(None) => {
                    return Err((
                        "the answer ended without a grpc-status".into(),
                        msg::UNKNOWN,
                        false,
                    ))
                }
            },
        }
    }
}

/// The fields the trailers' code and the terminal piece carry, never a field block's.
const STATUS_FIELDS: &[&str] = &[msg::GRPC_STATUS, msg::GRPC_MESSAGE];

/// The stream's end, from the fields that carry `grpc-status` (`status`): the trailers (`fields`
/// as a field block, its code the status), then the terminal piece — empty on `OK`, else the
/// failure whose bytes are the decoded `grpc-message`.
fn trailers(id: u64, fields: &HeaderMap, status: &HeaderMap) -> [Piece; 2] {
    let code = status
        .get(msg::GRPC_STATUS)
        .map_or(msg::UNKNOWN, |v| msg::parse_status(v.as_bytes()));
    let block = Piece {
        status: Some(code),
        ..Piece::fields(id, Bytes::from(field_block(fields, STATUS_FIELDS)))
    };
    if code == msg::OK {
        return [block, Piece::end(id)];
    }
    let text = status
        .get(msg::GRPC_MESSAGE)
        .map(|v| msg::decode_message(v.as_bytes()))
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| format!("grpc-status {code}").into_bytes());
    [
        block,
        Piece {
            failed: true,
            ..Piece::data(id, Bytes::from(text))
        },
    ]
}

// ── the accepted side ────────────────────────────────────────────────────────────────────────────

#[derive(Default)]
struct Arrivals {
    next: u64,
    new: VecDeque<(u64, Request<Incoming>, Reply)>,
}

#[derive(Default)]
struct ReplyState {
    head: Option<(StatusCode, HeaderMap)>,
    waker: Option<Waker>,
}

/// The answer to one accepted call: its head once the host states it, and its body.
#[derive(Clone, Default)]
struct Reply {
    state: Arc<Mutex<ReplyState>>,
    chan: Chan,
}

impl Reply {
    fn head(&self, status: StatusCode, fields: HeaderMap) {
        let mut s = self.state.lock().expect("reply");
        s.head = Some((status, fields));
        if let Some(w) = s.waker.take() {
            w.wake();
        }
    }
}

/// The service's answer: ready once the host has stated the head.
struct ReplyFut {
    reply: Reply,
    /// The head went out, and the body with it: from here the body says when it is let go of.
    answered: bool,
}

impl Future for ReplyFut {
    type Output = Result<Response<ChanBody>, Infallible>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut s = self.reply.state.lock().expect("reply");
        let Some((status, fields)) = s.head.take() else {
            s.waker = Some(cx.waker().clone());
            return Poll::Pending;
        };
        drop(s);
        let mut r = Response::new(self.reply.chan.body());
        *r.status_mut() = status;
        *r.headers_mut() = fields;
        self.answered = true;
        Poll::Ready(Ok(r))
    }
}

impl Drop for ReplyFut {
    /// Dropped before the head went out: the far end reset the call while the host was still
    /// working on it.
    fn drop(&mut self) {
        if !self.answered {
            self.reply.chan.let_go();
        }
    }
}

struct Accept {
    arrivals: Arc<Mutex<Arrivals>>,
    calls: Vec<(u64, AStream)>,
    /// Every request the far end sent, as HTTP/2 decoded it off the wire: method, URI and every
    /// field line in order (a test reads what a dialled head carried).
    #[cfg(test)]
    seen: Vec<(http::Method, http::Uri, HeaderMap)>,
}

struct AStream {
    /// The call's messages; `None` once the far end has sent its last.
    body: Option<(Incoming, Messages)>,
    reply: Reply,
    content_type: HeaderValue,
    head_buf: Vec<u8>,
    head_sent: bool,
    reply_over: bool,
    sleep: Option<Pin<Box<dyn Sleep>>>,
}

impl AStream {
    fn send_head(&mut self, head: &Head, trailers: Option<&Head>) {
        let mut fields = HeaderMap::new();
        fields.insert(http::header::CONTENT_TYPE, self.content_type.clone());
        for h in std::iter::once(head).chain(trailers) {
            for (name, value) in &h.fields {
                if RESERVED_ON_ANSWER.contains(&name.as_str()) || hop_by_hop(name, []) {
                    continue;
                }
                if let (Ok(n), Ok(v)) = (
                    HeaderName::from_bytes(name.as_bytes()),
                    HeaderValue::from_bytes(value),
                ) {
                    fields.append(n, v);
                }
            }
        }
        self.head_sent = true;
        self.reply.head(StatusCode::OK, fields);
    }

    fn finish(&mut self, trailers: &Head) {
        if self.head_sent {
            let mut map = HeaderMap::new();
            for (name, value) in &trailers.fields {
                if let (Ok(n), Ok(v)) = (
                    HeaderName::from_bytes(name.as_bytes()),
                    HeaderValue::from_bytes(value),
                ) {
                    map.append(n, v);
                }
            }
            self.reply.chan.push(Frame::trailers(map));
        } else {
            // Trailers-only: one HEADERS frame carrying the status, and END_STREAM.
            self.send_head(&Head::default(), Some(trailers));
        }
        self.reply.chan.end();
        self.reply_over = true;
    }

    fn fail_reply(&mut self, code: u16, why: &[u8]) {
        self.finish(&Head {
            fields: vec![
                (msg::GRPC_STATUS.into(), code.to_string().into_bytes()),
                (
                    msg::GRPC_MESSAGE.into(),
                    msg::encode_status_message(why).into_bytes(),
                ),
            ],
            content_length: None,
        });
    }
}

/// Fields this layer owns on an answer's head, beside the hop-by-hop ones.
const RESERVED_ON_ANSWER: &[&str] = &["content-type", "content-length"];

impl Accept {
    fn step(&mut self, out: &mut VecDeque<Piece>, max: usize, io: &HostIo, cx: &mut Context<'_>) {
        let new: Vec<_> = self
            .arrivals
            .lock()
            .expect("arrivals")
            .new
            .drain(..)
            .collect();
        for (id, req, reply) in new {
            #[cfg(test)]
            self.seen.push((
                req.method().clone(),
                req.uri().clone(),
                req.headers().clone(),
            ));
            let ct = req.headers().get(http::header::CONTENT_TYPE).cloned();
            let Some(ct) = ct.filter(|v| msg::is_grpc_content_type(v.as_bytes())) else {
                // Not a gRPC call: answered here, never handed up.
                reply.head(StatusCode::UNSUPPORTED_MEDIA_TYPE, HeaderMap::new());
                reply.chan.end();
                continue;
            };
            let target = req.uri().path_and_query().map_or("/", |p| p.as_str());
            let words = HeadWords {
                method: Bytes::copy_from_slice(req.method().as_str().as_bytes()),
                target: Bytes::copy_from_slice(target.as_bytes()),
                authority: req.uri().authority().map_or_else(Bytes::new, |a| {
                    Bytes::copy_from_slice(a.as_str().as_bytes())
                }),
                reason: Bytes::new(),
            };
            let sleep = req
                .headers()
                .get(msg::GRPC_TIMEOUT)
                .and_then(|v| msg::parse_timeout(v.as_bytes()))
                .map(|d| {
                    let now = io.timer().now_ns();
                    io.timer().sleep_until_ns(
                        now.saturating_add(u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)),
                    )
                });
            out.push_back(Piece {
                head: Some(words),
                ..Piece::fields(id, Bytes::from(field_block(req.headers(), &[])))
            });
            self.calls.push((
                id,
                AStream {
                    body: Some((req.into_body(), Messages::new(max))),
                    reply,
                    content_type: ct,
                    head_buf: Vec::new(),
                    head_sent: false,
                    reply_over: false,
                    sleep,
                },
            ));
        }
        for (id, s) in &mut self.calls {
            if !s.reply_over && s.reply.chan.gone() {
                // THE FAR END CANCELLED THE CALL: it reset the stream, and the connection let go
                // of the answer. Before the far end's last message its body says so too; after it
                // (a call the far end half-closed, then cancelled) this is the only sign, and the
                // host must hear it or it keeps answering into a stream nobody reads.
                s.body = None;
                s.reply_over = true;
                s.reply.chan.end();
                out.push_back(Piece {
                    status: Some(msg::CANCELLED),
                    ..Piece::failure(*id, "the far end cancelled the call")
                });
                continue;
            }
            if !s.reply_over {
                if let Some(sl) = s.sleep.as_mut() {
                    if sl.as_mut().poll(cx).is_ready() {
                        s.sleep = None;
                        s.fail_reply(msg::DEADLINE_EXCEEDED, b"deadline exceeded");
                        s.body = None;
                        out.push_back(Piece {
                            status: Some(msg::DEADLINE_EXCEEDED),
                            ..Piece::failure(*id, "deadline exceeded")
                        });
                        continue;
                    }
                }
            }
            while let Some((b, msgs)) = s.body.as_mut() {
                match Pin::new(&mut *b).poll_frame(cx) {
                    Poll::Pending => break,
                    Poll::Ready(Some(Ok(fr))) => {
                        if let Ok(d) = fr.into_data() {
                            match msgs.push(&d) {
                                Ok(got) => out.extend(got.into_iter().map(|m| Piece::data(*id, m))),
                                Err(e) => {
                                    let (why, code) = (e.to_string(), e.status());
                                    s.body = None;
                                    s.fail_reply(code, why.as_bytes());
                                    out.push_back(Piece {
                                        status: Some(code),
                                        ..Piece::failure(*id, &why)
                                    });
                                }
                            }
                        }
                    }
                    Poll::Ready(None) => {
                        let whole = msgs.end();
                        s.body = None;
                        match whole {
                            // The far end sent its last: the stream's end (`PIECE_END`).
                            Ok(()) => out.push_back(Piece::end(*id)),
                            Err(e) => {
                                let why = e.to_string();
                                s.fail_reply(msg::INTERNAL, why.as_bytes());
                                out.push_back(Piece {
                                    status: Some(msg::INTERNAL),
                                    ..Piece::failure(*id, &why)
                                });
                            }
                        }
                    }
                    Poll::Ready(Some(Err(e))) => {
                        // The far end reset the call.
                        s.body = None;
                        s.reply_over = true;
                        s.reply.chan.end();
                        out.push_back(Piece {
                            status: Some(msg::CANCELLED),
                            ..Piece::failure(*id, &e.to_string())
                        });
                    }
                }
            }
        }
        for (id, s) in &self.calls {
            if !s.reply_over && s.reply.chan.take_writable() {
                out.push_back(Piece::writable(*id));
            }
        }
        self.calls
            .retain(|(_, s)| !(s.reply_over && s.body.is_none() && s.reply.chan.ended()));
    }
}

#[cfg(test)]
#[path = "tests/engine_tests.rs"]
mod tests;
