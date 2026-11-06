// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The engine: gRPC over `hyper`'s HTTP/2, both sides, run as a sans-IO framer.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use crate::hyper_io::{extend_wiped, field_block, held_bytes, HeadWords, HostIo, Owed, Piece};
use busbar_contract::abi::host::service::UnitRef;
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::services::{HeadViewArgs, RefusalCopy};
use busbar_contract::abi::sdk::transport::policy::Loans;
use busbar_contract::abi::sdk::Out;
use busbar_contract::abi::transport::fields::hop_by_hop;
use busbar_contract::abi::transport::guest_policy::Policy;
use busbar_contract::abi::transport::sensitive_fields::SensitiveFields;
use busbar_contract::abi::transport::FramerOut;
use busbar_contract::abi::transport::FAULT_CALLER;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode};
use http_body::{Body, Frame};
use hyper::body::Incoming;
use hyper::client::conn::http2 as client;
use hyper::rt::{Executor, Sleep};
use hyper::server::conn::http2 as server;

use crate::msg::{self, Head, Messages};

/// A head block the host emitted, held until it is whole: wiped when it drops, since a dialled
/// head carries the auth's credential lines (TSEAL: until the attach slot is sealed, credentials
/// reach the framer as plaintext, and the framer wipes the copies it owns).
type HeadBuf = zeroize::Zeroizing<Vec<u8>>;

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
    /// The largest message payload read from a far end; what the host emits is bounded by the
    /// stream's queue ([`stream_bound`]), not by this.
    pub max_message_bytes: usize,
}

/// Why a framing failed; the op that finds it answers FAILED with this text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure(pub String);

/// The host selects an immutable loan and admits a matched no-auth request before it is framed.
pub(crate) trait Admission {
    fn ticket(&self) -> Ticket;
    fn open(
        &mut self,
        loans: &mut Loans,
        stream: u64,
        out: &mut Out<'_, FramerOut>,
    ) -> Result<Option<Arc<Policy>>, Failure>;
    fn hand_in(
        &mut self,
        stream: u64,
        policy: &Policy,
        head: &HeadViewArgs<'_>,
        sequence: &mut u32,
    ) -> Result<Result<UnitRef, RefusalCopy>, Failure>;
}

pub(crate) enum AdmissionProgress {
    Idle,
    Requested,
    Published,
}

type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;

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

/// THE HOST'S OWN BACKPRESSURE, the other way: what a connection holds for the host (pieces handed
/// up and not yet taken), past which it reads no stream's body until the host takes them.
const INBOUND_HIGH_WATER: usize = STREAM_HIGH_WATER;

/// What one piece held for the host counts beside its bytes ([`INBOUND_HIGH_WATER`]).
const PIECE_COST: usize = 64;

/// The most requests one accepted connection holds unanswered in each of its two queues: newly
/// arrived and not yet read, and awaiting host admission. A request past either is answered 503.
const PENDING_REQUEST_LIMIT: usize = 200;

/// What `out` holds for the host, as [`INBOUND_HIGH_WATER`] counts it.
fn held_for_host(out: &VecDeque<Piece>) -> usize {
    out.iter().map(|p| p.bytes.len() + PIECE_COST).sum()
}

/// Why a stream whose host emitted past its bound (the high-water mark and one whole message
/// more) failed: the framer bounds what it holds for a far end that is not reading.
pub(crate) const OVER_BOUND: &str =
    "the stream's queue is past its bound: the far end is not reading";

/// The room a head block may take beside one whole message: a head block the host emits (an
/// accepted call's answer, or a dialled call's request with its auth's lines) is read up to
/// `max_message_bytes` and this much, and a stream's bound counts it as part of the one message
/// more it holds past the high-water mark.
pub(crate) const HEAD_ALLOWANCE: usize = 64 * 1024;

/// A STREAM'S BOUND: the payload bytes it may queue for the far end before a host that keeps
/// emitting has it failed — the high-water mark, and one whole message (with its head block) more.
pub(crate) fn stream_bound(max_message_bytes: usize) -> usize {
    STREAM_HIGH_WATER
        .saturating_add(max_message_bytes)
        .saturating_add(HEAD_ALLOWANCE)
}

/// The feeding end of a [`ChanBody`].
#[derive(Clone, Default)]
struct Chan(Arc<Mutex<ChanState>>);

impl Chan {
    fn push(&self, f: Frame<Bytes>) {
        let mut s = self.0.lock().unwrap_or_else(PoisonError::into_inner);
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
        self.0.lock().unwrap_or_else(PoisonError::into_inner).queued
    }
    /// Drop every frame queued and not yet taken.
    fn drop_queued(&self) {
        let mut s = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        s.frames.clear();
        s.queued = 0;
    }
    /// Fail the stream: drop what is queued, and have the connection reset it.
    fn reset(&self) {
        let mut s = self.0.lock().unwrap_or_else(PoisonError::into_inner);
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
        let mut s = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let full = s.queued >= STREAM_HIGH_WATER;
        s.announced |= full;
        full
    }
    /// Whether a stream answered full has drained to its low-water mark: once per announcement.
    fn take_writable(&self) -> bool {
        let mut s = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let writable = s.announced && s.queued <= STREAM_LOW_WATER;
        if writable {
            s.announced = false;
        }
        writable
    }
    fn end(&self) {
        let mut s = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        s.ended = true;
        if let Some(w) = s.waker.take() {
            w.wake();
        }
    }
    fn ended(&self) -> bool {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).ended
    }
    /// The body was let go of before its end (see [`ChanState::gone`]).
    fn gone(&self) -> bool {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).gone
    }
    /// Nobody will read this body again: drop what is queued and take no more.
    fn let_go(&self) {
        let mut s = self.0.lock().unwrap_or_else(PoisonError::into_inner);
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
    // `hyper` reads a reset's reason from an `h2::Error` in the error's source chain, which an
    // `io::Error` hides.
    type Error = h2::Error;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, h2::Error>>> {
        let mut s = self.0 .0.lock().unwrap_or_else(PoisonError::into_inner);
        if s.reset {
            return Poll::Ready(Some(Err(h2::Error::from(h2::Reason::CANCEL))));
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
        let s = self.0 .0.lock().unwrap_or_else(PoisonError::into_inner);
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

type Task = Pin<Box<dyn Future<Output = ()> + Send>>;

#[derive(Default)]
struct TaskList {
    tasks: Vec<Task>,
    waker: Option<Arc<Waker>>,
}

/// The framing owns its tasks. Hyper's connection and stream tasks retain their executor, so
/// that executor must hold this list weakly or finishing a framing would leave a strong cycle.
#[derive(Default)]
struct Tasks(Arc<Mutex<TaskList>>);

#[derive(Clone)]
struct Spawner(Weak<Mutex<TaskList>>);

impl<F: Future<Output = ()> + Send + 'static> Executor<F> for Spawner {
    fn execute(&self, future: F) {
        if let Some(list) = self.0.upgrade() {
            let wake = {
                let mut list = list.lock().unwrap_or_else(PoisonError::into_inner);
                list.tasks.push(Box::pin(future));
                list.waker.clone()
            };

            if let Some(wake) = wake {
                wake.wake_by_ref();
            }
        }
    }
}

impl Tasks {
    fn spawner(&self) -> Spawner {
        Spawner(Arc::downgrade(&self.0))
    }

    fn run(&self, cx: &mut Context<'_>) {
        let previous = {
            let list = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            list.waker.clone()
        };
        let wake = match previous {
            Some(wake) if wake.will_wake(cx.waker()) => wake,
            _ => Arc::new(cx.waker().clone()),
        };
        let (mut tasks, old_wake) = {
            let mut list = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            let old_wake = list.waker.replace(wake);
            (std::mem::take(&mut list.tasks), old_wake)
        };
        drop(old_wake);
        tasks.retain_mut(|task| task.as_mut().poll(cx).is_pending());
        let mut list = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        tasks.append(&mut list.tasks);
        list.tasks = tasks;
    }
}

/// One connection's gRPC machine.
pub struct Conn {
    io: HostIo,
    tasks: Tasks,
    out: VecDeque<Piece>,
    conn_err: Arc<Mutex<Option<hyper::Error>>>,
    conn_done: Arc<AtomicBool>,
    failed: Option<Failure>,
    posture: Posture,
    side: Side,
    /// The last drive left a body unread because the host had not taken what it was handed
    /// ([`INBOUND_HIGH_WATER`]): the host is owed a re-call once it has.
    held_back: bool,
    /// Drives so far: each reads the streams from one further on ([`Room::first`]).
    turn: usize,
}

enum Side {
    Dial(Dial),
    Accept(Accept),
}

impl Owed for Conn {
    fn take_wire(&mut self, cap: usize) -> Vec<u8> {
        self.io.take_wire(cap)
    }
    /// Wire bytes still owed, or a body the last drive left unread for the host's sake: either way
    /// the host calls again (`YIELD_MORE`), and the re-call reads on once it has taken its pieces.
    /// A failed connection still owes what its HTTP/2 machine wrote on the way down (its GOAWAY):
    /// the host takes that before the framing fails.
    fn wire_pending(&self) -> bool {
        self.io.wire_pending() || (self.failed.is_none() && self.held_back)
    }
    fn pieces(&mut self) -> &mut VecDeque<Piece> {
        &mut self.out
    }
    fn next_deadline(&self) -> Option<u64> {
        let accepted = match &self.side {
            Side::Accept(accept) => accept.next_deadline(),
            Side::Dial(_) => None,
        };
        self.io.next_deadline().into_iter().chain(accepted).min()
    }
    fn ended(&self) -> bool {
        self.conn_done.load(Ordering::Acquire)
    }
}

/// Record the actual connection driver's terminal result in its framing.
fn watch<F>(
    exec: &impl Executor<BoxFut<()>>,
    conn: F,
    err: &Arc<Mutex<Option<hyper::Error>>>,
    done: &Arc<AtomicBool>,
) where
    F: Future<Output = hyper::Result<()>> + Send + 'static,
{
    let (err, done) = (err.clone(), done.clone());
    exec.execute(Box::pin(async move {
        if let Err(e) = conn.await {
            *err.lock().unwrap_or_else(PoisonError::into_inner) = Some(e);
        }
        done.store(true, Ordering::Release);
    }));
}

impl Conn {
    /// Open a dialled connection to `target` (an `http`/`https` URL: its scheme and authority are
    /// every call's), at host time `now_ns`.
    pub fn dial(target: &str, posture: Posture, now_ns: u64) -> Result<Self, Failure> {
        let uri: http::Uri = target.parse().map_err(|_| Failure("not a target".into()))?;
        let (Some(scheme), Some(authority)) = (uri.scheme(), uri.authority()) else {
            return Err(Failure("not a target".into()));
        };

        let authority = authority
            .as_str()
            .rsplit_once('@')
            .map_or(authority.as_str(), |(_, host)| host);
        let base = format!("{scheme}://{authority}");
        let io = HostIo::new(now_ns);
        let conn_err = Arc::new(Mutex::new(None));
        let conn_done = Arc::new(AtomicBool::new(false));
        let tasks = Tasks::default();
        let mut b = client::Builder::new(tasks.spawner());
        b.timer(io.timer()).adaptive_window(posture.adaptive_window);
        if let Some(every) = posture.keep_alive_interval {
            b.keep_alive_interval(every)
                .keep_alive_timeout(posture.keep_alive_timeout);
        }
        let (exec, err, done, stream) = (
            tasks.spawner(),
            conn_err.clone(),
            conn_done.clone(),
            io.stream(),
        );
        let handshake: BoxFut<hyper::Result<client::SendRequest<ChanBody>>> =
            Box::pin(async move {
                let (s, c) = b.handshake(stream).await?;
                watch(&exec, c, &err, &done);
                Ok(s)
            });
        Ok(Self {
            io,
            tasks,
            out: VecDeque::new(),
            conn_err,
            conn_done,
            failed: None,
            posture,
            held_back: false,
            turn: 0,
            side: Side::Dial(Dial {
                handshake: Some(handshake),
                sender: None,
                base,
                calls: Vec::new(),
                ended: Ended::default(),
            }),
        })
    }

    /// Open an accepted connection, at host time `now_ns`.
    #[must_use]
    pub fn accept(posture: Posture, now_ns: u64) -> Self {
        let io = HostIo::new(now_ns);
        let conn_err = Arc::new(Mutex::new(None));
        let conn_done = Arc::new(AtomicBool::new(false));
        let arrivals = Arc::new(Mutex::new(Arrivals::default()));
        let svc_arrivals = arrivals.clone();
        let clock = io.timer();
        let svc = hyper::service::service_fn(move |mut req: Request<Incoming>| {
            req.extensions_mut().insert(ReceivedAt(clock.now_ns()));
            let reply = Reply::default();
            {
                let mut a = svc_arrivals.lock().unwrap_or_else(PoisonError::into_inner);
                if a.new.len() >= PENDING_REQUEST_LIMIT {
                    reply.head(StatusCode::SERVICE_UNAVAILABLE, HeaderMap::new());
                    reply.chan.end();
                } else {
                    a.next += 1;
                    let id = a.next;
                    a.new.push_back((id, req, reply.clone()));
                }
            }
            ReplyFut {
                reply,
                answered: false,
            }
        });
        let tasks = Tasks::default();
        let mut b = server::Builder::new(tasks.spawner());
        b.timer(io.timer()).adaptive_window(posture.adaptive_window);
        let conn = b.serve_connection(io.stream(), svc);
        watch(&tasks.spawner(), conn, &conn_err, &conn_done);
        Self {
            io,
            tasks,
            out: VecDeque::new(),
            conn_err,
            conn_done,
            failed: None,
            posture,
            held_back: false,
            turn: 0,
            side: Side::Accept(Accept {
                arrivals,
                calls: Vec::new(),
                ended: Ended::default(),
                policy: None,
                waiting: VecDeque::new(),
                now_ns,
            }),
        }
    }

    /// Attach the host's initial policy cache. Each accepted request asks for its own selection.
    pub(crate) fn with_policies(mut self, loans: Option<Loans>, scheme: u8) -> Self {
        if let Side::Accept(accept) = &mut self.side {
            accept.policy = loans.map(|loans| AcceptedPolicy {
                loans,
                scheme,
                sequence: 0,
            });
        }
        self
    }

    /// Whether this ticket's original input was taken before its policy roundtrip.
    pub(crate) fn policy_pending(&self, ticket: Ticket) -> bool {
        matches!(&self.side, Side::Accept(accept) if accept.policy.as_ref().is_some_and(|policy| policy.loans.pending_stream(ticket).is_some()))
    }

    /// Cancel only this ticket's unadmitted request; other streams keep their bodies and replies.
    pub(crate) fn cancel_policy(&mut self, ticket: Ticket) -> bool {
        let Side::Accept(accept) = &mut self.side else {
            return false;
        };
        let Some(policy) = &mut accept.policy else {
            return false;
        };
        let Some(stream) = policy.loans.cancel(ticket) else {
            return false;
        };
        if let Some(at) = accept
            .waiting
            .iter()
            .position(|request| request.id == stream)
        {
            let request = accept.waiting.remove(at).expect("position above");
            request.reply.chan.reset();
            request
                .reply
                .head(StatusCode::SERVICE_UNAVAILABLE, HeaderMap::new());
        }
        accept.ended.insert(stream);
        true
    }

    /// Admit at most one request between fills. A policy request must be an empty READY answer.
    pub(crate) fn admit(
        &mut self,
        host: &mut dyn Admission,
        reply: &mut Out<'_, FramerOut>,
    ) -> Result<AdmissionProgress, Failure> {
        if self.io.wire_pending() || !self.out.is_empty() {
            return Ok(AdmissionProgress::Idle);
        }
        let Side::Accept(accept) = &mut self.side else {
            return Ok(AdmissionProgress::Idle);
        };
        accept.admit(&mut self.out, self.posture.max_message_bytes, host, reply)
    }

    /// The far side sent `bytes` (`end` = and then ended).
    pub fn ingest(&mut self, bytes: &[u8], end: bool) {
        self.io.ingest(bytes, end);
    }

    /// Bytes for `stream` (`end` = they end the frame). `deadline_ns` is the attempt's deadline on
    /// a dialled stream's first `emit` (`0` = none stated), `now_ns` the host's time.
    pub fn emit(
        &mut self,
        stream: u64,
        bytes: &[u8],
        end: bool,
        deadline_ns: u64,
        now_ns: u64,
    ) -> Result<(), Failure> {
        self.emit_marked(stream, bytes, end, deadline_ns, now_ns, None)
    }

    /// Emit a request head carrying the host's credential-header classification.
    pub(crate) fn emit_sensitive(
        &mut self,
        stream: u64,
        bytes: &[u8],
        end: bool,
        deadline_ns: u64,
        now_ns: u64,
        sensitive: SensitiveFields,
    ) -> Result<(), Failure> {
        self.emit_marked(stream, bytes, end, deadline_ns, now_ns, Some(sensitive))
    }

    fn emit_marked(
        &mut self,
        stream: u64,
        bytes: &[u8],
        end: bool,
        deadline_ns: u64,
        now_ns: u64,
        sensitive: Option<SensitiveFields>,
    ) -> Result<(), Failure> {
        let max = self
            .posture
            .max_message_bytes
            .saturating_add(HEAD_ALLOWANCE);

        let bound = stream_bound(self.posture.max_message_bytes);
        match &mut self.side {
            Side::Dial(d) => {
                if d.ended.contains(stream) {
                    return Ok(());
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
                        let mut call = DialStream::new(timer.sleep_until_ns(at));
                        call.sensitive = sensitive.clone().unwrap_or_default();
                        d.calls.push((stream, call));
                        d.calls.len() - 1
                    }
                };
                let s = &mut d.calls[idx].1;
                let read = if matches!(s.stage, DStage::Head(_))
                    && sensitive
                        .as_ref()
                        .is_some_and(|fields| fields != &s.sensitive)
                {
                    Err("request sensitivity changed during its head".into())
                } else {
                    s.take(&d.base, bytes, end, max)
                };
                if let Err(why) = read {
                    s.chan.reset();
                    s.stage = DStage::Done;
                    // Nothing was sent: the caller's call was unbuildable, not the far end's fault.
                    self.out.push_back(Piece {
                        status: Some(msg::INTERNAL),
                        fault: Some(FAULT_CALLER),
                        ..Piece::failure(stream, &why)
                    });
                } else if s.chan.queued() > bound {
                    s.chan.reset();
                    s.stage = DStage::Done;
                    self.out.push_back(Piece {
                        status: Some(msg::RESOURCE_EXHAUSTED),
                        ..Piece::failure(stream, OVER_BOUND)
                    });
                }
                d.sweep();
                Ok(())
            }
            Side::Accept(a) => {
                let Some((_, s)) = a.calls.iter_mut().find(|(s, _)| *s == stream) else {
                    return a.late(stream);
                };
                if bytes.is_empty() || s.reply_over {
                    return Ok(());
                }
                if !s.head_sent {
                    extend_wiped(&mut s.head_buf, bytes);
                    let read = match msg::read_head(&s.head_buf, max) {
                        Ok(None) if end => Err("the frame ended inside the head block".into()),
                        read => read,
                    };
                    match read {
                        Ok(None) => return Ok(()),
                        Err(why) => {
                            s.fail_reply(msg::INTERNAL, why.as_bytes());

                            self.out.push_back(Piece {
                                status: Some(msg::INTERNAL),
                                ..Piece::failure(stream, &why)
                            });
                            return Ok(());
                        }
                        Ok(Some((head, took))) => {
                            let rest = std::mem::take(&mut s.head_buf)[took..].to_vec();
                            if let Err(why) = s.send_head(&head, None) {
                                s.fail_reply(msg::INTERNAL, why.as_bytes());
                                self.out.push_back(Piece {
                                    status: Some(msg::INTERNAL),
                                    ..Piece::failure(stream, &why)
                                });
                                return Ok(());
                            }
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
                Ok(())
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
    pub fn end_call(&mut self, stream: u64, trailers: &[u8], status: u32) -> Result<(), Failure> {
        let Side::Accept(a) = &mut self.side else {
            return Err(Failure("a dialled call is not answered".into()));
        };
        let Some((_, s)) = a.calls.iter_mut().find(|(s, _)| *s == stream) else {
            return a.late(stream);
        };
        if s.reply_over {
            return Ok(());
        }

        match msg::refusal_block(trailers).map_err(Failure)? {
            Some(h) => s.finish(&h).map_err(Failure)?,
            None if status != 0 => s.fail_reply(
                msg::status_of_refusal(status),
                msg::refusal_message(status).as_bytes(),
            ),
            None => s.fail_reply(msg::UNKNOWN, trailers),
        }
        Ok(())
    }

    /// Apply accepting deadlines before a host operation can finish or emit a late success.
    pub(crate) fn expire_deadlines(&mut self, now_ns: u64) {
        if let Side::Accept(accept) = &mut self.side {
            accept.now_ns = now_ns;
            let mut room = Room::of(&self.out, self.turn);
            accept.expire(&mut self.out, &mut room);
        }
    }

    /// Drive the connection at host time `now_ns` until nothing inside it has more to do.
    pub fn drive(&mut self, now_ns: u64) {
        self.io.set_time(now_ns);
        if self.failed.is_some() {
            return;
        }
        let io = self.io.clone();
        let max = self.posture.max_message_bytes;
        let turn = self.turn;
        self.turn = self.turn.wrapping_add(1);
        let held_back = &mut self.held_back;
        let mut stream_failed = false;
        let r = io.rounds(|cx| {
            self.tasks.run(cx);
            let mut room = Room::of(&self.out, turn);
            room.partial = match &self.side {
                Side::Dial(d) => d
                    .calls
                    .iter()
                    .map(|(_, s)| match &s.stage {
                        DStage::Body(_, msgs) => msgs.buffered(),
                        _ => 0,
                    })
                    .sum(),
                Side::Accept(a) => a
                    .calls
                    .iter()
                    .filter_map(|(_, s)| s.body.as_ref())
                    .map(|(_, msgs)| msgs.buffered())
                    .sum(),
            };
            let r = match &mut self.side {
                Side::Dial(d) => d.step(&mut self.out, &mut room, max, cx).map(|failed| {
                    stream_failed |= failed;
                }),
                Side::Accept(a) => {
                    a.now_ns = now_ns;
                    a.step(&mut self.out, &mut room, max, cx);
                    Ok(())
                }
            };
            *held_back = room.held_back;
            r
        });
        if let Err(f) = r {
            self.failed = Some(f);
            return;
        }
        let err = self
            .conn_err
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(e) = err {
            // h2 reports a frame-boundary EOF as BrokenPipe even after the last RPC
            // completed. Keep truncated frames and unfinished calls as failures, including
            // calls that this drive swept after reporting a stream failure.
            let drained = matches!(&self.side, Side::Dial(d)
                if d.calls.is_empty() && !d.ended.0.is_empty());
            if !stream_failed && boundary_eof(&e) {
                if drained {
                    return;
                }
                // Complete frames can still be queued in Incoming behind the host's
                // high-water mark. Keep the terminal error until those bodies and
                // trailers have been read; the next drive still rejects missing trailers
                // or any stream failure. Do not bypass the bounded output queue.
                if self.held_back && matches!(&self.side, Side::Dial(_)) {
                    *self.conn_err.lock().unwrap_or_else(PoisonError::into_inner) = Some(e);
                    return;
                }
            }
            self.failed = Some(Failure(e.to_string()));
        }
    }

    /// Far-side bytes ingested and not yet read by the connection: what it retains while
    /// `hyper` has stopped reading (its own writes are blocked on a far end not reading them).
    #[must_use]
    pub fn retained_input(&self) -> usize {
        self.io.pending_input()
    }

    /// Why this framing failed, once it has.
    #[must_use]
    pub fn failure(&self) -> Option<&Failure> {
        self.failed.as_ref()
    }
}

/// h2 distinguishes a complete frame boundary (BrokenPipe) from a truncated frame
/// (UnexpectedEof). Preserve that distinction instead of matching Hyper's display text.
fn boundary_eof(e: &(dyn std::error::Error + 'static)) -> bool {
    let mut at = Some(e);
    while let Some(err) = at {
        // Hyper unwraps h2 I/O errors before exposing its connection error.
        if let Some(io) = err.downcast_ref::<std::io::Error>() {
            return io.kind() == std::io::ErrorKind::BrokenPipe;
        }
        if let Some(h) = err.downcast_ref::<h2::Error>() {
            return h
                .get_io()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::BrokenPipe);
        }
        at = err.source();
    }
    false
}

/// What one drive round may still hand the host before it reads no more ([`INBOUND_HIGH_WATER`]).
struct Room {
    held: usize,
    partial: usize,
    /// A body was left unread for the host's sake.
    held_back: bool,
    /// The stream this drive reads first: each drive starts one further on.
    first: usize,
}

impl Room {
    fn of(out: &VecDeque<Piece>, first: usize) -> Self {
        Self {
            held: held_for_host(out),
            partial: 0,
            held_back: false,
            first,
        }
    }

    /// The order a round reads `n` streams in: every stream once, starting at [`Room::first`]
    /// (modulo `n`) and wrapping, so that while the host is the bottleneck no stream fills the room
    /// ahead of the others on every drive.
    fn order(&self, n: usize) -> impl Iterator<Item = usize> {
        let first = if n == 0 { 0 } else { self.first % n };
        (0..n).map(move |k| (first + k) % n)
    }

    /// Whether a body may be read now; if not, it is left unread and the host is owed a re-call.
    fn open(&mut self) -> bool {
        let open = self.held < INBOUND_HIGH_WATER;
        self.held_back |= !open;
        open
    }

    /// `got` was handed up.
    fn took(&mut self, got: &[Bytes]) {
        self.held += got.iter().map(|m| m.len() + PIECE_COST).sum::<usize>();
    }
}

struct Dial {
    handshake: Option<BoxFut<hyper::Result<client::SendRequest<ChanBody>>>>,
    sender: Option<client::SendRequest<ChanBody>>,
    base: String,
    calls: Vec<(u64, DialStream)>,
    /// Streams that have ended (their terminal piece is out). An `emit` on one is late and is
    /// dropped: it never opens a second call under the same stream.
    ended: Ended,
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
                // An early answer leaves the request unfinished: reset it, so the connection
                // sends RST_STREAM rather than hold the send half and the slot open.
                if !s.chan.ended() {
                    s.chan.reset();
                }
                ended.insert(*id);
            }
            !s.over()
        });
    }
}

enum DStage {
    /// The head block, still arriving.
    Head(HeadBuf),
    /// A request, waiting for the connection to take it.
    Queued(Request<ChanBody>),
    /// Sent; waiting for the answer's head.
    Asked(BoxFut<hyper::Result<Response<Incoming>>>),
    /// The answer's messages.
    Body(Incoming, Messages),
    /// Answered in full, or failed.
    Done,
}

struct DialStream {
    sensitive: SensitiveFields,
    stage: DStage,
    chan: Chan,
    /// Bytes of the message stream still to come, when the head stated its length.
    left: Option<usize>,
    /// The attempt's deadline: the stream fails `DEADLINE_EXCEEDED` here when it passes.
    sleep: Pin<Box<dyn Sleep>>,
}

impl DialStream {
    fn new(sleep: Pin<Box<dyn Sleep>>) -> Self {
        Self {
            sensitive: SensitiveFields::default(),
            stage: DStage::Head(HeadBuf::default()),
            chan: Chan::default(),
            left: None,
            sleep,
        }
    }

    fn over(&self) -> bool {
        matches!(self.stage, DStage::Done)
    }

    /// Take `bytes` the host emitted on this stream.
    fn take(&mut self, base: &str, bytes: &[u8], end: bool, max: usize) -> Result<(), String> {
        let body: Vec<u8> = match &mut self.stage {
            DStage::Head(buf) => {
                extend_wiped(buf, bytes);
                let Some((head, took)) = msg::read_head(buf, max)? else {
                    if end {
                        return Err("the frame ended inside the head block".into());
                    }
                    return Ok(());
                };

                let rest = std::mem::take(buf)[took..].to_vec();
                let req = self.request(base, &head)?;
                self.left = head.content_length;
                self.stage = DStage::Queued(req);
                rest
            }
            DStage::Done => return Ok(()),
            _ => bytes.to_vec(),
        };
        if !body.is_empty() {
            if self.chan.ended() {
                return Err("bytes after the request's end".into());
            }
            if let Some(left) = self.left.as_mut() {
                if body.len() > *left {
                    return Err("more message bytes than the head's content-length".into());
                }
                *left -= body.len();
            }
            self.chan.push(Frame::data(Bytes::from(body)));
        }
        if end {
            if let Some(short @ 1..) = self.left {
                return Err(format!(
                    "the frame ended {short} bytes short of the head's content-length"
                ));
            }
        }
        if self.left == Some(0) || (end && self.left.is_none()) {
            self.chan.end();
        }
        Ok(())
    }

    fn request(&self, base: &str, head: &Head) -> Result<Request<ChanBody>, String> {
        if self.sensitive.contains(b":path") {
            return Err(
                "sensitive request targets cannot be represented by this HTTP/2 client".into(),
            );
        }
        let path = head.get("path").ok_or("the head names no path")?;
        if !path.starts_with(b"/") {
            return Err("the head's path is not absolute".into());
        }
        let uri = format!("{base}{}", String::from_utf8_lossy(path));
        let mut content_type = match head.get("content-type") {
            Some(ct) if msg::is_grpc_content_type(ct) => {
                HeaderValue::from_bytes(ct).map_err(|_| "content-type is not a field value")?
            }
            Some(_) => return Err("content-type is not a gRPC content type".into()),
            None => HeaderValue::from_static(msg::CONTENT_TYPE),
        };
        content_type.set_sensitive(self.sensitive.contains(b"content-type"));
        let mut b = Request::builder()
            .method(http::Method::POST)
            .uri(uri)
            .version(http::Version::HTTP_2)
            .header(http::header::CONTENT_TYPE, content_type)
            .header(http::header::TE, "trailers");

        for (name, value) in &head.fields {
            if RESERVED_ON_REQUEST.contains(&name.as_str()) || hop_by_hop(name, []) {
                continue;
            }
            let n = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| format!("`{name}` is not a field name"))?;
            let mut v = HeaderValue::from_bytes(value)
                .map_err(|_| format!("`{name}`'s value is not a field value"))?;
            v.set_sensitive(self.sensitive.contains(name.as_bytes()));
            b = b.header(n, v);
        }
        b.body(self.chan.body())
            .map_err(|e| format!("request: {e}"))
    }
}

/// Fields this layer owns on a request, beside the hop-by-hop ones HTTP/2 forbids: a head block's
/// own are dropped.
const RESERVED_ON_REQUEST: &[&str] = &[
    "path",
    "method",
    "authority",
    "content-type",
    "content-length",
    "host",
];

impl Dial {
    fn step(
        &mut self,
        out: &mut VecDeque<Piece>,
        room: &mut Room,
        max: usize,
        cx: &mut Context<'_>,
    ) -> Result<bool, Failure> {
        if let Some(h) = self.handshake.as_mut() {
            if let Poll::Ready(r) = h.as_mut().poll(cx) {
                self.handshake = None;
                self.sender = Some(r.map_err(|e| Failure(e.to_string()))?);
            }
        }
        let mut stream_failed = false;
        for at in room.order(self.calls.len()) {
            let (id, s) = &mut self.calls[at];
            if let Err((why, code, conn)) = advance(*id, s, &mut self.sender, out, room, max, cx) {
                if conn {
                    return Err(Failure(why));
                }
                stream_failed = true;

                if let DStage::Body(_, msgs) = &s.stage {
                    room.partial = room.partial.saturating_sub(msgs.buffered());
                }
                s.chan.reset();
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
        Ok(stream_failed)
    }
}

/// Move one dialled stream as far as it goes this round. `Err((why, code, true))` is the
/// connection's failure (the sender refused), `Err((why, code, false))` the stream's own.
fn advance(
    id: u64,
    s: &mut DialStream,
    sender: &mut Option<client::SendRequest<ChanBody>>,
    out: &mut VecDeque<Piece>,
    room: &mut Room,
    max: usize,
    cx: &mut Context<'_>,
) -> Result<(), (String, u16, bool)> {
    if !s.over() && s.sleep.as_mut().poll(cx).is_ready() {
        return Err(("deadline exceeded".into(), msg::DEADLINE_EXCEEDED, false));
    }
    loop {
        match &mut s.stage {
            DStage::Head(_) | DStage::Done => return Ok(()),
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
                    let r = r.map_err(|e| {
                        let (code, why) = wire_failure(&e);
                        (why, code, false)
                    })?;

                    let stated = r.headers().contains_key(msg::GRPC_STATUS);
                    if !stated && r.status() != StatusCode::OK {
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
                    if !stated && !ct.is_some_and(|v| msg::is_grpc_content_type(v.as_bytes())) {
                        return Err(("the answer is not gRPC".into(), msg::UNKNOWN, false));
                    }
                    out.push_back(Piece::fields(
                        id,
                        Bytes::from(field_block(r.headers(), STATUS_FIELDS)),
                    ));
                    if stated {
                        if !r.body().is_end_stream() {
                            return Err((
                                "the answer states grpc-status before its body ended".into(),
                                msg::INTERNAL,
                                false,
                            ));
                        }
                        out.extend(trailers(id, &HeaderMap::new(), r.headers()));
                        s.stage = DStage::Done;
                        return Ok(());
                    }
                    s.stage = DStage::Body(r.into_body(), Messages::new(max));
                }
            },
            DStage::Body(_, _) if !room.open() => return Ok(()),
            DStage::Body(b, msgs) => match Pin::new(&mut *b).poll_frame(cx) {
                Poll::Pending => return Ok(()),
                Poll::Ready(Some(Err(e))) => {
                    let (code, why) = wire_failure(&e);
                    return Err((why, code, false));
                }
                Poll::Ready(Some(Ok(fr))) => match fr.into_data() {
                    Ok(d) => {
                        if room.partial.saturating_add(d.len()) > stream_bound(max) {
                            return Err((
                                "connection partial-message budget exceeded".into(),
                                msg::RESOURCE_EXHAUSTED,
                                false,
                            ));
                        }
                        room.partial = room.partial.saturating_sub(msgs.buffered());
                        let got = msgs
                            .push_bytes(d)
                            .map_err(|e| (dial_bad_text(&e), e.status(), false))?;
                        room.partial += msgs.buffered();
                        room.took(&got);
                        out.extend(got.into_iter().map(|m| Piece::data(id, m)));
                    }
                    Err(other) => {
                        if let Ok(t) = other.into_trailers() {
                            msgs.end().map_err(|e| (e.to_string(), e.status(), false))?;
                            out.extend(trailers(id, &t, &t));
                            s.stage = DStage::Done;
                            return Ok(());
                        }
                    }
                },

                Poll::Ready(None) => {
                    let why = if msgs.end().is_err() {
                        "the answer ended inside a message, with no grpc-status"
                    } else {
                        "the answer ended without a grpc-status"
                    };
                    return Err((why.into(), msg::INTERNAL, false));
                }
            },
        }
    }
}

/// A DIALLED STREAM'S FAILURE BELOW gRPC, as the status it stands for and this framer's own text
/// for it.
fn wire_failure(e: &(dyn std::error::Error + 'static)) -> (u16, String) {
    let mut at = Some(e);
    while let Some(err) = at {
        if let Some(h) = err.downcast_ref::<h2::Error>() {
            if let Some(reason) = h.reason() {
                let code = u32::from(reason);
                let what = if h.is_go_away() {
                    "the connection went away"
                } else {
                    "the stream was reset"
                };

                let status = if h.is_go_away() && h.is_remote() && code == 0 {
                    msg::UNAVAILABLE
                } else {
                    msg::status_of_reset(code)
                };
                return (status, format!("{what}: {}", msg::reset_name(code)));
            }
            break;
        }
        at = err.source();
    }
    (
        msg::UNAVAILABLE,
        format!("the connection to the far end was lost: {e}"),
    )
}

/// What a dialled answer that is no message stream is called, in this framer's own words.
fn dial_bad_text(e: &msg::Bad) -> String {
    match e {
        msg::Bad::TooLarge(n, limit) => {
            format!(
                "the answer's message is {n} bytes, over the limit of {limit} bytes ({})",
                crate::meta::setting::BODY_MAX_BYTES
            )
        }
        other => other.to_string(),
    }
}

/// The fields the trailers' code and the terminal piece carry, never a field block's.
const STATUS_FIELDS: &[&str] = &[msg::GRPC_STATUS, msg::GRPC_MESSAGE];

/// The stream's end, from the fields that carry `grpc-status` (`status`): the trailers (`fields`
/// as a field block, its code the status), then the terminal piece — empty on `OK`, else the
/// failure whose bytes are the decoded `grpc-message`, as printable text ([`msg::message_text`]).
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
        .map(|v| msg::message_text(v.as_bytes()))
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| {
            if let Some(sent) = status.get(msg::GRPC_STATUS) {
                // A value that is not a canonical code reads as UNKNOWN: the text says what the
                // far end sent, not a code it did not.
                let canonical = msg::canonical_status(sent.as_bytes()).is_some();
                if canonical {
                    format!("grpc-status {code}").into_bytes()
                } else {
                    format!(
                        "grpc-status {} (not a gRPC status; read as UNKNOWN)",
                        sent.as_bytes().escape_ascii()
                    )
                    .into_bytes()
                }
            } else {
                b"the answer's trailers carry no grpc-status".to_vec()
            }
        });
    [
        block,
        Piece {
            failed: true,
            ..Piece::data(id, Bytes::from(text))
        },
    ]
}

#[derive(Clone, Copy)]
struct ReceivedAt(u64);

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
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
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
        let mut s = self
            .reply
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
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
    /// Calls that have ended and been let go of. An `emit` or a refusal on one is late (it raced
    /// the far end's cancel, or the call's own end) and is dropped, as on a dialled stream.
    ended: Ended,
    policy: Option<AcceptedPolicy>,
    waiting: VecDeque<Unadmitted>,
    now_ns: u64,
}

struct AcceptedPolicy {
    loans: Loans,
    scheme: u8,
    sequence: u32,
}

struct Unadmitted {
    id: u64,
    request: Request<Incoming>,
    reply: Reply,
    ticket: Option<Ticket>,
    deadline_ns: Option<u64>,
}

struct AStream {
    /// Keep the exact selected generation until the stream's body and reply are both retired.
    _policy: Option<Arc<Policy>>,
    _unit: UnitRef,
    /// The call's messages; `None` once the far end has sent its last.
    body: Option<(Incoming, Messages)>,
    reply: Reply,
    content_type: HeaderValue,
    head_buf: HeadBuf,
    head_sent: bool,
    reply_over: bool,
    deadline_ns: Option<u64>,
}

impl AStream {
    fn new(
        request: Request<Incoming>,
        reply: Reply,
        max: usize,
        policy: Option<Arc<Policy>>,
        unit: UnitRef,
        deadline_ns: Option<u64>,
    ) -> Self {
        let content_type = request
            .headers()
            .get(http::header::CONTENT_TYPE)
            .cloned()
            .expect("the accepted request was validated as gRPC");
        Self {
            _policy: policy,
            _unit: unit,
            body: Some((request.into_body(), Messages::new(max))),
            reply,
            content_type,
            head_buf: HeadBuf::default(),
            head_sent: false,
            reply_over: false,
            deadline_ns,
        }
    }

    /// Send the answer's head: `head`'s fields, and on a trailers-only answer `trailers`'.
    fn send_head(&mut self, head: &Head, trailers: Option<&Head>) -> Result<(), String> {
        let mut fields = HeaderMap::new();
        fields.insert(http::header::CONTENT_TYPE, self.content_type.clone());
        answer_fields(std::iter::once(head).chain(trailers), &mut fields)?;
        if trailers.is_none() {
            fields.remove(msg::GRPC_STATUS);
            fields.remove(msg::GRPC_MESSAGE);
            fields.remove("grpc-status-details-bin");
        }
        self.head_sent = true;
        self.reply.head(StatusCode::OK, fields);
        Ok(())
    }

    /// End the call with `trailers` (trailers-only before any head).
    fn finish(&mut self, trailers: &Head) -> Result<(), String> {
        if self.head_sent {
            let mut map = HeaderMap::new();
            answer_fields([trailers], &mut map)?;
            self.reply.chan.push(Frame::trailers(map));
        } else {
            self.send_head(&Head::default(), Some(trailers))?;
        }
        self.reply.chan.end();
        self.reply_over = true;

        self.body = None;
        Ok(())
    }

    fn fail_reply(&mut self, code: u16, why: &[u8]) {
        let done = self.finish(&Head {
            fields: vec![
                (msg::GRPC_STATUS.into(), code.to_string().into_bytes()),
                (
                    msg::GRPC_MESSAGE.into(),
                    msg::encode_status_message(why).into_bytes(),
                ),
            ],
            content_length: None,
        });
        debug_assert!(done.is_ok(), "{done:?}");
    }
}

/// Fields this layer owns on an answer's head, beside the hop-by-hop ones.
const RESERVED_ON_ANSWER: &[&str] = &["content-type", "content-length"];

/// Whether an answer field named `name` (lower case) is never the host's to send: one this layer
/// owns ([`RESERVED_ON_ANSWER`]), or a connection-specific one HTTP/2 forbids in every field block
/// (RFC 9113 §8.2.2).
pub(crate) fn not_the_hosts(name: &str) -> bool {
    RESERVED_ON_ANSWER.contains(&name) || hop_by_hop(name, [])
}

/// The answer fields `blocks` state, appended to `map` in order: a head's or the trailers' alike,
/// those this layer owns ([`RESERVED_ON_ANSWER`]) and the connection-specific ones HTTP/2 forbids in
/// every field block (RFC 9113 §8.2.2) dropped.
fn answer_fields<'h>(
    blocks: impl IntoIterator<Item = &'h Head>,
    map: &mut HeaderMap,
) -> Result<(), String> {
    for h in blocks {
        for (name, value) in &h.fields {
            if not_the_hosts(name) {
                continue;
            }
            let n = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| format!("`{name}` is not a field name"))?;
            let v = HeaderValue::from_bytes(value)
                .map_err(|_| format!("`{name}`'s value is not a field value"))?;
            map.append(n, v);
        }
    }
    Ok(())
}

fn cancelled_request(body: Option<&mut Incoming>, cx: &mut Context<'_>) -> (u16, String) {
    if let Some(body) = body {
        loop {
            match Pin::new(&mut *body).poll_frame(cx) {
                Poll::Ready(Some(Err(error))) => return wire_failure(&error),
                Poll::Ready(Some(Ok(_))) => {}
                Poll::Ready(None) | Poll::Pending => break,
            }
        }
    }
    (msg::CANCELLED, "the far end cancelled the call".into())
}

/// End a request before it was admitted; no host task or unit exists yet.
fn close_unadmitted(reply: &Reply, code: u16, why: &str) {
    let mut fields = HeaderMap::new();
    fields.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static(msg::CONTENT_TYPE),
    );
    fields.insert(msg::GRPC_STATUS, HeaderValue::from(code));
    fields.insert(
        msg::GRPC_MESSAGE,
        HeaderValue::from_str(&msg::encode_status_message(why.as_bytes()))
            .expect("encoded message"),
    );
    reply.head(StatusCode::OK, fields);
    reply.chan.end();
}

impl Accept {
    fn next_deadline(&self) -> Option<u64> {
        self.waiting
            .iter()
            .filter_map(|request| request.deadline_ns)
            .chain(
                self.calls
                    .iter()
                    .filter(|(_, stream)| !stream.reply_over)
                    .filter_map(|(_, stream)| stream.deadline_ns),
            )
            .min()
    }

    fn expire(&mut self, out: &mut VecDeque<Piece>, room: &mut Room) {
        self.waiting.retain_mut(|request| {
            if !request
                .deadline_ns
                .is_some_and(|deadline| self.now_ns >= deadline)
            {
                return true;
            }
            if let (Some(policy), Some(ticket)) = (&mut self.policy, request.ticket) {
                policy.loans.cancel(ticket);
            }
            close_unadmitted(&request.reply, msg::DEADLINE_EXCEEDED, "deadline exceeded");
            self.ended.insert(request.id);
            out.push_back(Piece {
                status: Some(msg::DEADLINE_EXCEEDED),
                ..Piece::failure(request.id, "deadline exceeded")
            });
            false
        });
        for (id, stream) in &mut self.calls {
            if stream.reply_over
                || !stream
                    .deadline_ns
                    .is_some_and(|deadline| self.now_ns >= deadline)
            {
                continue;
            }
            if let Some((_, messages)) = &stream.body {
                room.partial = room.partial.saturating_sub(messages.buffered());
            }
            stream.reply.chan.drop_queued();
            stream.fail_reply(msg::DEADLINE_EXCEEDED, b"deadline exceeded");
            out.push_back(Piece {
                status: Some(msg::DEADLINE_EXCEEDED),
                ..Piece::failure(*id, "deadline exceeded")
            });
        }
    }

    fn admit(
        &mut self,
        out: &mut VecDeque<Piece>,
        max: usize,
        host: &mut dyn Admission,
        reply: &mut Out<'_, FramerOut>,
    ) -> Result<AdmissionProgress, Failure> {
        let Some(policy) = &mut self.policy else {
            return Ok(AdmissionProgress::Idle);
        };
        let ticket = host.ticket();
        let at = self
            .waiting
            .iter()
            .position(|request| request.ticket == Some(ticket))
            .or_else(|| {
                self.waiting
                    .iter()
                    .position(|request| request.ticket.is_none())
            });
        let Some(at) = at else {
            return Ok(AdmissionProgress::Idle);
        };
        let request = &mut self.waiting[at];
        if request.reply.chan.gone() {
            policy.loans.cancel(request.ticket.unwrap_or(ticket));
            let mut request = self.waiting.remove(at).expect("position above");
            let mut cx = Context::from_waker(std::task::Waker::noop());
            let (code, why) = cancelled_request(Some(request.request.body_mut()), &mut cx);
            self.ended.insert(request.id);
            out.push_back(Piece {
                status: Some(code),
                ..Piece::failure(request.id, &why)
            });
            return Ok(AdmissionProgress::Published);
        }
        request.ticket = Some(ticket);
        let loan = match host.open(&mut policy.loans, request.id, reply) {
            Ok(Some(loan)) => loan,
            Ok(None) => return Ok(AdmissionProgress::Requested),
            Err(error) => {
                policy.loans.cancel(ticket);
                let request = self.waiting.remove(at).expect("position above");
                request.reply.chan.reset();
                request
                    .reply
                    .head(StatusCode::SERVICE_UNAVAILABLE, HeaderMap::new());
                self.ended.insert(request.id);
                out.push_back(Piece {
                    status: Some(msg::INTERNAL),
                    ..Piece::failure(request.id, &error.0)
                });
                return Err(error);
            }
        };
        let request = self.waiting.remove(at).expect("position above");
        let req = &request.request;
        let fields: Vec<_> = req
            .headers()
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_bytes()))
            .collect();
        let view = HeadViewArgs {
            method: req.method().as_str(),
            target: req.uri().path(),
            authority: req.uri().authority().map_or_else(
                || {
                    req.headers()
                        .get(http::header::HOST)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                },
                http::uri::Authority::as_str,
            ),
            query: req.uri().query(),
            fields: &fields,
            scheme: policy.scheme,
        };
        let decision = host.hand_in(request.id, &loan, &view, &mut policy.sequence);
        drop(fields);
        match decision {
            Ok(Ok(unit)) => self.publish(request, max, Some(loan), unit, out),
            Ok(Err(refusal)) => {
                let mut stream = AStream::new(
                    request.request,
                    request.reply,
                    max,
                    Some(loan),
                    UnitRef::NONE,
                    request.deadline_ns,
                );

                let validated = (|| {
                    let mut fields = HeaderMap::new();
                    for (name, value) in refusal.fields {
                        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                            Failure("the host refusal has an invalid field name".into())
                        })?;
                        let value = HeaderValue::from_bytes(&value).map_err(|_| {
                            Failure("the host refusal has an invalid field value".into())
                        })?;
                        fields.append(name, value);
                    }
                    let status = u16::try_from(refusal.status)
                        .ok()
                        .filter(|status| (100..=599).contains(status))
                        .and_then(|status| StatusCode::from_u16(status).ok())
                        .ok_or_else(|| Failure("the host refusal has an invalid status".into()))?;
                    Ok::<_, Failure>((status, fields))
                })();
                let (status, fields) = match validated {
                    Ok(validated) => validated,
                    Err(error) => {
                        stream.reply.chan.reset();
                        stream
                            .reply
                            .head(StatusCode::SERVICE_UNAVAILABLE, HeaderMap::new());
                        self.ended.insert(request.id);
                        out.push_back(Piece {
                            status: Some(msg::INTERNAL),
                            ..Piece::failure(request.id, &error.0)
                        });
                        return Err(error);
                    }
                };
                stream.reply.head(status, fields);
                stream
                    .reply
                    .chan
                    .push(Frame::data(Bytes::from(refusal.body)));
                stream.reply.chan.end();
                stream.body = None;
                stream.reply_over = true;
                self.calls.push((request.id, stream));
                out.push_back(Piece {
                    status: Some(msg::status_of_http(status.as_u16())),
                    ..Piece::failure(request.id, "the host refused the call")
                });
            }
            Err(error) => {
                request.reply.chan.reset();
                request
                    .reply
                    .head(StatusCode::SERVICE_UNAVAILABLE, HeaderMap::new());
                self.ended.insert(request.id);
                out.push_back(Piece {
                    status: Some(msg::INTERNAL),
                    ..Piece::failure(request.id, &error.0)
                });
                return Err(error);
            }
        }
        Ok(AdmissionProgress::Published)
    }

    fn publish(
        &mut self,
        request: Unadmitted,
        max: usize,
        policy: Option<Arc<Policy>>,
        unit: UnitRef,
        out: &mut VecDeque<Piece>,
    ) {
        let Unadmitted {
            id,
            request: req,
            reply,
            deadline_ns,
            ..
        } = request;
        let target = req.uri().path_and_query().map_or("/", |p| p.as_str());
        let words = HeadWords {
            method: Bytes::copy_from_slice(req.method().as_str().as_bytes()),
            target: Bytes::copy_from_slice(target.as_bytes()),
            authority: req.uri().authority().map_or_else(Bytes::new, |a| {
                Bytes::copy_from_slice(a.as_str().as_bytes())
            }),
            reason: Bytes::new(),
        };
        out.push_back(Piece {
            head: Some(words),
            ..Piece::fields(
                id,
                held_bytes(HeadBuf::new(field_block(req.headers(), &[]))),
            )
        });
        self.calls
            .push((id, AStream::new(req, reply, max, policy, unit, deadline_ns)));
    }

    /// An op on `stream`, which this connection does not hold: dropped when the call ended (A
    /// STREAM ENDS ONCE), else no such stream.
    fn late(&self, stream: u64) -> Result<(), Failure> {
        if self.ended.contains(stream) {
            Ok(())
        } else {
            Err(Failure(format!("no such stream: {stream}")))
        }
    }

    fn step(
        &mut self,
        out: &mut VecDeque<Piece>,
        room: &mut Room,
        max: usize,
        cx: &mut Context<'_>,
    ) {
        // Deadlines still cancel work while the host is backpressured.
        self.expire(out, room);
        if !room.open() {
            return;
        }
        self.waiting.retain_mut(|request| {
            if !request.reply.chan.gone() {
                return true;
            }
            if let (Some(policy), Some(ticket)) = (&mut self.policy, request.ticket) {
                policy.loans.cancel(ticket);
            }
            let (code, why) = cancelled_request(Some(request.request.body_mut()), cx);
            self.ended.insert(request.id);
            out.push_back(Piece {
                status: Some(code),
                ..Piece::failure(request.id, &why)
            });
            false
        });
        let new: Vec<_> = self
            .arrivals
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .new
            .drain(..)
            .collect();
        for (id, req, reply) in new {
            if req.method() != http::Method::POST {
                // gRPC calls are POSTs (PROTOCOL-HTTP2.md): answered here, never handed up.
                let mut fields = HeaderMap::new();
                fields.insert(http::header::ALLOW, HeaderValue::from_static("POST"));
                reply.head(StatusCode::METHOD_NOT_ALLOWED, fields);
                reply.chan.end();
                // Never handed up, and its id is used: ended, so the ended runs stay contiguous.
                self.ended.insert(id);
                continue;
            }
            if !req
                .headers()
                .get(http::header::CONTENT_TYPE)
                .is_some_and(|v| msg::is_grpc_content_type(v.as_bytes()))
            {
                reply.head(StatusCode::UNSUPPORTED_MEDIA_TYPE, HeaderMap::new());
                reply.chan.end();
                // Never handed up, and its id is used: ended, so the ended runs stay contiguous.
                self.ended.insert(id);
                continue;
            }
            if let Some(bad) = req
                .headers()
                .get(msg::GRPC_ENCODING)
                .and_then(|v| msg::unsupported_encoding(v.as_bytes()))
            {
                let mut fields = HeaderMap::new();
                fields.insert(
                    http::header::CONTENT_TYPE,
                    HeaderValue::from_static(msg::CONTENT_TYPE),
                );
                fields.insert(
                    msg::GRPC_ACCEPT_ENCODING,
                    HeaderValue::from_static(msg::ACCEPT_ENCODING),
                );
                fields.insert(msg::GRPC_STATUS, HeaderValue::from(bad.status()));
                if let Ok(text) =
                    HeaderValue::from_str(&msg::encode_status_message(bad.to_string().as_bytes()))
                {
                    fields.insert(msg::GRPC_MESSAGE, text);
                }
                reply.head(StatusCode::OK, fields);
                reply.chan.end();
                // Never handed up, and its id is used: ended, so the ended runs stay contiguous.
                self.ended.insert(id);
                continue;
            }
            let received = req
                .extensions()
                .get::<ReceivedAt>()
                .map_or(self.now_ns, |at| at.0);
            let deadline_ns = match req.headers().get(msg::GRPC_TIMEOUT) {
                Some(value) => match msg::timeout_ns(value.as_bytes()) {
                    Ok(timeout) => Some(received.saturating_add(timeout)),
                    Err(why) => {
                        close_unadmitted(&reply, msg::INVALID_ARGUMENT, why);
                        self.ended.insert(id);
                        continue;
                    }
                },
                None => None,
            };
            if deadline_ns.is_some_and(|deadline| self.now_ns >= deadline) {
                close_unadmitted(&reply, msg::DEADLINE_EXCEEDED, "deadline exceeded");
                self.ended.insert(id);
                continue;
            }
            if self.policy.is_some() {
                if self.waiting.len() >= PENDING_REQUEST_LIMIT {
                    reply.head(StatusCode::SERVICE_UNAVAILABLE, HeaderMap::new());
                    reply.chan.end();
                    self.ended.insert(id);
                    continue;
                }
                self.waiting.push_back(Unadmitted {
                    id,
                    request: req,
                    reply,
                    ticket: None,
                    deadline_ns,
                });
            } else {
                self.publish(
                    Unadmitted {
                        id,
                        request: req,
                        reply,
                        ticket: None,
                        deadline_ns,
                    },
                    max,
                    None,
                    UnitRef::NONE,
                    out,
                );
            }
        }
        room.held_back |= !self.waiting.is_empty();
        for at in room.order(self.calls.len()) {
            let (id, s) = &mut self.calls[at];
            if !s.reply_over && s.reply.chan.gone() {
                let (code, why) = cancelled_request(s.body.as_mut().map(|(body, _)| body), cx);
                if let Some((_, msgs)) = &s.body {
                    room.partial = room.partial.saturating_sub(msgs.buffered());
                }
                s.body = None;
                s.reply_over = true;
                s.reply.chan.end();
                out.push_back(Piece {
                    status: Some(code),
                    ..Piece::failure(*id, &why)
                });
                continue;
            }
            while let Some((b, msgs)) = s.body.as_mut() {
                if !room.open() {
                    break;
                }
                match Pin::new(&mut *b).poll_frame(cx) {
                    Poll::Pending => break,
                    Poll::Ready(Some(Ok(fr))) => {
                        if let Ok(d) = fr.into_data() {
                            if room.partial.saturating_add(d.len()) > stream_bound(max) {
                                room.partial = room.partial.saturating_sub(msgs.buffered());
                                s.body = None;
                                s.fail_reply(
                                    msg::RESOURCE_EXHAUSTED,
                                    b"connection partial-message budget exceeded",
                                );
                                out.push_back(Piece {
                                    status: Some(msg::RESOURCE_EXHAUSTED),
                                    ..Piece::failure(
                                        *id,
                                        "connection partial-message budget exceeded",
                                    )
                                });
                                break;
                            }
                            room.partial = room.partial.saturating_sub(msgs.buffered());
                            match msgs.push_bytes(d) {
                                Ok(got) => {
                                    room.partial += msgs.buffered();
                                    room.took(&got);
                                    out.extend(got.into_iter().map(|m| Piece::data(*id, m)));
                                }
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
                        room.partial = room.partial.saturating_sub(msgs.buffered());
                        s.body = None;
                        match whole {
                            Ok(()) => out.push_back(Piece::end(*id)),
                            Err(e) => {
                                let why = e.to_string();
                                s.fail_reply(e.status(), why.as_bytes());
                                out.push_back(Piece {
                                    status: Some(e.status()),
                                    ..Piece::failure(*id, &why)
                                });
                            }
                        }
                    }
                    Poll::Ready(Some(Err(e))) => {
                        let (code, why) = wire_failure(&e);
                        room.partial = room.partial.saturating_sub(msgs.buffered());
                        s.body = None;
                        s.reply_over = true;
                        s.reply.chan.end();
                        out.push_back(Piece {
                            status: Some(code),
                            ..Piece::failure(*id, &why)
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
        let ended = &mut self.ended;
        self.calls.retain(|(id, s)| {
            let over = s.reply_over && s.body.is_none() && s.reply.chan.ended();
            if over {
                ended.insert(*id);
            }
            !over
        });
    }
}

#[cfg(test)]
#[path = "tests/engine_tests.rs"]
mod tests;
