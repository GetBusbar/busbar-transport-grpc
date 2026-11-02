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

use crate::hyper_io::{field_block, HeadWords, HostIo, Owed, Piece};
use busbar_contract::abi::host::service::UnitRef;
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::services::{HeadViewArgs, RefusalCopy};
use busbar_contract::abi::sdk::transport::policy::Loans;
use busbar_contract::abi::sdk::Out;
use busbar_contract::abi::transport::fields::hop_by_hop;
use busbar_contract::abi::transport::guest_policy::Policy;
use busbar_contract::abi::transport::sensitive_fields::SensitiveFields;
use busbar_contract::abi::transport::FramerOut;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode};
use http_body::{Body, Frame};
use hyper::body::Incoming;
use hyper::client::conn::http2 as client;
use hyper::rt::{Executor, Sleep};
use hyper::server::conn::http2 as server;

use crate::msg::{self, Head, Messages};

/// A head block the host emitted, held until it is whole: wiped when it drops, since a dialled
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
    /// The largest message payload carried, either way.
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
pub(crate) const STREAM_HIGH_WATER: usize = 1 << 20;

/// A stream answered full that has drained to this many queued bytes is writable again
pub(crate) const STREAM_LOW_WATER: usize = 256 * 1024;

/// THE HOST'S OWN BACKPRESSURE, the other way: what a connection holds for the host (pieces handed
const INBOUND_HIGH_WATER: usize = STREAM_HIGH_WATER;

/// What one piece held for the host counts beside its bytes ([`INBOUND_HIGH_WATER`]).
const PIECE_COST: usize = 64;

/// What `out` holds for the host, as [`INBOUND_HIGH_WATER`] counts it.
fn held_for_host(out: &VecDeque<Piece>) -> usize {
    out.iter().map(|p| p.bytes.len() + PIECE_COST).sum()
}

/// Why a stream whose host emitted past its bound (the high-water mark and one whole message
pub(crate) const OVER_BOUND: &str =
    "the stream's queue is past its bound: the far end is not reading";

/// The room a head block may take beside one whole message: an answer's head block is read up to
pub(crate) const HEAD_ALLOWANCE: usize = 64 * 1024;

/// A STREAM'S BOUND: the payload bytes it may queue for the far end before a host that keeps
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
    type Error = std::io::Error;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        let mut s = self.0 .0.lock().unwrap_or_else(PoisonError::into_inner);
        if s.reset {
            return Poll::Ready(Some(Err(std::io::Error::other("the stream was failed"))));
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
    conn_err: Arc<Mutex<Option<String>>>,
    conn_done: Arc<AtomicBool>,
    failed: Option<Failure>,
    posture: Posture,
    side: Side,
    /// The last drive left a body unread because the host had not taken what it was handed
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
    fn wire_pending(&self) -> bool {
        self.failed.is_none() && (self.io.wire_pending() || self.held_back)
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
            *err.lock().unwrap_or_else(PoisonError::into_inner) = Some(e.to_string());
        }
        done.store(true, Ordering::Release);
    }));
}

impl Conn {
    /// Open a dialled connection to `target` (an `http`/`https` URL: its scheme and authority are
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
        let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
            let reply = Reply::default();
            {
                let mut a = svc_arrivals.lock().unwrap_or_else(PoisonError::into_inner);
                a.next += 1;
                let id = a.next;
                a.new.push_back((id, req, reply.clone()));
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
                    self.out.push_back(Piece {
                        status: Some(msg::INTERNAL),
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
                    s.head_buf.extend_from_slice(bytes);
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
        let r = io.rounds(|cx| {
            self.tasks.run(cx);
            let mut room = Room::of(&self.out, turn);
            let r = match &mut self.side {
                Side::Dial(d) => d.step(&mut self.out, &mut room, max, cx),
                Side::Accept(a) => {
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
            .clone();
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

    /// Why this framing failed, once it has.
    #[must_use]
    pub fn failure(&self) -> Option<&Failure> {
        self.failed.as_ref()
    }
}

/// What one drive round may still hand the host before it reads no more ([`INBOUND_HIGH_WATER`]).
struct Room {
    held: usize,
    /// A body was left unread for the host's sake.
    held_back: bool,
    /// The stream this drive reads first: each drive starts one further on.
    first: usize,
}

impl Room {
    fn of(out: &VecDeque<Piece>, first: usize) -> Self {
        Self {
            held: held_for_host(out),
            held_back: false,
            first,
        }
    }

    /// The order a round reads `n` streams in: from [`Room::first`] round, so that while the host is
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
                buf.extend_from_slice(bytes);
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
const RESERVED_ON_REQUEST: &[&str] = &[
    "path",
    "method",
    "authority",
    "content-type",
    msg::GRPC_TIMEOUT,
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
    ) -> Result<(), Failure> {
        if let Some(h) = self.handshake.as_mut() {
            if let Poll::Ready(r) = h.as_mut().poll(cx) {
                self.handshake = None;
                self.sender = Some(r.map_err(|e| Failure(e.to_string()))?);
            }
        }
        for at in room.order(self.calls.len()) {
            let (id, s) = &mut self.calls[at];
            if let Err((why, code, conn)) = advance(*id, s, &mut self.sender, out, room, max, cx) {
                if conn {
                    return Err(Failure(why));
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
        Ok(())
    }
}

/// Move one dialled stream as far as it goes this round. `Err((why, code, true))` is the
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
                        let got = msgs
                            .push_bytes(d)
                            .map_err(|e| (dial_bad_text(&e), e.status(), false))?;
                        room.took(&got);
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
        "the connection to the far end was lost".into(),
    )
}

/// What a dialled answer that is no message stream is called, in this framer's own words.
fn dial_bad_text(e: &msg::Bad) -> String {
    match e {
        msg::Bad::TooLarge(n, limit) => {
            format!("the answer's message is {n} bytes, over the limit of {limit} bytes")
        }
        other => other.to_string(),
    }
}

/// The fields the trailers' code and the terminal piece carry, never a field block's.
const STATUS_FIELDS: &[&str] = &[msg::GRPC_STATUS, msg::GRPC_MESSAGE];

/// The stream's end, from the fields that carry `grpc-status` (`status`): the trailers (`fields`
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
        .unwrap_or_else(|| format!("grpc-status {code}").into_bytes());
    [
        block,
        Piece {
            failed: true,
            ..Piece::data(id, Bytes::from(text))
        },
    ]
}

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
    ended: Ended,
    policy: Option<AcceptedPolicy>,
    waiting: VecDeque<Unadmitted>,
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
}

impl AStream {
    fn new(
        request: Request<Incoming>,
        reply: Reply,
        max: usize,
        policy: Option<Arc<Policy>>,
        unit: UnitRef,
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
        }
    }

    /// Send the answer's head: `head`'s fields, and on a trailers-only answer `trailers`'.
    fn send_head(&mut self, head: &Head, trailers: Option<&Head>) -> Result<(), String> {
        let mut fields = HeaderMap::new();
        fields.insert(http::header::CONTENT_TYPE, self.content_type.clone());
        answer_fields(std::iter::once(head).chain(trailers), &mut fields)?;
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
pub(crate) fn not_the_hosts(name: &str) -> bool {
    RESERVED_ON_ANSWER.contains(&name) || hop_by_hop(name, [])
}

/// The answer fields `blocks` state, appended to `map` in order: a head's or the trailers' alike,
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

impl Accept {
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
            let request = self.waiting.remove(at).expect("position above");
            self.ended.insert(request.id);
            out.push_back(Piece {
                status: Some(msg::CANCELLED),
                ..Piece::failure(request.id, "the far end cancelled the call")
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
                let refused_status = msg::status_of_refusal(u32::from(refusal.status));
                let mut stream = AStream::new(
                    request.request,
                    request.reply,
                    max,
                    Some(loan),
                    UnitRef::NONE,
                );

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
                let status = StatusCode::from_u16(refusal.status)
                    .map_err(|_| Failure("the host refusal has an invalid status".into()))?;
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
                    status: Some(refused_status),
                    ..Piece::failure(request.id, "the host refused the call")
                });
            }
            Err(error) => {
                request.reply.chan.reset();
                request
                    .reply
                    .head(StatusCode::SERVICE_UNAVAILABLE, HeaderMap::new());
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
            ..Piece::fields(id, Bytes::from(field_block(req.headers(), &[])))
        });
        self.calls
            .push((id, AStream::new(req, reply, max, policy, unit)));
    }

    /// An op on `stream`, which this connection does not hold: dropped when the call ended (A
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
        let new: Vec<_> = self
            .arrivals
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .new
            .drain(..)
            .collect();
        for (id, req, reply) in new {
            let ct = req.headers().get(http::header::CONTENT_TYPE).cloned();
            let Some(_ct) = ct.filter(|v| msg::is_grpc_content_type(v.as_bytes())) else {
                reply.head(StatusCode::UNSUPPORTED_MEDIA_TYPE, HeaderMap::new());
                reply.chan.end();
                continue;
            };
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
                continue;
            }
            if self.policy.is_some() {
                self.waiting.push_back(Unadmitted {
                    id,
                    request: req,
                    reply,
                    ticket: None,
                });
            } else {
                self.publish(
                    Unadmitted {
                        id,
                        request: req,
                        reply,
                        ticket: None,
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
                s.body = None;
                s.reply_over = true;
                s.reply.chan.end();
                out.push_back(Piece {
                    status: Some(msg::CANCELLED),
                    ..Piece::failure(*id, "the far end cancelled the call")
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
                            match msgs.push_bytes(d) {
                                Ok(got) => {
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
                        s.body = None;
                        match whole {
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
