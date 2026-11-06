// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Request timeout defaults use the host clock before authentication signs the head.

mod common;

use std::cell::Cell;
use std::ffi::c_void;
use std::mem::size_of;

use busbar_contract::abi::host::service::{ClockNowIn, HostSlots, ServiceOut, SERVICES};
use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome, RawOutcome};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables, Ticket};
use busbar_contract::abi::transport::{slot, LocateIn, LocateOut, Ops};
use common::{call, dropped, linked, s, z};

const NOW: u64 = 9_000_000;
const STATIC: &str = "content-type: application/grpc\r\nte: trailers\r\n";

thread_local! {
    static CLOCK_CALLED: Cell<bool> = const { Cell::new(false) };
    static CLOCK_TICKETLESS: Cell<bool> = const { Cell::new(false) };
}

extern "C" fn clock(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: CLOCK_NOW lends its concrete frame and writable reading for this call.
    unsafe {
        let input = &*input.cast::<ClockNowIn>();
        CLOCK_CALLED.with(|called| called.set(true));
        CLOCK_TICKETLESS.with(|none| none.set(input.head.handle.ticket == Ticket::NONE));
        (*input.reading).mono_ns = NOW;
        (*input.reading).wall_ns = 1_790_000_000_000_000_000;
        (*out).outcome = RawOutcome::of(Outcome::Ready);
    }
    RawOutcome::of(Outcome::Ready)
}

extern "C" fn failed_clock(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the clock service lends a writable ServiceOut.
    unsafe { (*out).outcome = RawOutcome::of(Outcome::Failed) };
    RawOutcome::of(Outcome::Failed)
}

#[derive(Clone, Copy)]
enum Clock {
    Available,
    Missing,
    Failed,
    NoHost,
}

fn locate(
    ops: &'static Ops,
    deadline_ns: u64,
    clock_mode: Clock,
    defaults_cap: usize,
) -> (Outcome, LocateOut, String) {
    CLOCK_CALLED.with(|called| called.set(false));
    CLOCK_TICKETLESS.with(|none| none.set(false));
    let mut services: HostSlots = z();
    services.size = size_of::<HostSlots>() as u32;
    services.slots = SERVICES;
    services.clock_now = match clock_mode {
        Clock::Available => Some(clock),
        Clock::Failed => Some(failed_clock),
        Clock::Missing | Clock::NoHost => None,
    };
    let mut tables: HostTables = z();
    tables.size = size_of::<HostTables>() as u32;
    tables.services = &services;
    let mut input: OpenIn = z();
    if !matches!(clock_mode, Clock::NoHost) {
        input.host = &tables;
    }
    let mut opened: OpenOut = z();
    // SAFETY: the exact lifecycle frames and nested host tables remain live through close.
    assert_eq!(
        unsafe {
            call(
                ops.head.open,
                std::ptr::null_mut(),
                &mut input,
                &mut opened,
                life::OPEN,
            )
        },
        Outcome::Ready
    );
    let mut authority = [0_u8; 256];
    let mut name = [0_u8; 256];
    let mut alpn = [0_u8; 64];
    let mut defaults = vec![0_u8; defaults_cap];
    let mut input: LocateIn = z();
    input.head.deadline_ns = deadline_ns;
    input.target = s("https://peer.test");
    input.authority_buf = authority.as_mut_ptr();
    input.authority_cap = authority.len();
    input.name_buf = name.as_mut_ptr();
    input.name_cap = name.len();
    input.alpn_buf = alpn.as_mut_ptr();
    input.alpn_cap = alpn.len();
    input.defaults_buf = defaults.as_mut_ptr();
    input.defaults_cap = defaults.len();
    let mut out: LocateOut = z();
    // SAFETY: the matching input/output and all buffers remain live for this crossing.
    let outcome = unsafe {
        call(
            ops.locate,
            opened.instance,
            &mut input,
            &mut out,
            slot::LOCATE,
        )
    };
    let rendered = String::from_utf8(defaults[..out.defaults_written as usize].to_vec()).unwrap();
    let mut input: InHead = z();
    let mut closed: OutHead = z();
    // SAFETY: close consumes this live instance after all synchronous crossings returned.
    assert_eq!(
        unsafe {
            call(
                ops.head.close,
                opened.instance,
                &mut input,
                &mut closed,
                life::CLOSE,
            )
        },
        Outcome::Ready
    );
    (outcome, out, rendered)
}

#[test]
fn locate_prepares_remaining_timeout_defaults_from_the_host_clock() {
    let (d, _library) = dropped();
    for ops in [linked(), d] {
        for (deadline, expected) in [(NOW + 3_000_000, "3000000n"), (NOW, "0n"), (NOW - 1, "0n")] {
            let (outcome, _, rendered) = locate(ops, deadline, Clock::Available, 256);
            assert_eq!(outcome, Outcome::Ready);
            assert_eq!(rendered, format!("{STATIC}grpc-timeout: {expected}\r\n"));
            CLOCK_CALLED.with(|called| assert!(called.get()));
            CLOCK_TICKETLESS.with(|none| assert!(none.get()));
        }
    }
}

#[test]
fn locate_timeout_preparation_fails_closed_without_a_working_host_clock() {
    let (d, _library) = dropped();
    for ops in [linked(), d] {
        for clock in [Clock::NoHost, Clock::Missing, Clock::Failed] {
            let (outcome, out, rendered) = locate(ops, NOW + 1, clock, 256);
            assert_eq!(outcome, Outcome::Failed);
            assert_eq!(out.defaults_written, 0);
            assert!(rendered.is_empty());
        }
        // A working clock service is installed, but no deadline asks for it: it is never called.
        let (outcome, _, rendered) = locate(ops, 0, Clock::Available, 256);
        assert_eq!(outcome, Outcome::Ready);
        assert_eq!(rendered, STATIC);
        CLOCK_CALLED.with(|called| assert!(!called.get()));
    }
}

#[test]
fn locate_without_a_deadline_needs_no_host_clock() {
    let (d, _library) = dropped();
    for ops in [linked(), d] {
        for clock in [Clock::NoHost, Clock::Missing] {
            let (outcome, out, rendered) = locate(ops, 0, clock, 256);
            assert_eq!(outcome, Outcome::Ready);
            assert_eq!(out.defaults_written as usize, STATIC.len());
            assert_eq!(rendered, STATIC);
            CLOCK_CALLED.with(|called| assert!(!called.get()));
        }
    }
}

#[test]
fn locate_timeout_defaults_participate_in_short_buffer_accounting() {
    let (d, _library) = dropped();
    for ops in [linked(), d] {
        let expected = format!("{STATIC}grpc-timeout: 3000000n\r\n");
        for cap in [0, expected.len() - 1] {
            let (outcome, out, rendered) = locate(ops, NOW + 3_000_000, Clock::Available, cap);
            assert_eq!(outcome, Outcome::Failed);
            assert_eq!(out.defaults_needed, expected.len() as u64);
            assert_eq!(out.defaults_written, 0);
            assert!(rendered.is_empty());
        }
        let (outcome, _, rendered) = locate(ops, NOW + 3_000_000, Clock::Available, expected.len());
        assert_eq!(outcome, Outcome::Ready);
        assert_eq!(rendered, expected);
    }
}
