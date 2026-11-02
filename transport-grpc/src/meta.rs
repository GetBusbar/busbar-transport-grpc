// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What this transport declares about itself: its key, the settings it reads, its status classes

use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::abi::sdk::transport::{setting_decls, SettingRow, DEFAULT_BODY_MAX};
use busbar_contract::abi::transport::{
    FaultRow, SettingDecl, StatusRow, TransportTail, FACT_ACCEPTS, FACT_DIALS, FAULT_CALLER,
    FAULT_HARD, FAULT_NONE, FAULT_TRANSIENT, FRAME_PIECE_SIZE, FRAMING_STREAM, ROLE_FRAMER,
    SETTING_COUNT, STATUS_CALLER_FAULT, STATUS_FAR_END_FAULT, STATUS_OTHER, STATUS_SUCCESS,
};
use busbar_contract::transport::registry::DEFAULT_REQUEST_TIMEOUT_SECS;

/// This transport's key: the scheme it claims.
pub const KEY: &str = "grpc";

/// Whether its claim carries sessions: a connection multiplexes calls, each its own stream and

pub(crate) const SESSION: bool = true;

/// The settings this transport reads.
pub mod setting {
    /// A dialled call's deadline when the host states none, in seconds.
    pub const REQUEST_TIMEOUT_SECS: &str = "limits.upstream_request_timeout_secs";
    /// The largest message carried, in bytes.
    pub const BODY_MAX_BYTES: &str = "limits.request_body_max_bytes";
}

/// What `grpc` composes over: NOTHING. No transport names another. The connector builds every

pub(crate) const COMPOSES_OVER: &[AbiStr] = &[];

/// `grpc-status` by class, as the canonical HTTP mapping of each code reads it: a `4xx` code is

pub(crate) const STATUS_ROWS: &[StatusRow] = &[
    row(0, 0, STATUS_SUCCESS),
    row(1, 1, STATUS_CALLER_FAULT),
    row(2, 2, STATUS_FAR_END_FAULT),
    row(3, 3, STATUS_CALLER_FAULT),
    row(4, 4, STATUS_FAR_END_FAULT),
    row(5, 11, STATUS_CALLER_FAULT),
    row(12, 15, STATUS_FAR_END_FAULT),
    row(16, 16, STATUS_CALLER_FAULT),
];

pub(crate) const fn row(lo: u32, hi: u32, class: u8) -> StatusRow {
    StatusRow {
        claim: 0,
        lo,
        hi,
        class: class as u32,
    }
}

pub(crate) fn class_of(code: u16) -> u8 {
    STATUS_ROWS
        .iter()
        .find(|r| (r.lo..=r.hi).contains(&u32::from(code)))
        .map_or(STATUS_OTHER, |r| r.class as u8)
}

/// What each `grpc-status` means to the BREAKER: the fault table, beside the status table and

pub(crate) const FAULT_ROWS: &[FaultRow] = &[
    fault_row(0, FAULT_CALLER),
    fault_row(1, FAULT_CALLER),
    fault_row(2, FAULT_TRANSIENT),
    fault_row(3, FAULT_CALLER),
    fault_row(4, FAULT_TRANSIENT),
    fault_row(5, FAULT_CALLER),
    fault_row(6, FAULT_CALLER),
    fault_row(7, FAULT_HARD),
    fault_row(8, FAULT_TRANSIENT),
    fault_row(9, FAULT_CALLER),
    fault_row(10, FAULT_TRANSIENT),
    fault_row(11, FAULT_CALLER),
    fault_row(12, FAULT_CALLER),
    fault_row(13, FAULT_TRANSIENT),
    fault_row(14, FAULT_TRANSIENT),
    fault_row(15, FAULT_TRANSIENT),
    fault_row(16, FAULT_HARD),
];

const fn fault_row(code: u32, fault: u8) -> FaultRow {
    FaultRow {
        claim: 0,
        lo: code,
        hi: code,
        fault: fault as u32,
    }
}

/// The breaker's reading of `code`, from the fault table (`FAULT_NONE` off it).
pub(crate) fn fault_of(code: u16) -> u8 {
    FAULT_ROWS
        .iter()
        .find(|r| (r.lo..=r.hi).contains(&u32::from(code)))
        .map_or(FAULT_NONE, |r| r.fault as u8)
}

/// How the breaker reads a BARE HTTP ANSWER (a far end, or a proxy or auth wall in front of it,

const HTTP_FAULTS: &[(u16, u16, u8)] = &[
    (401, 401, FAULT_HARD),
    (403, 403, FAULT_HARD),
    (408, 408, FAULT_TRANSIENT),
    (429, 429, FAULT_TRANSIENT),
    (500, 599, FAULT_TRANSIENT),
];

/// The breaker's reading of a bare HTTP answer's `status` ([`HTTP_FAULTS`]; off the table, the

pub(crate) fn fault_of_http(status: u16) -> u8 {
    HTTP_FAULTS
        .iter()
        .find(|(lo, hi, _)| (*lo..=*hi).contains(&status))
        .map_or(FAULT_CALLER, |(_, _, f)| *f)
}

/// The request timeout's declared default, as the decimal text a setting declaration states it in.
pub(crate) const DEFAULT_TIMEOUT: &str = "300";

/// `text` read as a decimal count (digits alone, as the declared defaults are).
pub(crate) const fn decimal(text: &str) -> u64 {
    let b = text.as_bytes();
    let mut n = 0;
    let mut i = 0;
    while i < b.len() {
        n = n * 10 + (b[i] - b'0') as u64;
        i += 1;
    }
    n
}

const _: () = assert!(decimal(DEFAULT_TIMEOUT) == DEFAULT_REQUEST_TIMEOUT_SECS);

pub(crate) const SETTING_ROWS: [SettingRow; 2] = [
    SettingRow {
        path: setting::REQUEST_TIMEOUT_SECS,
        kind: SETTING_COUNT,
        default: DEFAULT_TIMEOUT,
    },
    SettingRow {
        path: setting::BODY_MAX_BYTES,
        kind: SETTING_COUNT,
        default: DEFAULT_BODY_MAX,
    },
];

pub(crate) const SETTINGS: &[SettingDecl] = &setting_decls(&SETTING_ROWS);

pub(crate) const TAIL: TransportTail = {
    let mut t = TransportTail::EMPTY
        .with_composes_over(COMPOSES_OVER)
        .with_claim_rows(crate::claims::CLAIMS)
        .with_status_rows(STATUS_ROWS)
        .with_settings(SETTINGS)
        .with_fault_rows(FAULT_ROWS);
    t.role = ROLE_FRAMER;
    t.framing = FRAMING_STREAM;
    t.frame_piece_size = FRAME_PIECE_SIZE;

    t.facts = FACT_ACCEPTS | FACT_DIALS;
    t
};
