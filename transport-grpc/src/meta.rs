// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What this transport declares about itself: its key, the settings it reads, its status classes
//! and the transport kind's tail its door states. Read once at registration and sealed, so it is data, held apart from the framing
//! code it describes.

use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::abi::sdk::door::abi_str;
use busbar_contract::abi::sdk::transport::DEFAULT_BODY_MAX;
use busbar_contract::abi::transport::{
    FaultRow, SettingDecl, StatusRow, TransportTail, FAULT_CALLER, FAULT_HARD, FAULT_NONE,
    FAULT_TRANSIENT, FRAME_PIECE_SIZE, FRAMING_STREAM, ROLE_FRAMER, SETTING_COUNT,
    STATUS_CALLER_FAULT, STATUS_FAR_END_FAULT, STATUS_OTHER, STATUS_SUCCESS,
};
use busbar_contract::transport::registry::DEFAULT_REQUEST_TIMEOUT_SECS;

/// This transport's key: the scheme it claims.
pub const KEY: &str = "grpc";

/// The settings this transport reads.
pub mod setting {
    /// A dialled call's deadline when the host states none, in seconds.
    pub const REQUEST_TIMEOUT_SECS: &str = "limits.upstream_request_timeout_secs";
    /// The largest message carried, in bytes.
    pub const BODY_MAX_BYTES: &str = "limits.request_body_max_bytes";
}

/// What `grpc` composes over: NOTHING. No transport names another. The connector builds every
/// connection as carrier -> [TLS] -> framer, and it picks the carrier from the target's scheme.
/// This framer frames whatever bytes it is handed. HTTP/2 is its own.
pub(crate) const COMPOSES_OVER: &[AbiStr] = &[];

/// `grpc-status` by class, as the canonical HTTP mapping of each code reads it: a `4xx` code is
/// the caller's fault, a `5xx` the far end's.
pub(crate) const STATUS_ROWS: &[StatusRow] = &[
    row(0, 0, STATUS_SUCCESS),
    // CANCELLED (499).
    row(1, 1, STATUS_CALLER_FAULT),
    // UNKNOWN (500).
    row(2, 2, STATUS_FAR_END_FAULT),
    // INVALID_ARGUMENT (400).
    row(3, 3, STATUS_CALLER_FAULT),
    // DEADLINE_EXCEEDED (504).
    row(4, 4, STATUS_FAR_END_FAULT),
    // NOT_FOUND .. OUT_OF_RANGE (404, 409, 403, 429, 400, 409, 400).
    row(5, 11, STATUS_CALLER_FAULT),
    // UNIMPLEMENTED .. DATA_LOSS (501, 500, 503, 500).
    row(12, 15, STATUS_FAR_END_FAULT),
    // UNAUTHENTICATED (401).
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
/// never folded into it (the status class is the fee decision's leg, and the two disagree where the
/// money and the destination's health do). One row per code gRPC defines, this wire's own reading,
/// held by the wire that owns the numbering. `ABORTED` reads transient (a conflict the far end
/// reports, which a retry may clear); `UNIMPLEMENTED` reads as the caller's (a method the far end
/// does not serve is the caller's request, and costs the destination nothing).
///
/// - `RESOURCE_EXHAUSTED` is the upstream's quota, not the caller's mistake: transient, and the
///   upstream's own wait is the cooldown floor.
/// - `UNAUTHENTICATED` and `PERMISSION_DENIED` are a withdrawn or rejected credential: hard, every
///   sibling lane naming the destination goes down with it.
/// - `INVALID_ARGUMENT`, `NOT_FOUND` and their neighbours are the caller's own request: caller.
/// - `OK` reaching the error path is evidence against nobody: caller, recorded against nobody.
///
/// A code gRPC has not defined states no reading, which the breaker reads as the caller's.
pub(crate) const FAULT_ROWS: &[FaultRow] = &[
    fault_row(0, FAULT_CALLER),     // OK
    fault_row(1, FAULT_CALLER),     // CANCELLED
    fault_row(2, FAULT_TRANSIENT),  // UNKNOWN
    fault_row(3, FAULT_CALLER),     // INVALID_ARGUMENT
    fault_row(4, FAULT_TRANSIENT),  // DEADLINE_EXCEEDED
    fault_row(5, FAULT_CALLER),     // NOT_FOUND
    fault_row(6, FAULT_CALLER),     // ALREADY_EXISTS
    fault_row(7, FAULT_HARD),       // PERMISSION_DENIED
    fault_row(8, FAULT_TRANSIENT),  // RESOURCE_EXHAUSTED
    fault_row(9, FAULT_CALLER),     // FAILED_PRECONDITION
    fault_row(10, FAULT_TRANSIENT), // ABORTED
    fault_row(11, FAULT_CALLER),    // OUT_OF_RANGE
    fault_row(12, FAULT_CALLER),    // UNIMPLEMENTED
    fault_row(13, FAULT_TRANSIENT), // INTERNAL
    fault_row(14, FAULT_TRANSIENT), // UNAVAILABLE
    fault_row(15, FAULT_TRANSIENT), // DATA_LOSS
    fault_row(16, FAULT_HARD),      // UNAUTHENTICATED
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
/// answering a call with an HTTP status and no `grpc-status`), by that HTTP status: 401/403 hard
/// (`Auth` -> `HardDown`); 408, 429, 529 and 5xx transient; every other status the caller's. The call's own status is the gRPC status the
/// HTTP one stands for (`msg::status_of_http`); its fault is read here, by the wire it came on, so a
/// bare 400 that the mapping calls INTERNAL records nothing. Data, walked
/// once: the first row that holds the status reads it.
const HTTP_FAULTS: &[(u16, u16, u8)] = &[
    (401, 401, FAULT_HARD),
    (403, 403, FAULT_HARD),
    (408, 408, FAULT_TRANSIENT),
    (429, 429, FAULT_TRANSIENT),
    (500, 599, FAULT_TRANSIENT),
];

/// The breaker's reading of a bare HTTP answer's `status` ([`HTTP_FAULTS`]; off the table, the
/// caller's).
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

// The declared default is the timeout the door applies when the setting is absent: one fact, held
// equal (as the SDK holds `DEFAULT_BODY_MAX` to its bound).
const _: () = assert!(decimal(DEFAULT_TIMEOUT) == DEFAULT_REQUEST_TIMEOUT_SECS);

pub(crate) const SETTINGS: &[SettingDecl] = &[
    SettingDecl {
        path: abi_str(setting::REQUEST_TIMEOUT_SECS),
        kind: SETTING_COUNT,
        _reserved: 0,
        default: abi_str(DEFAULT_TIMEOUT),
    },
    SettingDecl {
        path: abi_str(setting::BODY_MAX_BYTES),
        kind: SETTING_COUNT,
        _reserved: 0,
        default: abi_str(DEFAULT_BODY_MAX),
    },
];

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
    t
};
