// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What this transport declares about itself, as the kind's own file (`BUSBAR-1.6.0.md` THE
//! DESIGN, §2): its key, the settings it reads, its status classes and the transport kind's tail its
//! door states. Read once at registration and sealed, so it is data, held apart from the framing
//! code it describes.

use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::abi::mechanism::door::KindTailHead;
use busbar_contract::abi::sdk::door::abi_str;
use busbar_contract::abi::transport::{
    FaultRow, SettingDecl, StatusRow, TransportTail, FAULT_CALLER, FAULT_HARD, FAULT_NONE,
    FAULT_TRANSIENT, FRAMING_STREAM, ROLE_FRAMER, SETTING_COUNT, STATUS_CALLER_FAULT,
    STATUS_FAR_END_FAULT, STATUS_OTHER, STATUS_SUCCESS,
};

/// This transport's key: the scheme it claims.
pub const KEY: &str = "grpc";

/// The settings this transport reads, at their 1.5.5 paths.
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
/// money and the destination's health do). One row per code gRPC defines, 1.5.5's breaker table
/// exactly, moved to the wire that owns the numbering (busbar ARCHITECT breaker ruling Q1):
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

pub(crate) const SETTINGS: &[SettingDecl] = &[
    SettingDecl {
        path: abi_str(setting::REQUEST_TIMEOUT_SECS),
        kind: SETTING_COUNT,
        _reserved: 0,
        default: abi_str("300"),
    },
    SettingDecl {
        path: abi_str(setting::BODY_MAX_BYTES),
        kind: SETTING_COUNT,
        _reserved: 0,
        default: abi_str("33554432"),
    },
];

pub(crate) const NONE: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

pub(crate) const TAIL: TransportTail = TransportTail {
    head: KindTailHead {
        size: std::mem::size_of::<TransportTail>() as u32,
        _reserved: 0,
    },
    role: ROLE_FRAMER,
    framing: FRAMING_STREAM,
    facts: 0,
    handshake_max_steps: 0,
    composes_over: COMPOSES_OVER.as_ptr(),
    composes_over_len: COMPOSES_OVER.len(),
    claim_rows: crate::claims::CLAIMS.as_ptr(),
    claim_rows_len: crate::claims::CLAIMS.len(),
    upgrades_to: std::ptr::null(),
    upgrades_to_len: 0,
    handoff_from: NONE,
    handoff_to: NONE,
    handoff_binding_fact: NONE,
    handshake_frame_kind: NONE,
    status_rows: STATUS_ROWS.as_ptr(),
    status_rows_len: STATUS_ROWS.len(),
    settings: SETTINGS.as_ptr(),
    settings_len: SETTINGS.len(),
    fault_rows: FAULT_ROWS.as_ptr(),
    fault_rows_len: FAULT_ROWS.len(),
};
