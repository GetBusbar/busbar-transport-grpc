// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The door's statement passes the kind's own checks, its status rows class every canonical
//! `grpc-status`, and its settings read as their declarations say.

use busbar_contract::abi::transport::check::{
    check_claim_rows, check_claims, check_composes_over, check_fault_cover, check_fault_rows,
    check_settings, check_status_rows, check_tail,
};
use busbar_contract::abi::transport::{
    FAULT_CALLER, FAULT_HARD, FAULT_NONE, FAULT_TRANSIENT, ROLE_FRAMER, STATUS_CALLER_FAULT,
    STATUS_FAR_END_FAULT, STATUS_OTHER, STATUS_SUCCESS,
};

use super::{class_of, fault_of, read_settings, CLAIM_NAMES, STATEMENT, TAIL};
use crate::claims::CLAIMS;
use crate::meta::{COMPOSES_OVER, FAULT_ROWS, SETTINGS, STATUS_ROWS};

#[test]
fn the_tail_is_a_framer_that_names_no_other_transport() {
    assert_eq!(check_tail(&TAIL), Ok(()));
    // One row per scheme the Statement names: the names are the Statement's alone.
    assert_eq!(check_claim_rows(STATEMENT.claims_len, &TAIL), Ok(()));
    assert_eq!(CLAIM_NAMES.len(), CLAIMS.len());
    assert_eq!(check_claims(CLAIMS), Ok(()));
    assert_eq!(check_composes_over(COMPOSES_OVER), Ok(()));
    assert_eq!(check_status_rows(STATUS_ROWS, CLAIMS.len() as u64), Ok(()));
    assert_eq!(check_fault_rows(FAULT_ROWS, CLAIMS.len() as u64), Ok(()));
    assert_eq!(check_fault_cover(STATUS_ROWS, FAULT_ROWS), Ok(()));
    assert_eq!(check_settings(SETTINGS), Ok(()));
    assert_eq!(TAIL.role, ROLE_FRAMER);
    // No transport names another (THE DESIGN, the transport chain). The connector picks the
    // carrier; the tail names none, so the connector serves it over the host's socket.
    assert!(COMPOSES_OVER.is_empty());
    assert_eq!(TAIL.composes_over_len, 0);
}

#[test]
fn every_canonical_status_has_the_class_its_http_mapping_gives_it() {
    assert_eq!(class_of(0), STATUS_SUCCESS);
    for code in [1, 3, 5, 6, 7, 8, 9, 10, 11, 16] {
        assert_eq!(class_of(code), STATUS_CALLER_FAULT, "code {code}");
    }
    for code in [2, 4, 12, 13, 14, 15] {
        assert_eq!(class_of(code), STATUS_FAR_END_FAULT, "code {code}");
    }
    assert_eq!(class_of(17), STATUS_OTHER);
}

/// Every code gRPC defines, stated as the breaker's reading. Written out rather than derived from
/// the table, so a row that drifted fails here: which codes penalise the destination, which take it
/// down across every pool, and which are the caller's own and cost the destination nothing.
#[test]
fn every_canonical_status_has_the_breakers_fault_reading() {
    let expect: [(u16, u8); 17] = [
        (0, FAULT_CALLER),
        (1, FAULT_CALLER),
        (2, FAULT_TRANSIENT),
        (3, FAULT_CALLER),
        (4, FAULT_TRANSIENT),
        (5, FAULT_CALLER),
        (6, FAULT_CALLER),
        (7, FAULT_HARD),
        (8, FAULT_TRANSIENT),
        (9, FAULT_CALLER),
        (10, FAULT_TRANSIENT),
        (11, FAULT_CALLER),
        (12, FAULT_CALLER),
        (13, FAULT_TRANSIENT),
        (14, FAULT_TRANSIENT),
        (15, FAULT_TRANSIENT),
        (16, FAULT_HARD),
    ];
    for (code, fault) in expect {
        assert_eq!(fault_of(code), fault, "code {code}");
    }
    assert_eq!(FAULT_ROWS.len(), expect.len(), "one row per code, no more");
    // A code gRPC has not defined is evidence about nobody: no reading.
    assert_eq!(fault_of(17), FAULT_NONE);
    assert_eq!(fault_of(200), FAULT_NONE);
}

#[test]
fn settings_read_as_declared_and_refuse_what_is_not() {
    let p = read_settings(b"").expect("absent reads as {}");
    assert_eq!(p.timeout.as_secs(), 300);
    assert_eq!(p.max_message_bytes, 33_554_432);
    let p = read_settings(
        br#"{"limits.upstream_request_timeout_secs":5,"limits.request_body_max_bytes":1024}"#,
    )
    .expect("settings");
    assert_eq!((p.timeout.as_secs(), p.max_message_bytes), (5, 1024));
    assert!(read_settings(b"not json").is_err());
    assert!(read_settings(br#"{"limits.upstream_request_timeout_secs":"5"}"#).is_err());
}
