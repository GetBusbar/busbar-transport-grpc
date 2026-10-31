// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `linked` entry the composition root folds, tied to the Statement the door states.

use busbar_contract::abi::transport::TransportTail;
use busbar_transport_grpc::{door, linked};

#[test]
fn the_linked_entry_states_the_framers_key_layers_and_session() {
    assert_eq!(linked::KEY, "grpc");
    assert!(linked::COMPOSES_OVER.is_empty());
    // SAFETY: `door()` answers the `'static` door of this crate.
    #[allow(unused_unsafe)]
    let d = unsafe { (linked::door)() };
    assert!(!d.ops().is_null());
    assert!(std::ptr::eq(d, door()), "one door");
}

#[test]
fn the_linked_entry_equals_the_statement() {
    // SAFETY: the door's Statement is this crate's `'static` one, and its kind tail a `'static`
    // `TransportTail` whose claim rows are `'static`.
    let (statement, tail) = unsafe {
        let st = &*(*door()).statement();
        (st, &*st.kind_tail().cast::<TransportTail>())
    };
    assert_eq!(tail.composes_over_len(), linked::COMPOSES_OVER.len());
    // SAFETY: the tail's claim rows, `claim_rows_len` of them.
    let rows = unsafe { std::slice::from_raw_parts(tail.claim_rows, tail.claim_rows_len) };
    assert_eq!(statement.claims_len, 1);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].session != 0, linked::SESSION);
    // SAFETY: the Statement's claim names, `claims_len` of them, `'static`.
    let name = unsafe { (*statement.claims).bytes() };
    assert_eq!(name, linked::KEY.as_bytes());
}
