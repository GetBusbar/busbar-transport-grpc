// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE `grpc` DOOR, BOTH WAYS IN**: the linked door (`busbar_transport_grpc::door`) and
//! this crate's built cdylib (the same door behind the one `export_door!`), each admitted through the
//! loader's ONE door validation and driven through the ONE dispatcher's crossing, give the same
//! Statement and the same answers.

use std::mem::zeroed;
use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{Blob, Outcome};
use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_plugin_loader::dispatch::kinds::transport::Transport;
use busbar_plugin_loader::dispatch::{
    in_head, out_head, Bind, ConnTable, Dispatcher, Frame, LinkedRow, LoadedDoor, NoSink, Plugin,
};

fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { zeroed() }
}

/// This product's freshly built cdylib. A missing artifact is a hard failure.
fn cdylib() -> std::path::PathBuf {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let file = busbar_plugin_loader::plugin_library_filename("busbar_transport_grpc_plugin");
    let path = match std::env::var_os("BUSBAR_PLUGIN_CDYLIB") {
        Some(path) => {
            let path = std::path::PathBuf::from(path);
            assert!(path.is_absolute(), "BUSBAR_PLUGIN_CDYLIB must be absolute");
            path
        }
        None => profile.join(file),
    };
    assert!(
        path.is_file(),
        "build this product's actual cdylib before testing: {}",
        path.display()
    );
    path
}

/// This crate's own door, as the loader names a compiled-in one.
fn loaded() -> LoadedDoor {
    let door: DoorFn = busbar_transport_grpc::door;
    LoadedDoor::from(door)
}

/// The row a compiled-in build holds for this door.
fn row() -> LinkedRow {
    LinkedRow::of_loaded(loaded()).expect("the door states itself")
}

fn bind(d: &Dispatcher) -> Bind {
    Bind {
        instance: Arc::from("the-instance"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: ConnTable::NoNeeds,
    }
}

fn open(p: &Plugin<Transport>) {
    let mut i: OpenIn = z();
    i.head = in_head();
    i.settings = Blob::json(b"{}");
    let mut o: OpenOut = z();
    o.head = out_head();
    let mut f = Frame::new(i, o);
    assert_eq!(p.call(life::OPEN, &mut f).outcome, Outcome::Ready);
}

#[path = "support/framer.rs"]
mod framer;

#[test]
fn the_statement_carries_the_declares_document() {
    let row = row();
    let read = busbar_contract::abi::mechanism::rendering::read(&row.statement).unwrap();
    assert_eq!(
        busbar_contract::abi::mechanism::extensions::declares(&read.extensions.bytes),
        Some(&include_bytes!("../../transport-grpc/declares.json")[..]),
    );
}

/// The gRPC door offers no authentication point and makes no authentication call.
#[test]
fn the_statement_offers_no_auth_point() {
    let row = row();
    let read = busbar_contract::abi::mechanism::rendering::read(&row.statement).unwrap();
    let points =
        busbar_contract::abi::transport::check::check_offered_points(&read.extensions.bytes)
            .map(|p| p.0);
    assert_eq!(points, Ok(0));
}

#[path = "support/negative.rs"]
mod negative;
