// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE `grpc` DOOR, BOTH WAYS IN**: the linked door (`busbar_transport_grpc::linked::door`) and
//! this crate's built cdylib (the same door behind the one `export_door!`), each admitted through the
//! loader's ONE door validation and driven through the ONE dispatcher's crossing, give the same
//! Statement and the same answers. Run against the busbar rev this repo pins (`.busbar-ref`). The
//! logic crate's own `tests/conformance.rs` and `tests/peers.rs` carry the full framing scenarios
//! against real tonic peers.
//!
//! THE RED ARMS, same file: a differing answer is caught by the comparison, and the door asked for
//! as another kind is refused, linked (by the door's own kind) and dropped in (by the stated kind,
//! before `dlopen`). A missing cdylib PANICS: this test IS the dropped-in door's proof.

use std::mem::zeroed;
use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome, BLOB_JSON};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::transport::{
    slot, BeginIn, FramerOut, FramerSink, LocateIn, LocateOut, SIDE_DIAL,
};
use busbar_plugin_loader::dispatch::kinds::hook::Hook;
use busbar_plugin_loader::dispatch::kinds::transport::Transport;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, load_linked, out_head, Bind, ConnTable, DispatchConfig, Dispatcher,
    Frame, LinkedRow, LoadError, NoSink, Plugin,
};
use busbar_transport_grpc_plugin::linked;

fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { zeroed() }
}

/// This crate's built cdylib (uplifted or under `deps`, newest wins). A missing artifact is a
/// failure, never a skip: this test IS the dropped-in door's proof.
fn cdylib() -> std::path::PathBuf {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let file = busbar_plugin_loader::plugin_library_filename("busbar_transport_grpc_plugin");
    [profile.join(&file), profile.join("deps").join(&file)]
        .into_iter()
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p)
        .unwrap_or_else(|| panic!("the busbar-transport-grpc-plugin cdylib ({file}) is not built"))
}

/// The row a compiled-in build holds for this door.
fn row() -> LinkedRow {
    LinkedRow::of(linked::door).expect("the door states itself")
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
    let settings = "{}";
    let mut i: OpenIn = z();
    i.head = in_head();
    i.settings = Blob {
        ptr: settings.as_ptr(),
        len: settings.len(),
        fmt: BLOB_JSON,
        flags: 0,
    };
    let mut o: OpenOut = z();
    o.head = out_head();
    let mut f = Frame::new(i, o);
    assert_eq!(p.call(life::OPEN, &mut f).outcome, Outcome::Ready);
}

/// What one door answered: what it located, then what a dial's begin answered.
type Script = Vec<String>;

/// One scripted exchange through the dispatcher: locate a target, begin a dial.
fn script(p: &Plugin<Transport>) -> Script {
    let target = "http://peer.test:50051";
    let (mut a, mut n, mut alpn) = (vec![0_u8; 256], vec![0_u8; 256], vec![0_u8; 64]);
    let mut i: LocateIn = z();
    i.head = in_head();
    i.target = AbiStr {
        ptr: target.as_ptr(),
        len: target.len(),
    };
    (i.authority_buf, i.authority_cap) = (a.as_mut_ptr(), a.len());
    (i.name_buf, i.name_cap) = (n.as_mut_ptr(), n.len());
    (i.alpn_buf, i.alpn_cap) = (alpn.as_mut_ptr(), alpn.len());
    let mut o: LocateOut = z();
    o.head = out_head();
    let mut f = Frame::new(i, o);
    let outcome = p.call(slot::LOCATE, &mut f).outcome;
    let o = f.out;
    let mut seen = vec![
        format!("locate {outcome:?}"),
        format!(
            "authority {:?}",
            String::from_utf8_lossy(&a[..o.authority_written as usize])
        ),
        format!(
            "name {:?} has_name {}",
            String::from_utf8_lossy(&n[..o.name_written as usize]),
            o.has_name
        ),
        format!("secure {}", o.secure),
        format!("alpn {:?}", &alpn[..o.alpn_written as usize]),
    ];
    assert_eq!(outcome, Outcome::Ready, "the door locates a gRPC target");

    let (mut wire, mut frame) = (vec![0_u8; 4096], vec![0_u8; 4096]);
    let mut pieces = vec![z(); 8];
    let mut i: BeginIn = z();
    i.head = in_head();
    i.side = SIDE_DIAL;
    i.target = AbiStr {
        ptr: target.as_ptr(),
        len: target.len(),
    };
    i.sink = FramerSink {
        wire: wire.as_mut_ptr(),
        wire_cap: wire.len(),
        frame: frame.as_mut_ptr(),
        frame_cap: frame.len(),
        pieces: pieces.as_mut_ptr(),
        pieces_cap: pieces.len(),
        now_monotonic_ns: 1,
        now_unix_ns: 1,
        heads: std::ptr::null_mut(),
        heads_cap: 0,
    };
    let mut o: FramerOut = z();
    o.head = out_head();
    let mut f = Frame::new(i, o);
    seen.push(format!("begin {:?}", p.call(slot::BEGIN, &mut f).outcome));
    seen
}

#[test]
fn the_linked_and_the_dropped_in_door_are_one_framer() {
    let d = Dispatcher::new(DispatchConfig::default());
    let linked: Plugin<Transport> = load_linked(&row(), bind(&d)).expect("the linked door loads");
    let dropped: Plugin<Transport> =
        load_dropped(&cdylib(), &row().statement, bind(&d)).expect("the dropped-in door loads");
    assert_eq!(linked.name(), linked::KEY);
    assert_eq!(dropped.name(), linked.name());
    open(&linked);
    open(&dropped);

    let a = script(&linked);
    let b = script(&dropped);
    assert_eq!(a, b, "both doors answer alike");

    // RED: a dropped-in image that answered one line differently is caught.
    let mut off = b.clone();
    off[1].push('!');
    assert_ne!(a, off, "a differing line is caught");
}

#[test]
fn the_door_asked_for_as_another_kind_is_refused_both_ways() {
    let d = Dispatcher::new(DispatchConfig::default());
    let want = (KindCode::Transport, KindCode::Hook);
    match load_linked::<Hook>(&row(), bind(&d)) {
        Err(LoadError::WrongKind { door, want: asked }) => assert_eq!((door, asked), want),
        other => panic!("the linked door loaded as a hook: {:?}", other.err()),
    }
    match load_dropped::<Hook>(&cdylib(), &row().statement, bind(&d)) {
        Err(LoadError::ManifestKind {
            stated,
            want: asked,
        }) => assert_eq!((stated, asked), want),
        other => panic!("the dropped-in door loaded as a hook: {:?}", other.err()),
    }
}

// THE PUBLISHED SUITE (busbar-plugin-loader's `conformance_suite!`): both legs through the one
// loader, every step at its pinned crossing count, over `conformance.json`.
busbar_plugin_loader::conformance_suite! {
    door: busbar_transport_grpc::door::door,
    cdylib: "busbar_transport_grpc_plugin",
    inputs: include_str!("conformance.json"),
}
