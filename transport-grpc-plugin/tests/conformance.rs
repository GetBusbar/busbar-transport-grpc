// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE `grpc` DOOR, BOTH WAYS IN**: the linked door (`busbar_transport_grpc::door`) and
//! this crate's built cdylib (the same door behind the one `export_door!`), each admitted through the
//! loader's ONE door validation and driven through the ONE dispatcher's crossing, give the same
//! Statement and the same answers.

use std::mem::zeroed;
use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome};
use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::transport::{
    slot, BeginIn, FramerOut, FramerSink, LocateIn, LocateOut, SIDE_DIAL,
};
use busbar_plugin_loader::dispatch::kinds::hook::Hook;
use busbar_plugin_loader::dispatch::kinds::transport::Transport;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, load_linked, out_head, Bind, ConnTable, DispatchConfig, Dispatcher,
    Frame, LinkedRow, LoadError, LoadedDoor, NoSink, Plugin,
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
    let settings = "{}";
    let mut i: OpenIn = z();
    i.head = in_head();
    i.settings = Blob::json(settings.as_bytes());
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
    let mut defaults = vec![0_u8; 256];
    let mut i: LocateIn = z();
    i.head = in_head();
    i.target = AbiStr::of(target);
    (i.authority_buf, i.authority_cap) = (a.as_mut_ptr(), a.len());
    (i.name_buf, i.name_cap) = (n.as_mut_ptr(), n.len());
    (i.alpn_buf, i.alpn_cap) = (alpn.as_mut_ptr(), alpn.len());
    (i.defaults_buf, i.defaults_cap) = (defaults.as_mut_ptr(), defaults.len());
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
    i.scheme = busbar_contract::abi::host::service::SCHEME_PLAIN;
    i.target = AbiStr::of(target);
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

/// Two doors' scripts must be the same lines: `Err` names the first that differs.
fn same_script(a: &Script, b: &Script) -> Result<(), String> {
    match a.iter().zip(b).position(|(x, y)| x != y) {
        None if a.len() == b.len() => Ok(()),
        None => Err(format!("{} lines vs {}", a.len(), b.len())),
        Some(i) => Err(format!("line {i}: {:?} vs {:?}", a[i], b[i])),
    }
}

#[test]
fn the_linked_and_the_dropped_in_door_are_one_framer() {
    let d = Dispatcher::new(DispatchConfig::default());
    let linked: Plugin<Transport> = load_linked(&row(), bind(&d)).expect("the linked door loads");
    let dropped: Plugin<Transport> =
        load_dropped(&cdylib(), &row().statement, bind(&d)).expect("the dropped-in door loads");
    assert_eq!(linked.name(), "grpc");
    assert_eq!(dropped.name(), linked.name());
    open(&linked);
    open(&dropped);

    let a = script(&linked);
    let b = script(&dropped);
    assert_eq!(same_script(&a, &b), Ok(()), "both doors answer alike");
    assert_eq!(
        a.last().map(String::as_str),
        Some("begin Ready"),
        "both doors begin the dial"
    );

    let mut off = b.clone();
    off[1].push('!');
    assert!(
        same_script(&a, &off).is_err_and(|e| e.starts_with("line 1:")),
        "a differing line is caught"
    );
    let short: Script = b[..b.len() - 1].to_vec();
    assert!(same_script(&a, &short).is_err(), "a missing line is caught");
}

#[test]
fn the_door_asked_for_as_another_kind_is_refused_both_ways() {
    let d = Dispatcher::new(DispatchConfig::default());
    let want = (KindCode::Transport, KindCode::Hook);
    match load_linked::<Hook>(&row(), bind(&d)) {
        Err(LoadError::ManifestKind {
            stated,
            want: asked,
        }) => assert_eq!((stated, asked), want),
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
