// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The claims this transport declares, as the kind's own file (`BUSBAR-1.6.0.md` THE DESIGN, §2):
//! the scheme it answers for and the selector forms and facts a claim over it reads. A declaration
//! and nothing else, read once at registration.

use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::abi::sdk::door::abi_str;
use busbar_contract::abi::sdk::transport::form_codes;
use busbar_contract::abi::transport::{Claim, STATUS_AT_TERMINAL, UNIT0_FIRST_MESSAGE};
use busbar_contract::transport::registry::{facts as tfacts, status_ns};
use busbar_contract::SelectorForm;

/// The shapes an ingress claim over this wire may take: a call is a path (`/<service>/<method>`)
/// and its metadata, on a connection its listener's port, name and protocol pick. gRPC is the top
/// framer of its connection, so it owns claim selection over the request that opens each call.
pub(crate) const SELECTOR_FORMS: &[SelectorForm] = &[
    SelectorForm::ExactPath,
    SelectorForm::PrefixOneLevel,
    SelectorForm::PathPattern,
    SelectorForm::HeaderExact,
    SelectorForm::HeaderPresent,
    SelectorForm::HeaderPrefix,
    SelectorForm::Sni,
    SelectorForm::Alpn,
    SelectorForm::Port,
];

pub(crate) const SELECTOR_CODES: [u8; SELECTOR_FORMS.len()] = form_codes(SELECTOR_FORMS);

pub(crate) const FACTS: &[AbiStr] = &[
    abi_str(tfacts::PATH),
    abi_str(tfacts::METHOD),
    abi_str(tfacts::AUTHORITY),
    abi_str(tfacts::PEER),
];

pub(crate) const fn bytes_str(b: &'static [u8]) -> AbiStr {
    AbiStr {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}

/// The scheme `grpc` claims, by name: the Statement's `claims`, the one place it is stated.
pub(crate) const CLAIM_NAMES: &[AbiStr] = &[abi_str(crate::meta::KEY)];

/// The claimed scheme's row, by index into [`CLAIM_NAMES`].
pub(crate) const CLAIMS: &[Claim] = &[Claim {
    selector_forms: bytes_str(&SELECTOR_CODES),
    egress_selector_forms: abi_str(""),
    facts: FACTS.as_ptr(),
    facts_len: FACTS.len(),
    status_namespace: abi_str(status_ns::GRPC),
    // A connection multiplexes calls, each its own stream; the session opens at a call's first
    // message.
    session: 1,
    session_bound: 1,
    unit0_trigger: UNIT0_FIRST_MESSAGE,
    status_at: STATUS_AT_TERMINAL,
    _reserved: 0,
}];
