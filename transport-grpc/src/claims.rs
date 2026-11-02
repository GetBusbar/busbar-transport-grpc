// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The claims this transport declares: the scheme it answers for and the selector forms and facts a claim over it reads. A declaration

use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::abi::sdk::door::abi_str;
use busbar_contract::abi::sdk::transport::form_codes;
use busbar_contract::abi::transport::{Claim, STATUS_AT_TERMINAL, UNIT0_FIRST_MESSAGE};
use busbar_contract::transport::registry::{facts as tfacts, status_ns};
use busbar_contract::SelectorForm;

/// The shapes an ingress claim over this wire may take: a call is a path (`/<service>/<method>`)

pub(crate) const SELECTOR_FORMS: &[SelectorForm] = &[
    SelectorForm::ExactPath,
    SelectorForm::PrefixOneLevel,
    SelectorForm::PathPattern,
    SelectorForm::PathSuffix,
    SelectorForm::PathContains,
    SelectorForm::HeaderPresent,
    SelectorForm::HeaderPrefix,
];

pub(crate) const SELECTOR_CODES: [u8; SELECTOR_FORMS.len()] = form_codes(SELECTOR_FORMS);

pub(crate) const FACTS: &[AbiStr] = &[
    abi_str(tfacts::PATH),
    abi_str(tfacts::METHOD),
    abi_str(tfacts::AUTHORITY),
    abi_str(tfacts::PEER),
];

/// The scheme `grpc` claims, by name: the Statement's `claims`, the one place it is stated.
pub(crate) const CLAIM_NAMES: &[AbiStr] = &[abi_str(crate::meta::KEY)];

/// The claimed scheme's row, by index into [`CLAIM_NAMES`].
pub(crate) const CLAIMS: &[Claim] = &[{
    let mut c = Claim::EMPTY.with_facts(FACTS);
    c.selector_forms = AbiStr::of_bytes(&SELECTOR_CODES);
    c.egress_selector_forms = abi_str("");
    c.status_namespace = abi_str(status_ns::GRPC);

    c.session = crate::meta::SESSION as u8;
    c.session_bound = 1;
    c.unit0_trigger = UNIT0_FIRST_MESSAGE;
    c.status_at = STATUS_AT_TERMINAL;
    c
}];
