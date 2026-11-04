use super::{prefix, PREFIX};

/// `payload` in its length-prefixed form.
pub fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PREFIX + payload.len());
    out.extend_from_slice(&prefix(payload.len()).expect("a test payload is short"));
    out.extend_from_slice(payload);
    out
}
