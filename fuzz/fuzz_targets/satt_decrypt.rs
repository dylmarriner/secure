#![no_main]
//! `SATT` attachment decryption: must never panic or succeed on input not sealed under the key.
use libfuzzer_sys::fuzz_target;
use secure_attachments::{AttachmentKey, decrypt_stream};

fuzz_target!(|data: &[u8]| {
    let key = AttachmentKey::from_bytes([7; 32]);
    let mut sink = Vec::new();
    assert!(decrypt_stream(&key, data, &mut sink).is_err());
});
