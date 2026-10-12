#![no_main]
//! `SVK1` vault-key envelope parser: must never panic, whatever the file contains.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = secure_crypto::VaultKeyEnvelope::from_bytes(data);
});
