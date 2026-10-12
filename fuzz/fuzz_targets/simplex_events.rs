#![no_main]
//! SimpleX chat-event parsing of arbitrary JSON from the core: must never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) {
        let _ = secure_messaging::parse_chat_event(value);
    }
});
