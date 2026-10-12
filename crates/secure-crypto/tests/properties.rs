//! Property tests over the persistent `SVK1` envelope and messaging-record formats
//! (`docs/security-remediation-plan.md` R9): parsers never panic on arbitrary input, and no
//! single-byte change to a valid object is ever accepted.

use proptest::prelude::*;
use secure_crypto::{
    Argon2Profile, VaultKey, VaultKeyEnvelope, open_messaging_record, seal_messaging_record,
};

/// The cheapest profile `validate` accepts, so each case costs milliseconds, not a second.
const FAST: Argon2Profile = Argon2Profile {
    memory_kib: 8 * 1024,
    iterations: 1,
    parallelism: 1,
};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn envelope_parser_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        let _ = VaultKeyEnvelope::from_bytes(&bytes);
    }

    #[test]
    fn record_open_never_panics_or_accepts_garbage(
        bytes in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let key = VaultKey::generate().expect("key");
        prop_assert!(open_messaging_record(&key, "c", "incoming", &bytes).is_err());
    }

    #[test]
    fn any_single_byte_change_to_a_record_is_rejected(
        plaintext in proptest::collection::vec(any::<u8>(), 0..128),
        index in any::<prop::sample::Index>(),
        flip in 1_u8..=255,
    ) {
        let key = VaultKey::generate().expect("key");
        let mut sealed = seal_messaging_record(&key, "c", "incoming", &plaintext).expect("seal");
        let at = index.index(sealed.len());
        sealed[at] ^= flip;
        prop_assert!(open_messaging_record(&key, "c", "incoming", &sealed).is_err());
    }

    #[test]
    fn records_are_bound_to_their_conversation_and_direction(
        plaintext in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let key = VaultKey::generate().expect("key");
        let sealed = seal_messaging_record(&key, "conv-a", "incoming", &plaintext).expect("seal");
        prop_assert!(open_messaging_record(&key, "conv-b", "incoming", &sealed).is_err());
        prop_assert!(open_messaging_record(&key, "conv-a", "outgoing", &sealed).is_err());
        prop_assert_eq!(
            open_messaging_record(&key, "conv-a", "incoming", &sealed).expect("open"),
            plaintext
        );
    }
}

proptest! {
    // Each case runs Argon2id twice (seal + open), so fewer cases.
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn any_single_byte_change_to_an_envelope_is_rejected(
        index in any::<prop::sample::Index>(),
        flip in 1_u8..=255,
    ) {
        let key = VaultKey::generate().expect("key");
        let envelope = VaultKeyEnvelope::seal(b"correct horse battery staple", &key, FAST)
            .expect("seal");
        let mut bytes = envelope.to_bytes();
        let at = index.index(bytes.len());
        bytes[at] ^= flip;
        // Either the structure is rejected outright, or it parses and then fails to open.
        // Opening is only attempted when the tampered profile is no costlier than FAST's
        // neighbourhood, so a flipped memory field cannot make one case take a gigabyte.
        if let Ok(tampered) = VaultKeyEnvelope::from_bytes(&bytes) {
            let memory_kib = u32::from_be_bytes(bytes[5..9].try_into().expect("4 bytes"));
            if memory_kib <= 64 * 1024 {
                prop_assert!(tampered.open(b"correct horse battery staple").is_err());
            }
        }
    }
}
