//! Property tests over the persistent `SATT` attachment format (`docs/security-remediation-plan.md`
//! R9): arbitrary input never panics, and any single-byte change or truncation of a valid object
//! is rejected rather than decrypted to a different or partial plaintext.

use proptest::prelude::*;
use secure_attachments::{AttachmentKey, decrypt_stream, encrypt_stream};

fn seal(key: &AttachmentKey, plaintext: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    encrypt_stream(
        key,
        "application/octet-stream",
        plaintext.len() as u64,
        plaintext,
        &mut out,
    )
    .expect("encrypt");
    out
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn decryption_of_arbitrary_bytes_never_panics_or_succeeds(
        bytes in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let key = AttachmentKey::generate().expect("key");
        let mut sink = Vec::new();
        prop_assert!(decrypt_stream(&key, bytes.as_slice(), &mut sink).is_err());
    }

    #[test]
    fn any_single_byte_change_is_rejected(
        plaintext in proptest::collection::vec(any::<u8>(), 0..2048),
        index in any::<prop::sample::Index>(),
        flip in 1_u8..=255,
    ) {
        let key = AttachmentKey::generate().expect("key");
        let mut sealed = seal(&key, &plaintext);
        let at = index.index(sealed.len());
        sealed[at] ^= flip;
        let mut sink = Vec::new();
        prop_assert!(decrypt_stream(&key, sealed.as_slice(), &mut sink).is_err());
    }

    #[test]
    fn any_truncation_is_rejected(
        plaintext in proptest::collection::vec(any::<u8>(), 0..2048),
        cut in any::<prop::sample::Index>(),
    ) {
        let key = AttachmentKey::generate().expect("key");
        let sealed = seal(&key, &plaintext);
        let keep = cut.index(sealed.len()); // strictly shorter than the full object
        let mut sink = Vec::new();
        prop_assert!(decrypt_stream(&key, &sealed[..keep], &mut sink).is_err());
    }

    #[test]
    fn round_trip_preserves_content(plaintext in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let key = AttachmentKey::generate().expect("key");
        let sealed = seal(&key, &plaintext);
        let mut out = Vec::new();
        decrypt_stream(&key, sealed.as_slice(), &mut out).expect("decrypt");
        prop_assert_eq!(out, plaintext);
    }
}
