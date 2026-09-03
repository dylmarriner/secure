use secure_crypto::{Argon2Profile, SubkeyPurpose, VaultKey, VaultKeyEnvelope};

const TEST_PROFILE: Argon2Profile = Argon2Profile {
    memory_kib: 8 * 1024,
    iterations: 1,
    parallelism: 1,
};

#[test]
fn vault_key_round_trips_through_authenticated_passphrase_envelope() {
    let key = VaultKey::generate().expect("OS randomness");
    let envelope = VaultKeyEnvelope::seal(b"correct horse battery staple", &key, TEST_PROFILE)
        .expect("seal key");

    let reopened = envelope
        .open(b"correct horse battery staple")
        .expect("open key");

    assert_eq!(key.as_bytes(), reopened.as_bytes());
}

#[test]
fn wrong_passphrase_cannot_open_vault_key_envelope() {
    let key = VaultKey::generate().expect("OS randomness");
    let envelope =
        VaultKeyEnvelope::seal(b"right passphrase", &key, TEST_PROFILE).expect("seal key");

    assert!(envelope.open(b"wrong passphrase").is_err());
}

#[test]
fn envelope_serialization_is_versioned_and_round_trips() {
    let key = VaultKey::generate().expect("OS randomness");
    let envelope = VaultKeyEnvelope::seal(b"passphrase", &key, TEST_PROFILE).expect("seal key");

    let bytes = envelope.to_bytes();
    assert_eq!(&bytes[..4], b"SVK1");

    let decoded = VaultKeyEnvelope::from_bytes(&bytes).expect("decode envelope");
    let reopened = decoded.open(b"passphrase").expect("open key");
    assert_eq!(key.as_bytes(), reopened.as_bytes());
}

#[test]
fn database_and_config_subkeys_are_domain_separated() {
    let key = VaultKey::generate().expect("OS randomness");

    let database = key
        .derive_subkey(SubkeyPurpose::DatabaseV1)
        .expect("derive database key");
    let config = key
        .derive_subkey(SubkeyPurpose::LocalConfigV1)
        .expect("derive config key");

    assert_ne!(&*database, &*config);
}

#[test]
fn repeated_generate_and_drop_does_not_panic() {
    // VaultKey locks its heap-allocated buffer in physical memory on construction
    // (best-effort mlock/VirtualLock) and unlocks it on drop. This does not - and cannot,
    // from safe Rust - prove the buffer's contents are actually zero after drop; that would
    // require reading freed memory. What it does pin: creating and dropping many keys in a
    // row must never panic, even if the platform lock call itself fails (missing privilege,
    // RLIMIT_MEMLOCK exceeded, etc.) - failures there are deliberately best-effort and must
    // never be treated as fatal.
    for _ in 0..64 {
        let key = VaultKey::generate().expect("OS randomness");
        let _ = key.derive_subkey(SubkeyPurpose::DatabaseV1);
        drop(key);
    }
}
