use secure_crypto::{
    Argon2Profile, SubkeyPurpose, VaultKey, VaultKeyEnvelope, open_messaging_record,
    seal_messaging_record,
};

const TEST_PROFILE: Argon2Profile = Argon2Profile {
    memory_kib: 8 * 1024,
    iterations: 1,
    parallelism: 1,
};

#[test]
fn messaging_records_round_trip_and_authenticate_metadata() {
    let key = VaultKey::generate().expect("test randomness");
    let ciphertext =
        seal_messaging_record(&key, "conversation-1", "incoming", b"hello").expect("seal record");

    assert_ne!(ciphertext, b"hello");
    assert_eq!(
        open_messaging_record(&key, "conversation-1", "incoming", &ciphertext)
            .expect("open record"),
        b"hello"
    );
    assert!(open_messaging_record(&key, "conversation-2", "incoming", &ciphertext).is_err());
    assert!(open_messaging_record(&key, "conversation-1", "outgoing", &ciphertext).is_err());
}

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
fn messaging_database_subkey_is_domain_separated() {
    let key = VaultKey::generate().expect("OS randomness");

    let messaging = key
        .derive_subkey(SubkeyPurpose::MessagingDatabaseV1)
        .expect("derive messaging database key");
    let database = key
        .derive_subkey(SubkeyPurpose::DatabaseV1)
        .expect("derive database key");
    let config = key
        .derive_subkey(SubkeyPurpose::LocalConfigV1)
        .expect("derive config key");

    assert_ne!(&*messaging, &*database);
    assert_ne!(&*messaging, &*config);
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

mod device_bound {
    use secure_crypto::{Argon2Profile, CryptoError, VaultKey, VaultKeyEnvelope};

    const FAST: Argon2Profile = Argon2Profile {
        memory_kib: 8 * 1024,
        iterations: 1,
        parallelism: 1,
    };
    const PASS: &[u8] = b"correct horse battery staple";

    #[test]
    fn device_bound_envelope_round_trips_with_the_same_device_secret() {
        let key = VaultKey::generate().expect("key");
        let secret = [7_u8; 32];
        let envelope =
            VaultKeyEnvelope::seal_device_bound(PASS, &secret, &key, FAST).expect("seal");
        assert!(envelope.is_device_bound());
        let reparsed = VaultKeyEnvelope::from_bytes(&envelope.to_bytes()).expect("parse");
        let opened = reparsed.open_device_bound(PASS, &secret).expect("open");
        assert_eq!(opened.as_bytes(), key.as_bytes());
    }

    #[test]
    fn a_destroyed_or_different_device_secret_makes_the_correct_passphrase_useless() {
        let key = VaultKey::generate().expect("key");
        let envelope =
            VaultKeyEnvelope::seal_device_bound(PASS, &[1_u8; 32], &key, FAST).expect("seal");
        assert_eq!(
            envelope.open_device_bound(PASS, &[2_u8; 32]).err(),
            Some(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn a_device_bound_envelope_cannot_be_opened_without_the_device_secret() {
        let key = VaultKey::generate().expect("key");
        let envelope =
            VaultKeyEnvelope::seal_device_bound(PASS, &[1_u8; 32], &key, FAST).expect("seal");
        assert_eq!(
            envelope.open(PASS).err(),
            Some(CryptoError::DeviceSecretRequired)
        );
    }

    #[test]
    fn relabelling_a_device_bound_envelope_as_legacy_fails_authentication() {
        let key = VaultKey::generate().expect("key");
        let envelope =
            VaultKeyEnvelope::seal_device_bound(PASS, &[1_u8; 32], &key, FAST).expect("seal");
        let mut bytes = envelope.to_bytes();
        bytes[4] = 1; // the version byte
        let relabelled = VaultKeyEnvelope::from_bytes(&bytes).expect("structurally valid");
        assert_eq!(
            relabelled.open(PASS).err(),
            Some(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn a_legacy_envelope_is_not_accepted_where_a_device_bound_one_is_required() {
        let key = VaultKey::generate().expect("key");
        let legacy = VaultKeyEnvelope::seal(PASS, &key, FAST).expect("seal");
        assert!(!legacy.is_device_bound());
        assert_eq!(
            legacy.open_device_bound(PASS, &[1_u8; 32]).err(),
            Some(CryptoError::NotDeviceBound)
        );
        assert_eq!(
            legacy.open(PASS).expect("legacy open").as_bytes(),
            key.as_bytes()
        );
    }
}
