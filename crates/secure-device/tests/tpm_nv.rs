//! Runs against a real TPM 2.0 (or `swtpm`) named by `SECURE_TPM_TCTI`, e.g.
//! `swtpm socket --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 \
//!   --tpmstate dir=/tmp/tpm --flags not-need-init,startup-clear` and
//! `SECURE_TPM_TCTI=swtpm:host=127.0.0.1,port=2321 cargo test -p secure-device --features tpm -- --ignored`.
#![cfg(all(feature = "tpm", target_os = "linux"))]

use secure_device::tpm::TpmNvStore;
use secure_device::{DeviceError, DeviceLocator, DeviceSecretStore};

fn store() -> TpmNvStore {
    TpmNvStore::from_environment().expect("SECURE_TPM_TCTI must name a reachable TPM")
}

#[test]
#[ignore = "needs a TPM 2.0 or swtpm; set SECURE_TPM_TCTI"]
fn secret_round_trips_through_tpm_nv() {
    let store = store();
    let (locator, secret) = store.create().expect("create");
    let reread = store.read(&locator).expect("read");
    assert_eq!(*reread, *secret);
    // A fresh connection (as after an application restart) reads the same secret.
    let again = store_from_locator_after_restart(&locator);
    assert_eq!(*again, *secret);
    store.destroy(&locator).expect("cleanup");
}

fn store_from_locator_after_restart(locator: &DeviceLocator) -> secure_device::DeviceSecret {
    let encoded = locator.encode();
    let decoded = DeviceLocator::decode(&encoded).expect("decode");
    store().read(&decoded).expect("read after restart")
}

#[test]
#[ignore = "needs a TPM 2.0 or swtpm; set SECURE_TPM_TCTI"]
fn destroyed_secret_is_gone_for_good_and_destroy_is_idempotent() {
    let store = store();
    let (locator, _secret) = store.create().expect("create");
    store.destroy(&locator).expect("destroy");
    assert!(matches!(store.read(&locator), Err(DeviceError::SecretGone)));
    store.destroy(&locator).expect("second destroy is success");
}

#[test]
#[ignore = "needs a TPM 2.0 or swtpm; set SECURE_TPM_TCTI"]
fn every_identity_gets_an_independent_secret() {
    let store = store();
    let (a, secret_a) = store.create().expect("create a");
    let (b, secret_b) = store.create().expect("create b");
    assert_ne!(a, b);
    assert_ne!(*secret_a, *secret_b);
    store.destroy(&a).expect("destroy a");
    assert_eq!(
        *store.read(&b).expect("b survives a's destruction"),
        *secret_b
    );
    store.destroy(&b).expect("cleanup");
}

#[test]
#[ignore = "needs a TPM 2.0 or swtpm; set SECURE_TPM_TCTI"]
fn locators_outside_the_owner_range_or_for_other_backends_are_refused() {
    let store = store();
    for locator in [
        DeviceLocator::new("tpm2-nv", 0x0180_0000),
        DeviceLocator::new("memory", 0x0100_0001),
    ] {
        assert!(matches!(
            store.read(&locator),
            Err(DeviceError::InvalidLocator)
        ));
        assert!(matches!(
            store.destroy(&locator),
            Err(DeviceError::InvalidLocator)
        ));
    }
}
