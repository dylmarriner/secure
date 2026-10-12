//! In-memory [`DeviceSecretStore`] for tests (feature `test-store`). It simulates a TPM that
//! lives outside the application-data directory, so tests can exercise snapshot-restore and
//! Burn semantics. It provides no security property and must never back a shipped build.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::{DeviceError, DeviceLocator, DeviceSecret, DeviceSecretStore, random_secret};

#[derive(Debug, Default)]
pub struct MemoryStore {
    secrets: Mutex<(u32, HashMap<u32, [u8; crate::SECRET_LEN]>)>,
}

impl MemoryStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many secrets currently exist (test assertions).
    #[must_use]
    pub fn live_secrets(&self) -> usize {
        self.secrets.lock().expect("lock").1.len()
    }
}

impl DeviceSecretStore for MemoryStore {
    fn create(&self) -> Result<(DeviceLocator, DeviceSecret), DeviceError> {
        let secret = random_secret()?;
        let mut guard = self.secrets.lock().expect("lock");
        guard.0 += 1;
        let handle = guard.0;
        guard.1.insert(handle, *secret);
        Ok((DeviceLocator::new("memory", handle), secret))
    }

    fn read(&self, locator: &DeviceLocator) -> Result<DeviceSecret, DeviceError> {
        if locator.backend() != "memory" {
            return Err(DeviceError::InvalidLocator);
        }
        self.secrets
            .lock()
            .expect("lock")
            .1
            .get(&locator.handle())
            .map(|secret| zeroize::Zeroizing::new(*secret))
            .ok_or(DeviceError::SecretGone)
    }

    fn destroy(&self, locator: &DeviceLocator) -> Result<(), DeviceError> {
        if locator.backend() != "memory" {
            return Err(DeviceError::InvalidLocator);
        }
        self.secrets
            .lock()
            .expect("lock")
            .1
            .remove(&locator.handle());
        Ok(())
    }
}
