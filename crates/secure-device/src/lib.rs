//! Device-bound destruction secrets (`docs/backup-snapshot-hardening.md`).
//!
//! Burn must make an old copy of Secure's application-data directory useless even to someone who
//! knows the old passphrase. That is impossible if every secret the identity needs lives in that
//! directory, so each identity's vault-key envelope is also bound to a random 32-byte secret kept
//! in device storage outside it (`secure_crypto::VaultKeyEnvelope::seal_device_bound`). Burn
//! destroys that secret; a restored envelope then has nothing to unwrap with.
//!
//! The application-data directory stores only a [`DeviceLocator`] - where the secret lives, not
//! the secret.
//!
//! Backends:
//! - [`tpm::TpmNvStore`] (feature `tpm`, Linux): a TPM 2.0 NV index under the owner hierarchy.
//! - [`UnavailableStore`]: every operation fails, so a platform without a supported backend
//!   refuses to provision a production identity instead of silently downgrading
//!   (`docs/self-destruct-semantics.md` invariant 6).
//! - [`memory::MemoryStore`] (feature `test-store`): tests only.
//!
//! What a TPM-backed secret does **not** cover, stated plainly: a VM snapshot that includes the
//! virtual TPM's state; an attacker with live code execution as the user while the identity is
//! unlocked (they can read the vault key from memory anyway); and a physical TPM-bus interposer,
//! because the NV read uses an unsalted session (`tpm` module docs).

#[cfg(feature = "test-store")]
pub mod memory;
#[cfg(feature = "tpm")]
pub mod tpm;

use std::fmt;

use thiserror::Error;
use zeroize::Zeroizing;

/// Length of a device secret, matching `secure_crypto::DEVICE_SECRET_LEN`.
pub const SECRET_LEN: usize = 32;

/// A device secret held in memory only while needed; zeroed on drop.
pub type DeviceSecret = Zeroizing<[u8; SECRET_LEN]>;

#[derive(Debug, Error)]
pub enum DeviceError {
    #[error(
        "no supported device-bound key storage is available on this machine ({0}); Secure \
         refuses to create or open a production identity without it"
    )]
    Unavailable(String),
    #[error("the device-bound secret for this identity no longer exists (it was destroyed)")]
    SecretGone,
    #[error("invalid device locator")]
    InvalidLocator,
    #[error("operating-system randomness unavailable")]
    RandomnessUnavailable,
    #[error("device storage error: {0}")]
    Backend(String),
}

/// Where an identity's device secret lives. Persisted in the application-data directory; it
/// reveals nothing about the secret itself.
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceLocator {
    backend: String,
    handle: u32,
}

impl fmt::Debug for DeviceLocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{:#010x}", self.backend, self.handle)
    }
}

const LOCATOR_MAGIC: &str = "SDL1";

impl DeviceLocator {
    #[must_use]
    pub fn new(backend: &str, handle: u32) -> Self {
        Self {
            backend: backend.to_owned(),
            handle,
        }
    }

    #[must_use]
    pub fn backend(&self) -> &str {
        &self.backend
    }

    #[must_use]
    pub fn handle(&self) -> u32 {
        self.handle
    }

    /// Versioned text encoding: `SDL1\n<backend>\n<handle hex>\n`.
    #[must_use]
    pub fn encode(&self) -> String {
        format!("{LOCATOR_MAGIC}\n{}\n{:08x}\n", self.backend, self.handle)
    }

    pub fn decode(text: &str) -> Result<Self, DeviceError> {
        let mut lines = text.lines();
        if lines.next() != Some(LOCATOR_MAGIC) {
            return Err(DeviceError::InvalidLocator);
        }
        let backend = lines.next().ok_or(DeviceError::InvalidLocator)?;
        if backend.is_empty()
            || !backend
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(DeviceError::InvalidLocator);
        }
        let handle = lines
            .next()
            .and_then(|hex| u32::from_str_radix(hex, 16).ok())
            .ok_or(DeviceError::InvalidLocator)?;
        if lines.next().is_some() {
            return Err(DeviceError::InvalidLocator);
        }
        Ok(Self::new(backend, handle))
    }
}

/// Storage for device-bound secrets. Implementations must keep the secret outside the
/// application-data directory, and `destroy` must make it permanently unrecoverable.
pub trait DeviceSecretStore: Send + Sync {
    /// Create a fresh random secret in device storage.
    fn create(&self) -> Result<(DeviceLocator, DeviceSecret), DeviceError>;
    /// Read an existing secret. [`DeviceError::SecretGone`] once destroyed.
    fn read(&self, locator: &DeviceLocator) -> Result<DeviceSecret, DeviceError>;
    /// Permanently destroy a secret. Idempotent: a secret that is already gone is success.
    fn destroy(&self, locator: &DeviceLocator) -> Result<(), DeviceError>;
}

/// The store for platforms with no supported device-bound backend: every operation fails.
#[derive(Debug, Clone)]
pub struct UnavailableStore {
    reason: String,
}

impl UnavailableStore {
    #[must_use]
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl DeviceSecretStore for UnavailableStore {
    fn create(&self) -> Result<(DeviceLocator, DeviceSecret), DeviceError> {
        Err(DeviceError::Unavailable(self.reason.clone()))
    }

    fn read(&self, _locator: &DeviceLocator) -> Result<DeviceSecret, DeviceError> {
        Err(DeviceError::Unavailable(self.reason.clone()))
    }

    fn destroy(&self, _locator: &DeviceLocator) -> Result<(), DeviceError> {
        Err(DeviceError::Unavailable(self.reason.clone()))
    }
}

pub(crate) fn random_secret() -> Result<DeviceSecret, DeviceError> {
    use rand_core::{OsRng, RngCore};
    let mut secret = Zeroizing::new([0_u8; SECRET_LEN]);
    OsRng
        .try_fill_bytes(&mut *secret)
        .map_err(|_| DeviceError::RandomnessUnavailable)?;
    Ok(secret)
}

/// The production store for this platform: the TPM backend where it is compiled in, otherwise
/// [`UnavailableStore`] (which makes identity provisioning fail closed).
#[must_use]
pub fn platform_store() -> Box<dyn DeviceSecretStore> {
    #[cfg(feature = "tpm")]
    {
        match tpm::TpmNvStore::from_environment() {
            Ok(store) => Box::new(store),
            Err(error) => Box::new(UnavailableStore::new(error.to_string())),
        }
    }
    #[cfg(not(feature = "tpm"))]
    {
        Box::new(UnavailableStore::new(
            "this build has no device-bound key backend for this platform",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locator_round_trips() {
        let locator = DeviceLocator::new("tpm2-nv", 0x015e_c123);
        assert_eq!(
            DeviceLocator::decode(&locator.encode()).expect("decode"),
            locator
        );
    }

    #[test]
    fn malformed_locators_are_rejected() {
        for text in [
            "",
            "SDL1",
            "SDL1\ntpm2-nv",
            "SDL1\ntpm2-nv\nzz\n",
            "SDL2\ntpm2-nv\n015ec123\n",
            "SDL1\n../x\n015ec123\n",
            "SDL1\ntpm2-nv\n015ec123\nextra\n",
        ] {
            assert!(DeviceLocator::decode(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn unavailable_store_fails_every_operation() {
        let store = UnavailableStore::new("no TPM");
        let locator = DeviceLocator::new("tpm2-nv", 1);
        assert!(matches!(store.create(), Err(DeviceError::Unavailable(_))));
        assert!(matches!(
            store.read(&locator),
            Err(DeviceError::Unavailable(_))
        ));
        assert!(matches!(
            store.destroy(&locator),
            Err(DeviceError::Unavailable(_))
        ));
    }
}
