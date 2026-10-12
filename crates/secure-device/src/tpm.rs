//! TPM 2.0 NV-index backend (feature `tpm`).
//!
//! Each identity's secret is a 32-byte ordinary NV index under the owner hierarchy, at a random
//! handle in the TCG owner range (0x01000000-0x013FFFFF). The index lives in the TPM's own
//! non-volatile memory, so copying or restoring the application-data directory (or the whole
//! user profile, or a disk image) does not copy it, and undefining it is permanent.
//!
//! Connection: `SECURE_TPM_TCTI` if set (any tpm2-tss TCTI string, e.g.
//! `swtpm:host=127.0.0.1,port=2321` for tests), otherwise `device:/dev/tpmrm0` - the kernel
//! resource manager, which on most distributions requires membership of the `tss` group.
//!
//! Assumptions and limits:
//! - Owner-hierarchy authorization is the empty password, the default on Linux unless an
//!   administrator has taken ownership. If it is not, every operation fails and identity
//!   provisioning fails closed.
//! - Any local process with TPM access can read or overwrite the index. That is no worse than the
//!   application-data directory itself (same user); what matters here is that Burn can destroy it
//!   and a snapshot cannot bring it back.
//! - Commands use an unsalted session, so the secret crosses the TPM bus in the clear. A physical
//!   bus interposer is out of scope.
//! - A VM snapshot that includes virtual-TPM state restores the index with it
//!   (`docs/backup-snapshot-hardening.md` lists this limit).

use std::convert::TryFrom;
use std::str::FromStr;

use tss_esapi::Context;
use tss_esapi::abstraction::nv;
use tss_esapi::attributes::NvIndexAttributesBuilder;
use tss_esapi::handles::{NvIndexHandle, NvIndexTpmHandle, TpmHandle};
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::resource_handles::{NvAuth, Provision};
use tss_esapi::structures::{MaxNvBuffer, NvPublicBuilder};
use tss_esapi::tcti_ldr::TctiNameConf;
use zeroize::Zeroizing;

use crate::{
    DeviceError, DeviceLocator, DeviceSecret, DeviceSecretStore, SECRET_LEN, random_secret,
};

const BACKEND: &str = "tpm2-nv";
const OWNER_RANGE_START: u32 = 0x0100_0000;
const OWNER_RANGE_LEN: u32 = 0x0040_0000;
const CREATE_ATTEMPTS: usize = 8;

/// TPM 2.0 NV-index [`DeviceSecretStore`].
#[derive(Debug)]
pub struct TpmNvStore {
    tcti: TctiNameConf,
    /// One TPM conversation at a time from this process. The kernel resource manager allows
    /// concurrent contexts, but a raw `/dev/tpm0` or `swtpm` connection does not, and these
    /// operations are rare enough that serialising them costs nothing.
    serial: std::sync::Mutex<()>,
}

fn backend_error(error: impl std::fmt::Display) -> DeviceError {
    DeviceError::Backend(error.to_string())
}

impl TpmNvStore {
    /// Connect using `SECURE_TPM_TCTI` or `/dev/tpmrm0`, and prove the TPM answers.
    pub fn from_environment() -> Result<Self, DeviceError> {
        let tcti =
            std::env::var("SECURE_TPM_TCTI").unwrap_or_else(|_| "device:/dev/tpmrm0".to_owned());
        Self::with_tcti(&tcti)
    }

    /// Connect using an explicit tpm2-tss TCTI string.
    pub fn with_tcti(tcti: &str) -> Result<Self, DeviceError> {
        let tcti = TctiNameConf::from_str(tcti)
            .map_err(|error| DeviceError::Unavailable(format!("invalid TCTI {tcti:?}: {error}")))?;
        let store = Self {
            tcti,
            serial: std::sync::Mutex::new(()),
        };
        let probe = store.context();
        drop(
            probe
                .map_err(|error| DeviceError::Unavailable(format!("no usable TPM 2.0: {error}")))?,
        );
        Ok(store)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.serial
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn context(&self) -> Result<Context, DeviceError> {
        Context::new(self.tcti.clone()).map_err(backend_error)
    }

    fn tpm_handle(locator: &DeviceLocator) -> Result<NvIndexTpmHandle, DeviceError> {
        if locator.backend() != BACKEND {
            return Err(DeviceError::InvalidLocator);
        }
        let handle = locator.handle();
        if !(OWNER_RANGE_START..OWNER_RANGE_START + OWNER_RANGE_LEN).contains(&handle) {
            return Err(DeviceError::InvalidLocator);
        }
        NvIndexTpmHandle::new(handle).map_err(|_| DeviceError::InvalidLocator)
    }

    fn exists(context: &mut Context, handle: NvIndexTpmHandle) -> Result<bool, DeviceError> {
        Ok(nv::list(context)
            .map_err(backend_error)?
            .iter()
            .any(|(public, _)| public.nv_index() == handle))
    }

    fn esys_handle(
        context: &mut Context,
        handle: NvIndexTpmHandle,
    ) -> Result<NvIndexHandle, DeviceError> {
        context
            .tr_from_tpm_public(TpmHandle::NvIndex(handle))
            .map(NvIndexHandle::from)
            .map_err(backend_error)
    }

    fn write(
        context: &mut Context,
        index: NvIndexHandle,
        bytes: &[u8; SECRET_LEN],
    ) -> Result<(), DeviceError> {
        let buffer = MaxNvBuffer::try_from(bytes.to_vec()).map_err(backend_error)?;
        context
            .execute_with_nullauth_session(|ctx| ctx.nv_write(NvAuth::Owner, index, buffer, 0))
            .map_err(backend_error)
    }

    fn random_handle() -> Result<u32, DeviceError> {
        use rand_core::{OsRng, RngCore};
        let mut bytes = [0_u8; 4];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| DeviceError::RandomnessUnavailable)?;
        Ok(OWNER_RANGE_START + u32::from_le_bytes(bytes) % OWNER_RANGE_LEN)
    }
}

impl DeviceSecretStore for TpmNvStore {
    fn create(&self) -> Result<(DeviceLocator, DeviceSecret), DeviceError> {
        let _serial = self.lock();
        let mut context = self.context()?;
        let attributes = NvIndexAttributesBuilder::new()
            .with_owner_write(true)
            .with_owner_read(true)
            .with_no_da(true)
            .build()
            .map_err(backend_error)?;

        for _ in 0..CREATE_ATTEMPTS {
            let raw = Self::random_handle()?;
            let handle = NvIndexTpmHandle::new(raw).map_err(backend_error)?;
            if Self::exists(&mut context, handle)? {
                continue;
            }
            let public = NvPublicBuilder::new()
                .with_nv_index(handle)
                .with_index_name_algorithm(HashingAlgorithm::Sha256)
                .with_index_attributes(attributes)
                .with_data_area_size(SECRET_LEN)
                .build()
                .map_err(backend_error)?;
            let index = context
                .execute_with_nullauth_session(|ctx| {
                    ctx.nv_define_space(Provision::Owner, None, public)
                })
                .map_err(backend_error)?;

            let secret = random_secret()?;
            if let Err(error) = Self::write(&mut context, index, &secret) {
                // Never leave a defined-but-unwritten index behind.
                let _ = context.execute_with_nullauth_session(|ctx| {
                    ctx.nv_undefine_space(Provision::Owner, index)
                });
                return Err(error);
            }
            return Ok((DeviceLocator::new(BACKEND, raw), secret));
        }
        Err(DeviceError::Backend(
            "no free NV handle found in the owner range".to_owned(),
        ))
    }

    fn read(&self, locator: &DeviceLocator) -> Result<DeviceSecret, DeviceError> {
        let _serial = self.lock();
        let handle = Self::tpm_handle(locator)?;
        let mut context = self.context()?;
        if !Self::exists(&mut context, handle)? {
            return Err(DeviceError::SecretGone);
        }
        let bytes = Zeroizing::new(
            context
                .execute_with_nullauth_session(|ctx| nv::read_full(ctx, NvAuth::Owner, handle))
                .map_err(backend_error)?,
        );
        let secret: [u8; SECRET_LEN] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| DeviceError::Backend("NV index has an unexpected size".to_owned()))?;
        Ok(Zeroizing::new(secret))
    }

    fn destroy(&self, locator: &DeviceLocator) -> Result<(), DeviceError> {
        let _serial = self.lock();
        let handle = Self::tpm_handle(locator)?;
        let mut context = self.context()?;
        if !Self::exists(&mut context, handle)? {
            return Ok(());
        }
        let index = Self::esys_handle(&mut context, handle)?;
        // Overwrite first (defence in depth against an implementation that does not scrub
        // undefined NV), then undefine - the step that makes it permanently unrecoverable.
        let cover = random_secret()?;
        let _ = Self::write(&mut context, index, &cover);
        context
            .execute_with_nullauth_session(|ctx| ctx.nv_undefine_space(Provision::Owner, index))
            .map_err(backend_error)
    }
}
