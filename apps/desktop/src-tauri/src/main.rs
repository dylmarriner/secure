//! Secure desktop Tauri host.
//!
//! This binary is deliberately the only place in the application allowed to hold the vault
//! master key and an open vault handle. The WebView only ever receives an [`AppStatus`] over
//! IPC; it never receives passphrases back, key material, or a database handle.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use secure_core::{AppEvent, AppLifecycle, AppState};
use secure_crypto::{Argon2Profile, VaultKey, VaultKeyEnvelope};
use secure_storage::Vault;
use serde::Serialize;
use tauri::{Manager, State};
use zeroize::Zeroizing;

const ENVELOPE_FILE_NAME: &str = "vault.key";
const DATABASE_FILE_NAME: &str = "vault.db";

/// Passphrases below this length are rejected during onboarding. This is a floor, not a
/// strength meter: it exists to stop trivially short input, not to replace the Argon2id
/// wrapping key derivation that actually protects the vault master key.
const MIN_PASSPHRASE_LEN: usize = 12;

struct VaultPaths {
    envelope: PathBuf,
    database: PathBuf,
}

impl VaultPaths {
    fn new(app_data_dir: PathBuf) -> Self {
        Self {
            envelope: app_data_dir.join(ENVELOPE_FILE_NAME),
            database: app_data_dir.join(DATABASE_FILE_NAME),
        }
    }

    /// A vault is considered to exist once its key envelope is on disk. The envelope, not the
    /// database file, is the source of truth: without it the database file - if present -
    /// cannot be decrypted by this application at all.
    fn vault_exists(&self) -> bool {
        self.envelope.exists()
    }
}

/// Long-term secret state that only exists between a successful unlock and the next lock.
/// Dropping this struct drops the SQLCipher connection and zeroes the vault master key. Both
/// fields are held only for that `Drop` behaviour and are never read directly, which is
/// exactly the point: nothing in this binary reaches into an unlocked vault's key material
/// except through the two fields' own `Drop` implementations.
#[allow(dead_code)]
struct UnlockedVault {
    key: VaultKey,
    vault: Vault,
}

struct AppRuntime {
    lifecycle: Mutex<AppLifecycle>,
    paths: VaultPaths,
    unlocked: Mutex<Option<UnlockedVault>>,
}

impl AppRuntime {
    fn new(paths: VaultPaths) -> Self {
        let mut lifecycle = AppLifecycle::new(AppState::Starting);
        let startup_event = if paths.vault_exists() {
            AppEvent::ExistingVault
        } else {
            AppEvent::NeedsOnboarding
        };
        lifecycle
            .apply(startup_event)
            .expect("Starting always accepts ExistingVault/NeedsOnboarding");

        Self {
            lifecycle: Mutex::new(lifecycle),
            paths,
            unlocked: Mutex::new(None),
        }
    }
}

#[derive(Debug, Serialize)]
struct AppStatus {
    state: &'static str,
}

fn status_for(state: AppState) -> AppStatus {
    AppStatus {
        state: match state {
            AppState::Starting => "starting",
            AppState::Onboarding => "onboarding",
            AppState::Locked => "locked",
            AppState::Unlocked => "unlocked",
            AppState::Ghost => "ghost",
            AppState::Destroying => "destroying",
            AppState::Destroyed => "destroyed",
        },
    }
}

/// Write `bytes` to `path` without ever leaving a partially-written file in place of an
/// existing one: write to a sibling temp file first, then atomically rename it into place.
fn write_file_atomically(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "target path has no parent directory",
        )
    })?;
    let mut tmp_path = parent.to_path_buf();
    let mut file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "target path has no file name"))?
        .to_os_string();
    file_name.push(".tmp");
    tmp_path.push(file_name);

    fs::write(&tmp_path, bytes)?;
    fs::rename(&tmp_path, path)
}

/// All command logic lives here as plain functions over `&AppRuntime`, independent of Tauri's
/// `State` extractor, so it can be exercised directly by tests without needing a running Tauri
/// application. The `#[tauri::command]` functions below are thin IPC adapters over these.
fn app_status_impl(runtime: &AppRuntime) -> Result<AppStatus, String> {
    let lifecycle = runtime
        .lifecycle
        .lock()
        .map_err(|_| "application lifecycle lock poisoned".to_owned())?;
    Ok(status_for(lifecycle.state()))
}

/// Create a brand-new vault: generate a random vault master key, wrap it under the given
/// passphrase, persist the envelope, and create the (empty) encrypted database. On any
/// failure after the envelope is written, the envelope is removed again so a half-finished
/// onboarding attempt cannot be mistaken for an existing vault on the next launch.
fn complete_onboarding_impl(passphrase: String, runtime: &AppRuntime) -> Result<AppStatus, String> {
    let passphrase = Zeroizing::new(passphrase);
    if passphrase.len() < MIN_PASSPHRASE_LEN {
        return Err(format!(
            "passphrase must be at least {MIN_PASSPHRASE_LEN} characters"
        ));
    }

    let mut lifecycle = runtime
        .lifecycle
        .lock()
        .map_err(|_| "application lifecycle lock poisoned".to_owned())?;

    if lifecycle.state() != AppState::Onboarding {
        return Err(format!(
            "cannot complete onboarding from {:?}",
            lifecycle.state()
        ));
    }

    if runtime.paths.vault_exists() {
        return Err("a vault already exists at this location".to_owned());
    }

    let vault_key =
        VaultKey::generate().map_err(|_| "failed to generate vault master key".to_owned())?;
    let envelope = VaultKeyEnvelope::seal(
        passphrase.as_bytes(),
        &vault_key,
        Argon2Profile::RECOMMENDED_V1,
    )
    .map_err(|_| "failed to seal the vault key envelope".to_owned())?;

    write_file_atomically(&runtime.paths.envelope, &envelope.to_bytes())
        .map_err(|error| format!("failed to persist the vault key envelope: {error}"))?;

    if let Err(error) = Vault::create_new(&runtime.paths.database, &vault_key) {
        let _ = fs::remove_file(&runtime.paths.envelope);
        return Err(format!(
            "failed to create the encrypted vault database: {error}"
        ));
    }

    lifecycle
        .apply(AppEvent::OnboardingComplete)
        .map_err(|error| error.to_string())?;

    Ok(status_for(lifecycle.state()))
}

/// Open an existing vault: read the key envelope, unwrap the vault master key with the given
/// passphrase, and open the encrypted database with the derived database subkey. The vault
/// master key and the open database handle live only in `runtime.unlocked` for as long as the
/// application remains unlocked; they are never returned to the WebView.
fn unlock_application_impl(passphrase: String, runtime: &AppRuntime) -> Result<AppStatus, String> {
    let passphrase = Zeroizing::new(passphrase);

    let mut lifecycle = runtime
        .lifecycle
        .lock()
        .map_err(|_| "application lifecycle lock poisoned".to_owned())?;

    if lifecycle.state() != AppState::Locked {
        return Err(format!("cannot unlock from {:?}", lifecycle.state()));
    }

    let envelope_bytes = fs::read(&runtime.paths.envelope)
        .map_err(|_| "vault key envelope is missing or unreadable".to_owned())?;
    let envelope = VaultKeyEnvelope::from_bytes(&envelope_bytes)
        .map_err(|_| "vault key envelope is invalid or corrupt".to_owned())?;
    let vault_key = envelope
        .open(passphrase.as_bytes())
        .map_err(|_| "incorrect passphrase".to_owned())?;
    let vault = Vault::open_existing(&runtime.paths.database, &vault_key)
        .map_err(|error| format!("failed to open the encrypted vault database: {error}"))?;

    let mut unlocked = runtime
        .unlocked
        .lock()
        .map_err(|_| "vault handle lock poisoned".to_owned())?;
    *unlocked = Some(UnlockedVault {
        key: vault_key,
        vault,
    });
    drop(unlocked);

    lifecycle
        .apply(AppEvent::UnlockSucceeded)
        .map_err(|error| error.to_string())?;

    Ok(status_for(lifecycle.state()))
}

/// Lock the application: drop the open database handle and zero the vault master key before
/// reporting success, so no runtime secret state outlives the transition back to `Locked`.
fn lock_application_impl(runtime: &AppRuntime) -> Result<AppStatus, String> {
    let mut lifecycle = runtime
        .lifecycle
        .lock()
        .map_err(|_| "application lifecycle lock poisoned".to_owned())?;

    match lifecycle.state() {
        AppState::Unlocked => {
            lifecycle
                .apply(AppEvent::Lock)
                .map_err(|error| error.to_string())?;

            let mut unlocked = runtime
                .unlocked
                .lock()
                .map_err(|_| "vault handle lock poisoned".to_owned())?;
            // Dropping the previous value here closes the SQLCipher connection and zeroes the
            // vault master key (VaultKey wraps its bytes in `Zeroizing`).
            *unlocked = None;
        }
        AppState::Locked => {}
        state => return Err(format!("cannot lock application from {state:?}")),
    }

    Ok(status_for(lifecycle.state()))
}

#[tauri::command]
fn app_status(runtime: State<'_, AppRuntime>) -> Result<AppStatus, String> {
    app_status_impl(&runtime)
}

#[tauri::command]
fn complete_onboarding(
    passphrase: String,
    runtime: State<'_, AppRuntime>,
) -> Result<AppStatus, String> {
    complete_onboarding_impl(passphrase, &runtime)
}

#[tauri::command]
fn unlock_application(
    passphrase: String,
    runtime: State<'_, AppRuntime>,
) -> Result<AppStatus, String> {
    unlock_application_impl(passphrase, &runtime)
}

#[tauri::command]
fn lock_application(runtime: State<'_, AppRuntime>) -> Result<AppStatus, String> {
    lock_application_impl(&runtime)
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let app_data_dir = app
                .path()
                .app_data_dir()
                .expect("application data directory must be resolvable");
            fs::create_dir_all(&app_data_dir)
                .expect("failed to create the application data directory");
            app.manage(AppRuntime::new(VaultPaths::new(app_data_dir)));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            app_status,
            complete_onboarding,
            unlock_application,
            lock_application
        ])
        .run(tauri::generate_context!())
        .expect("failed to run Secure desktop application");
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSPHRASE: &str = "correct horse battery staple";

    fn runtime_in(dir: &std::path::Path) -> AppRuntime {
        AppRuntime::new(VaultPaths::new(dir.to_path_buf()))
    }

    #[test]
    fn fresh_install_starts_in_onboarding() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        let status = app_status_impl(&runtime).expect("status");
        assert_eq!(status.state, "onboarding");
    }

    #[test]
    fn full_onboard_lock_unlock_lock_cycle() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());

        let status =
            complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding succeeds");
        assert_eq!(status.state, "locked");
        assert!(runtime.paths.envelope.is_file());
        assert!(runtime.paths.database.is_file());

        let status =
            unlock_application_impl(PASSPHRASE.to_owned(), &runtime).expect("unlock succeeds");
        assert_eq!(status.state, "unlocked");

        let status = lock_application_impl(&runtime).expect("lock succeeds");
        assert_eq!(status.state, "locked");

        // A brand-new AppRuntime pointed at the same directory must see the vault as already
        // existing and start Locked, not Onboarding - onboarding is not repeatable.
        let restarted = runtime_in(dir.path());
        let status = app_status_impl(&restarted).expect("status");
        assert_eq!(status.state, "locked");

        let status = unlock_application_impl(PASSPHRASE.to_owned(), &restarted)
            .expect("unlock across a restart succeeds with the correct passphrase");
        assert_eq!(status.state, "unlocked");
    }

    #[test]
    fn onboarding_rejects_short_passphrase() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        let error = complete_onboarding_impl("short".to_owned(), &runtime)
            .expect_err("short passphrase must be rejected");
        assert!(error.contains("at least"));
        assert!(
            !runtime.paths.envelope.exists(),
            "a rejected onboarding attempt must not write an envelope"
        );
    }

    #[test]
    fn onboarding_cannot_run_twice() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("first onboarding");

        let error = complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime)
            .expect_err("onboarding a second time must fail");
        assert!(error.contains("cannot complete onboarding"));
    }

    #[test]
    fn unlock_rejects_wrong_passphrase() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");

        let error = unlock_application_impl("definitely the wrong passphrase".to_owned(), &runtime)
            .expect_err("wrong passphrase must fail");
        assert_eq!(error, "incorrect passphrase");

        // Lifecycle must remain Locked, not silently advance to Unlocked, after a failed
        // unlock attempt.
        let status = app_status_impl(&runtime).expect("status");
        assert_eq!(status.state, "locked");
    }

    #[test]
    fn unlock_is_rejected_before_onboarding_completes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        let error = unlock_application_impl(PASSPHRASE.to_owned(), &runtime)
            .expect_err("cannot unlock a vault that does not exist yet");
        assert!(error.contains("cannot unlock from"));
    }

    #[test]
    fn locking_an_already_locked_application_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");

        let status = lock_application_impl(&runtime).expect("locking an already-locked app");
        assert_eq!(status.state, "locked");
    }

    #[test]
    fn failed_onboarding_does_not_leave_an_orphaned_envelope() {
        // Simulate a database-creation failure after the envelope has already been written by
        // pre-creating the database path as a directory, which Vault::create_new refuses to
        // touch. complete_onboarding_impl must then remove the envelope it just wrote.
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = VaultPaths::new(dir.path().to_path_buf());
        std::fs::create_dir_all(&paths.database).expect("pre-create database path as directory");
        let runtime = AppRuntime::new(VaultPaths::new(dir.path().to_path_buf()));

        let error = complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime)
            .expect_err("database creation must fail");
        assert!(error.contains("failed to create the encrypted vault database"));
        assert!(
            !runtime.paths.envelope.exists(),
            "the orphaned envelope must be cleaned up after a failed onboarding"
        );
    }
}
