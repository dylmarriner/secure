//! Application runtime state and lifecycle command logic.
//!
//! All command logic lives here as plain functions over `&AppRuntime`, independent of Tauri's
//! `State` extractor, so it can be exercised directly by tests without needing a running Tauri
//! application. The `#[tauri::command]` functions in `main.rs` are thin IPC adapters over these.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rand_core::{OsRng, RngCore};
use secure_attachments::store::AttachmentStore;
use secure_core::{AppEvent, AppLifecycle, AppState, DestructionEvent, DestructionStage};
use secure_crypto::{Argon2Profile, VaultKey, VaultKeyEnvelope};
use secure_storage::Vault;
use secure_transport::{TorTransport, TransportState};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::destruction_journal;
#[cfg(feature = "simplex-native")]
pub(crate) use crate::messaging::MessagingStatus;
#[cfg(feature = "simplex-native")]
use crate::messaging::{MessagingRuntime, MessagingStartError};

const ENVELOPE_FILE_NAME: &str = "vault.key";
const DATABASE_FILE_NAME: &str = "vault.db";
const ATTEMPTS_FILE_NAME: &str = "vault.attempts";
const BURN_JOURNAL_FILE_NAME: &str = "vault.burn";

/// Passphrases below this length are rejected during onboarding. This is a floor, not a
/// strength meter: it exists to stop trivially short input, not to replace the Argon2id
/// wrapping key derivation that actually protects the vault master key.
const MIN_PASSPHRASE_LEN: usize = 12;

/// After this many consecutive incorrect passphrase attempts, [`unlock_application_impl`]
/// performs a full Burn Identity (Phase 6) rather than merely refusing the attempt. This is a
/// wipe-on-brute-force failsafe, not an additional access control: the actual protection on the
/// vault is still Argon2id plus the passphrase itself. See [`destroy_identity_locked`] for what
/// "destroys" means here and its honest limits.
const MAX_FAILED_UNLOCK_ATTEMPTS: u32 = 3;

pub(crate) struct VaultPaths {
    envelope: PathBuf,
    database: PathBuf,
    /// Persisted count of consecutive incorrect unlock attempts. Deliberately stored as a
    /// plain, unauthenticated integer next to the envelope rather than protected/encrypted
    /// somehow: protecting it would require a key that itself requires the correct passphrase
    /// to obtain, which is exactly what this counter exists to gate *before* that succeeds.
    /// Anyone with direct read/write access to the application's data directory can reset or
    /// edit this file to defeat the wipe-on-N-attempts failsafe - but that same level of access
    /// already lets them copy the encrypted database and envelope out for offline attack, or
    /// delete them outright, so this file being tamperable does not lower the vault's actual
    /// security boundary. What it defends against is repeated passphrase guesses made *through
    /// this application's own unlock command*, which is the threat "wrong PIN 3 times" is
    /// actually describing.
    attempts: PathBuf,
    /// Durable Burn Identity progress marker. Its *existence* means a burn was started and has
    /// not been observed to finish; its contents name how far the sequence got. See
    /// [`destruction_journal`] for why a damaged one is treated as a pending burn rather than
    /// as no burn at all.
    journal: PathBuf,
    /// Directory of encrypted attachment objects (`secure_attachments::store`). Deleted whole by
    /// Burn Identity; individual objects are deleted after a Burn Conversation destroys their keys.
    attachments: PathBuf,
    /// The normal identity's SimpleX store prefix. Not feature-gated: a store created by a
    /// `simplex-native` build must still be cleaned up by Burn Identity in any build.
    messaging_prefix: PathBuf,
    /// A different file prefix from `messaging_prefix`, so a Ghost session's SimpleX store can
    /// never be the normal vault's - see [`GhostSession`]/the Ghost checklist in this phase's
    /// plan. Reused (not randomised) across Ghost sessions: only one Ghost session is ever
    /// active at a time, and it is always cleaned up (best-effort) before reuse, both at
    /// `AppRuntime::new` (restart) and at the start/end of every Ghost session.
    ghost_messaging_prefix: PathBuf,
}

impl VaultPaths {
    pub(crate) fn new(app_data_dir: PathBuf) -> Self {
        Self {
            envelope: app_data_dir.join(ENVELOPE_FILE_NAME),
            database: app_data_dir.join(DATABASE_FILE_NAME),
            attempts: app_data_dir.join(ATTEMPTS_FILE_NAME),
            journal: app_data_dir.join(BURN_JOURNAL_FILE_NAME),
            attachments: app_data_dir.join("attachments"),
            messaging_prefix: app_data_dir.join("simplex"),
            ghost_messaging_prefix: app_data_dir.join("ghost-simplex"),
        }
    }

    /// A vault is considered to exist once its key envelope is on disk. The envelope, not the
    /// database file, is the source of truth: without it the database file - if present -
    /// cannot be decrypted by this application at all.
    fn vault_exists(&self) -> bool {
        self.envelope.exists()
    }
}

/// Read the persisted failed-unlock-attempt count. Missing, unreadable or non-numeric content
/// is treated as `0` rather than an error - a failure to read this advisory counter must never
/// itself block a legitimate unlock attempt.
fn read_failed_attempts(path: &Path) -> u32 {
    fs::read_to_string(path)
        .ok()
        .and_then(|contents| contents.trim().parse::<u32>().ok())
        .unwrap_or(0)
}

/// Persist the failed-unlock-attempt count, atomically (see [`write_file_atomically`]) so a
/// crash mid-write can never leave a torn value that parses as some other count.
fn write_failed_attempts(path: &Path, count: u32) -> io::Result<()> {
    write_file_atomically(path, count.to_string().as_bytes())
}

/// Best-effort delete every file in `prefix`'s directory whose name starts with `prefix`'s own
/// file name - i.e. everything SimpleX's native core created under one `db_file_prefix`
/// (`<prefix>_chat.db`, `<prefix>_agent.db`, and any of their own `-wal`/`-shm` sidecars).
/// Deliberately not a hard failure if a file cannot be removed (permissions, already gone) -
/// this is disk hygiene for an ephemeral Ghost store, not a security boundary in itself; the
/// actual boundary is that the store's key is never persisted anywhere, so leftover ciphertext
/// is unreadable even if this cleanup misses a file (best-effort, same as `burn`'s own
/// ciphertext cleanup - the OS/filesystem may still retain remnants this cannot reach).
fn remove_prefixed_files(prefix: &Path) {
    let (Some(parent), Some(file_prefix)) = (prefix.parent(), prefix.file_name()) else {
        return;
    };
    let Ok(entries) = fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with(&*file_prefix.to_string_lossy())
        {
            let _ = fs::remove_file(entry.path());
        }
    }
}

/// Long-term secret state that only exists between a successful unlock and the next lock.
/// Dropping this struct drops the SQLCipher connection and zeroes the vault master key. Both
/// fields are read only by narrowly-scoped code that needs exactly them: `key` by
/// [`messaging_key`] (to derive the messaging database subkey - never the raw master key
/// itself) and its own `Drop`; `vault` by [`VaultEventSink`] (behind `simplex-native`, to
/// persist delivered `ChatEvent`s) and its own `Drop`. Nothing else in this binary reaches into
/// either. Both fields go unused when `simplex-native` is off (that build's only reader,
/// `messaging_key`, is itself feature-gated), hence the blanket allow.
#[cfg_attr(not(feature = "simplex-native"), allow(dead_code))]
struct UnlockedVault {
    key: VaultKey,
    vault: Vault,
}

/// Ghost Session's runtime-only identity material (Phase 7). Deliberately reuses
/// `secure_crypto::VaultKey` rather than a bespoke type: the security properties Ghost needs -
/// a random 256-bit key, memory-locked best-effort, zeroed on drop - are exactly what
/// `VaultKey` already provides, and it was never actually specific to wrapping a persistent
/// vault; it is just "a locked, zeroizing 256-bit key" that happens to be named for its first
/// use. Forking a near-identical type here to get a different name would be exactly the
/// decorative duplication the project's engineering rules rule out.
///
/// There is nothing else in this struct, and that absence is the point: Ghost has no envelope
/// file, no persistent database, and (unlike `UnlockedVault`) no vault this crate's own storage
/// layer ever writes to. This key exists only in this `Mutex`, for as long as `end_ghost`/
/// identity burn has not yet cleared it. If `simplex-native` messaging is started from a Ghost
/// session it does still create an on-disk SimpleX store (`VaultPaths::ghost_messaging_prefix`),
/// since SimpleX requires a filesystem-backed database; that store's key is derived from this
/// one and is equally never persisted, and the store itself is deleted best-effort at Ghost end
/// and at every process restart (`remove_prefixed_files`). See this phase's Ghost checklist in
/// `docs/security-remediation-plan.md` for why that is "ephemeral", not "none".
///
/// `key` is held only for its `Drop` behaviour and is never read directly - the same pattern as
/// `UnlockedVault` above, for the same reason: nothing in this binary reaches into Ghost's key
/// material except through that `Drop` implementation.
#[allow(dead_code)]
struct GhostSession {
    key: VaultKey,
}

pub(crate) struct AppRuntime {
    lifecycle: Mutex<AppLifecycle>,
    paths: VaultPaths,
    /// Shared (not cloned) with the messaging event sink while messaging is running, so a
    /// delivered `ChatEvent` can be persisted through the same handle `lock`/`unlock` use -
    /// there is exactly one `Option<UnlockedVault>` in the process, never a second copy that
    /// could drift out of sync with it.
    unlocked: Arc<Mutex<Option<UnlockedVault>>>,
    /// Managed Tor transport. Constructing it never performs network I/O (it only builds
    /// config and directory paths); bootstrapping is a separate, explicit step triggered by
    /// the `start_tor` command, not something onboarding/unlock does implicitly. There is no
    /// messaging layer yet to decide *when* Tor should be required, so this deliberately does
    /// not interlock with vault lock/unlock - see `docs/implementation-plan.md` Phase 2.
    ///
    /// Behind a mutex because `Stopped` is terminal for a `TorTransport` (R2 relies on that: a
    /// late bootstrap can never revive a stopped client), while lock/unlock and Burn Identity
    /// with a replacement must be able to bring Tor back. [`Self::startable_transport`] swaps a
    /// stopped instance for a fresh one; nothing ever restarts a stopped instance. Never held
    /// across an `.await` - callers clone the `Arc` out via [`Self::transport`].
    transport: Mutex<Arc<TorTransport>>,
    #[cfg_attr(not(feature = "simplex-native"), allow(dead_code))]
    tor_state_dir: PathBuf,
    #[cfg_attr(not(feature = "simplex-native"), allow(dead_code))]
    tor_cache_dir: PathBuf,
    /// The active Ghost session's ephemeral identity, if any - see [`GhostSession`]. Never
    /// read or written by any code path that also touches `paths`/`unlocked`; that separation
    /// is what makes "normal database remains unchanged by Ghost conversations" true by
    /// construction rather than by a runtime check that could be forgotten somewhere.
    ghost: Mutex<Option<GhostSession>>,
    #[cfg(feature = "simplex-native")]
    messaging: tokio::sync::Mutex<Option<MessagingRuntime>>,
}

impl AppRuntime {
    pub(crate) fn new(
        paths: VaultPaths,
        tor_state_dir: PathBuf,
        tor_cache_dir: PathBuf,
    ) -> Result<Self, String> {
        let transport = TorTransport::new(&tor_state_dir, &tor_cache_dir)
            .map_err(|error| format!("failed to configure Tor transport: {error}"))?;

        // Ghost Session never survives a restart (see `start_ghost_impl`'s doc comment) - a
        // fresh `AppRuntime` always starts with `ghost: None`, regardless of the burn/vault
        // branches below. Any ghost-messaging store files found here are therefore always
        // orphaned from a session that ended without a clean `end_ghost`, e.g. a crash. Best
        // effort, matching this phase's Ghost checklist: cleanup ("delete ciphertext best-effort
        // on Ghost end/restart") does not claim the OS/filesystem cannot retain remnants.
        remove_prefixed_files(&paths.ghost_messaging_prefix);

        // An interrupted Burn Identity takes precedence over every other startup path. This is
        // checked *before* the vault-exists branch below, because the dangerous case is exactly
        // the one where both are true: a burn that crashed before deleting the envelope leaves a
        // perfectly openable vault on disk, and without this the application would come back
        // offering the normal unlock prompt for an identity the user had already ordered
        // destroyed. Resuming here is forward-only - the recovered stage is never lowered - so a
        // burn interrupted at any point still reaches `Destroyed`.
        if let Some(stage) = destruction_journal::read_stage(&paths.journal) {
            let runtime = Self {
                lifecycle: Mutex::new(AppLifecycle::resuming_destruction(stage)),
                paths,
                unlocked: Arc::new(Mutex::new(None)),
                transport: Mutex::new(Arc::new(transport)),
                tor_state_dir,
                tor_cache_dir,
                ghost: Mutex::new(None),
                #[cfg(feature = "simplex-native")]
                messaging: tokio::sync::Mutex::new(None),
            };
            runtime.resume_interrupted_identity_burn();
            return Ok(runtime);
        }

        let mut lifecycle = AppLifecycle::new(AppState::Starting);
        let startup_event = if paths.vault_exists() {
            AppEvent::ExistingVault
        } else {
            AppEvent::NeedsOnboarding
        };
        lifecycle
            .apply(startup_event)
            .expect("Starting always accepts ExistingVault/NeedsOnboarding");

        // Restart-time cleanup: if there is no envelope, any database/attempts file present is
        // orphaned - either a previous Burn Identity completed the security-critical envelope
        // deletion but crashed before finishing best-effort cleanup, or cleanup itself failed.
        // Either way the database is already permanently unreadable (its key can only ever come
        // from the now-gone envelope), so removing it here is pure disk hygiene, not a security
        // boundary - this mirrors Phase 6's "restart only resumes cleanup" requirement without
        // needing its own tombstone/stage machinery, since there is nothing left to protect by
        // the time this runs.
        if !paths.vault_exists() {
            let _ = fs::remove_file(&paths.database);
            let _ = fs::remove_file(&paths.attempts);
        }

        Ok(Self {
            lifecycle: Mutex::new(lifecycle),
            paths,
            unlocked: Arc::new(Mutex::new(None)),
            transport: Mutex::new(Arc::new(transport)),
            tor_state_dir,
            tor_cache_dir,
            ghost: Mutex::new(None),
            #[cfg(feature = "simplex-native")]
            messaging: tokio::sync::Mutex::new(None),
        })
    }

    /// The current Tor transport.
    fn transport(&self) -> Arc<TorTransport> {
        Arc::clone(
            &self
                .transport
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// The current transport, replaced first by a fresh, never-started one if it has been
    /// stopped (e.g. by a previous lock). Constructing a transport performs no network I/O.
    #[cfg_attr(not(feature = "simplex-native"), allow(dead_code))]
    fn startable_transport(&self) -> Result<Arc<TorTransport>, String> {
        let mut slot = self
            .transport
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot.state() == TransportState::Stopped {
            let fresh = TorTransport::new(&self.tor_state_dir, &self.tor_cache_dir)
                .map_err(|error| format!("failed to configure Tor transport: {error}"))?;
            *slot = Arc::new(fresh);
        }
        Ok(Arc::clone(&slot))
    }

    /// Drive a Burn Identity that a previous run started but did not finish through to
    /// `Destroyed`, from the stage recovered off disk.
    ///
    /// Deliberately infallible from the caller's perspective: this runs during application
    /// construction, and refusing to start because cleanup hit an I/O error would leave the user
    /// with an application that cannot launch *and* an identity still mid-destruction. Every
    /// stage's work is best-effort and idempotent, so anything that does not succeed now is
    /// simply retried on the next launch - the journal is only cleared once the sequence
    /// genuinely reaches its terminal stage.
    fn resume_interrupted_identity_burn(&self) {
        let Ok(mut lifecycle) = self.lifecycle.lock() else {
            return;
        };

        if lifecycle.state() == AppState::Destroyed {
            // The previous run reached the terminal stage but was killed before it could clear
            // its own journal. The cleanup pass is re-run anyway - it is idempotent, and this
            // costs one pair of `remove_file` calls against files that are almost certainly
            // already gone - then the stale marker is removed so the data directory stops
            // advertising that an identity was burned here.
            perform_destruction_step(DestructionEvent::DataCleanupFinished, self);
            destruction_journal::clear(&self.paths.journal);
            let _ = enter_fresh_provisioning(&mut lifecycle);
            return;
        }

        if destroy_identity_locked(&mut lifecycle, self).is_ok() {
            let _ = enter_fresh_provisioning(&mut lifecycle);
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct AppStatus {
    state: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct TorStatus {
    state: &'static str,
    /// `0.0`-`1.0` bootstrap progress once a bootstrap attempt has been made; `null` before
    /// the first attempt. Purely informational - nothing in the application uses this to
    /// decide whether a connection may be attempted.
    bootstrap_fraction: Option<f32>,
}

fn tor_status_for(transport: &TorTransport) -> TorStatus {
    TorStatus {
        state: match transport.state() {
            TransportState::NotStarted => "not_started",
            TransportState::Bootstrapping => "bootstrapping",
            TransportState::Ready => "ready",
            TransportState::Failed => "failed",
            TransportState::Stopped => "stopped",
        },
        bootstrap_fraction: transport.bootstrap_fraction(),
    }
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
/// existing one, and durably: the temp file is fsynced before the rename and the directory after
/// it (`docs/security-remediation-plan.md` Phase R1). The vault key envelope is written through
/// here, and an envelope that is atomically renamed but lost on power failure is an identity
/// that silently disappears.
fn write_file_atomically(path: &Path, bytes: &[u8]) -> io::Result<()> {
    destruction_journal::write_durably(path, bytes)
}

pub(crate) fn app_status_impl(runtime: &AppRuntime) -> Result<AppStatus, String> {
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
pub(crate) fn complete_onboarding_impl(
    passphrase: String,
    runtime: &AppRuntime,
) -> Result<AppStatus, String> {
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

    provision_new_vault(&passphrase, runtime)?;

    lifecycle
        .apply(AppEvent::OnboardingComplete)
        .map_err(|error| error.to_string())?;

    Ok(status_for(lifecycle.state()))
}

/// Create a brand-new vault on disk: a freshly generated random vault master key, sealed under
/// `passphrase` into the envelope, plus the (empty) encrypted database.
///
/// Shared by first-run onboarding and by the replacement identity a burn can leave in place.
/// Both are the same operation - a new random key that has never existed before - which is
/// exactly why it is safe to run straight after a destruction: nothing about the destroyed
/// identity is reused or recoverable here, and this cannot resurrect it.
///
/// Refuses to run if an envelope is already present, so it can never silently overwrite a live
/// vault's key and strand its database. On any failure after the envelope is written, the
/// envelope is removed again so a half-finished attempt is not mistaken for an existing vault.
fn provision_new_vault(passphrase: &Zeroizing<String>, runtime: &AppRuntime) -> Result<(), String> {
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

    // Defensive: a leftover attempts file from a previously destroyed identity must not carry
    // a stale count into this brand-new vault. Normal Burn Identity cleanup already removes
    // this file itself; this guards against that best-effort removal having failed.
    let _ = fs::remove_file(&runtime.paths.attempts);

    Ok(())
}

/// Perform the real-world work of one destruction stage. Every arm must be idempotent: the
/// crash-recovery design in [`destruction_journal`] can legitimately re-run a step whose work
/// had already completed before the process died, and can equally re-run one whose journal entry
/// was written moments before the crash prevented it running at all.
fn perform_destruction_step(event: DestructionEvent, runtime: &AppRuntime) {
    match event {
        // UiSealed: this backend function has no UI surface of its own to blank. By the time
        // this runs, the decision to destroy is already final - there is no further passphrase
        // attempt to guard against - so this stage is a pure bookkeeping marker here.
        DestructionEvent::UiSealed => {}

        // NetworkStopped: stop the managed Tor transport before touching key material, matching
        // `secure_transport::TorTransport::stop`'s own shutdown-sequencing contract (terminal
        // and synchronous from the caller's perspective - no new connection can start once it
        // returns). Best-effort: a transport that is already stopped, or that fails to stop
        // cleanly, must not block identity destruction.
        DestructionEvent::NetworkStopped => {
            let transport = runtime.transport();
            if transport.state() != TransportState::Stopped {
                let _ = transport.stop();
            }
        }

        // RuntimeSecretsRevoked: drop any open vault handle, and any active Ghost session key.
        // `UnlockedVault`/`GhostSession`'s own `Drop` implementations close the SQLCipher
        // connection and zero their keys respectively - there is no separate "zero the key"
        // step to write here. A burn reached from `AppState::Ghost` is exactly the case that
        // needs the second of these; burning from `Locked`/`Unlocked` finds `ghost` already
        // `None` and this is a no-op.
        DestructionEvent::RuntimeSecretsRevoked => {
            if let Ok(mut unlocked) = runtime.unlocked.lock() {
                *unlocked = None;
            }
            if let Ok(mut ghost) = runtime.ghost.lock() {
                *ghost = None;
            }
        }

        // PersistentKeyAccessDestroyed: the critical boundary. Once the wrapped
        // vault-master-key envelope is gone, the encrypted database is permanently unreadable.
        // The vault master key is randomly generated (not derived from the passphrase), the
        // passphrase only ever wraps it via Argon2id inside this one envelope file, and Argon2id
        // cannot be run backwards - so after this step no passphrase, however correct, can
        // recover it. Every later stage is disk hygiene over ciphertext that is already
        // cryptographically dead.
        DestructionEvent::PersistentKeyAccessDestroyed => {
            shred_file_best_effort(&runtime.paths.envelope);
        }

        // DataCleanupFinished: best-effort removal of what is now cryptographically useless
        // ciphertext and bookkeeping. A failure here does not, and must not, undo the
        // destruction guarantee already established by the previous stage. The database is
        // overwritten before unlinking for the same reason the envelope is - and because
        // overwriting it with random bytes is what lets the space it occupied be reoccupied by
        // something indistinguishable from ciphertext rather than left as recognisable
        // SQLCipher-shaped data.
        DestructionEvent::DataCleanupFinished => {
            shred_file_best_effort(&runtime.paths.database);
            let _ = fs::remove_file(&runtime.paths.attempts);
            // The SimpleX store and attachment objects are keyed from (or by keys stored in) the
            // now-destroyed vault, so they are already unreadable; removing them is the mandatory
            // post-burn cleanup attempt (`docs/self-destruct-semantics.md`), and it also keeps a
            // replacement identity from tripping over the old store at the same prefix.
            remove_prefixed_files(&runtime.paths.messaging_prefix);
            let _ = AttachmentStore::destroy_all(&runtime.paths.attachments);
        }
    }
}

/// After a completed burn, move straight to fresh provisioning (onboarding a brand-new identity)
/// instead of stopping at the terminal `Destroyed` state. `docs/self-destruct-semantics.md`
/// requires Secure to return to a clean, usable state after Burn and, if anything interrupts
/// replacement, to resume *fresh* provisioning - never a dead end that needs a restart, and never
/// the old identity. The destroyed lifecycle is replaced, not reopened: this is exactly what a
/// relaunch over the now-empty data directory produces.
fn enter_fresh_provisioning(lifecycle: &mut AppLifecycle) -> Result<(), String> {
    *lifecycle = AppLifecycle::new(AppState::Starting);
    lifecycle
        .apply(AppEvent::NeedsOnboarding)
        .map_err(|error| error.to_string())
}

/// Start a new Burn Identity: durably arm the journal, then move the lifecycle to `Destroying`,
/// then run the sequence. The order is the security property (Phase R1): if the `Armed` record
/// cannot be persisted, this returns an error with the lifecycle and every file untouched, so a
/// crash can never leave a half-destroyed identity with no record that a burn was ordered.
fn begin_identity_burn(lifecycle: &mut AppLifecycle, runtime: &AppRuntime) -> Result<(), String> {
    destruction_journal::record_stage(&runtime.paths.journal, DestructionStage::Armed).map_err(
        |error| {
            format!("could not durably arm the burn journal ({error}) - nothing has been destroyed")
        },
    )?;
    if let Err(error) = lifecycle.apply(AppEvent::BeginIdentityBurn) {
        // Nothing was destroyed and the lifecycle refused the burn, so the marker just written
        // must not force one on the next launch.
        destruction_journal::clear(&runtime.paths.journal);
        return Err(error.to_string());
    }
    destroy_identity_locked(lifecycle, runtime)
}

/// Drive a Burn Identity (Phase 6) from wherever `lifecycle` currently stands through to the
/// terminal `Destroyed` state, recording progress durably at every step.
///
/// The caller must already hold `runtime.lifecycle` locked with its state at
/// `AppState::Destroying` - either because it just applied `AppEvent::BeginIdentityBurn`, or
/// because it reconstructed the lifecycle from a recovered journal via
/// `AppLifecycle::resuming_destruction`. This function does not itself decide to destroy
/// anything; it only executes a decision already made.
///
/// Ordering is the whole point, and only one direction is safe. The journal is *armed* before any
/// work begins - that file's existence is what makes the burn survive a crash at all - but each
/// individual stage is recorded only **after** its work has actually run. A crash in the gap
/// therefore leaves the journal *understating* progress, so recovery re-runs the one step that
/// was in flight; since every step is idempotent (stopping an already-stopped transport, dropping
/// an already-dropped handle, deleting an already-deleted file) that re-run is a no-op. Recording
/// a stage before its work would produce the opposite error - a journal claiming a step happened
/// when the crash prevented it - and recovery would skip it. For
/// `PersistentKeyAccessDestroyed`, "skip it" means the vault key envelope survives a burn.
fn destroy_identity_locked(
    lifecycle: &mut AppLifecycle,
    runtime: &AppRuntime,
) -> Result<(), String> {
    // Arm the journal before any work at all. Monotonic, so on a resumed burn this is a no-op
    // rather than a rewind of the recovered stage. Callers starting a new burn arm it themselves
    // *before* moving the lifecycle to `Destroying` (see [`begin_identity_burn`]); this repeat is
    // the guarantee for any other path into this function.
    destruction_journal::record_stage(&runtime.paths.journal, DestructionStage::Armed)
        .map_err(|error| format!("could not durably arm the burn journal: {error}"))?;

    while let Some(stage) = lifecycle.destruction_stage() {
        let Some(event) = stage.advancing_event() else {
            break; // DestructionStage::Complete - the sequence is finished.
        };

        // Act, then journal. See the ordering note above.
        perform_destruction_step(event, runtime);

        lifecycle
            .apply_destruction(event)
            .map_err(|error| error.to_string())?;

        // A failed record aborts the live sequence. The journal still names the earlier stage,
        // so the next launch re-runs this (idempotent) step and continues forward - continuing
        // now instead would let later, irreversible steps run with a journal that understates
        // them by more than one step.
        if let Some(reached) = lifecycle.destruction_stage() {
            destruction_journal::record_stage(&runtime.paths.journal, reached).map_err(
                |error| {
                    format!(
                        "burn paused: could not durably record progress ({error}); it will resume \
                     on the next launch"
                    )
                },
            )?;
        }
    }

    // Terminal. Remove the journal so the data directory carries no lasting record that an
    // identity was ever created here, let alone destroyed - engineering rule 8, and the whole
    // point of "as if it never existed".
    destruction_journal::clear(&runtime.paths.journal);

    Ok(())
}

/// Delete a file after best-effort overwriting of its contents in place with random bytes.
///
/// Random rather than zeros, deliberately. A zero-filled region is conspicuous - it advertises
/// that something was deliberately erased at that offset. Random bytes are indistinguishable
/// from the encrypted content that legitimately occupies these files, so the overwrite is itself
/// the cover: what remains looks like ordinary ciphertext rather than like a wiped hole.
///
/// **What this does and does not buy, stated honestly.** Overwriting raises the bar against
/// trivial undelete and file-carving of unlinked data. It does *not* guarantee the previous
/// bytes are unrecoverable, and nothing running in userspace can: copy-on-write and journalling
/// filesystems (btrfs, ZFS, ext4 with `data=journal`) may retain the old extent, SSD
/// wear-levelling and over-provisioning mean the flash translation layer may never reuse the
/// physical page that held it, and snapshots or backups are entirely outside this process's
/// reach. The actual destruction guarantee here is cryptographic - the key material is gone from
/// the only place the application ever wrote it - and this overwrite is defence in depth on top
/// of that, not a substitute for it. The project's own stated position already says Secure does
/// not promise forensic invisibility; this does not change that.
fn shred_file_best_effort(path: &Path) {
    if let Ok(metadata) = fs::metadata(path)
        && metadata.is_file()
        && let Ok(file) = fs::OpenOptions::new().write(true).open(path)
    {
        let mut cover = [0_u8; 4096];
        let mut remaining = metadata.len();
        while remaining > 0 {
            // Fresh randomness per chunk: a single repeated block would be as recognisable a
            // pattern as a run of zeros, which is the thing this is trying not to leave behind.
            OsRng.fill_bytes(&mut cover);
            let chunk = remaining.min(cover.len() as u64) as usize;
            if io::Write::write_all(&mut &file, &cover[..chunk]).is_err() {
                break;
            }
            remaining -= chunk as u64;
        }
        // Force the overwrite to the device before unlinking: an overwrite still sitting in the
        // page cache when the file is removed may never be written out at all, which would make
        // this step pure theatre.
        let _ = file.sync_all();
    }

    let _ = fs::remove_file(path);
    let _ = destruction_journal::sync_parent_dir(path);
}

/// Open an existing vault: read the key envelope, unwrap the vault master key with the given
/// passphrase, and open the encrypted database with the derived database subkey. The vault
/// master key and the open database handle live only in `runtime.unlocked` for as long as the
/// application remains unlocked; they are never returned to the WebView.
pub(crate) fn unlock_application_impl(
    passphrase: String,
    runtime: &AppRuntime,
) -> Result<AppStatus, String> {
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

    // Only a wrong *passphrase* against an otherwise-valid envelope counts toward the
    // wipe-on-N-attempts failsafe below - a missing/corrupt envelope (already handled above)
    // is a different failure class entirely and must not let an attacker force a wipe by
    // damaging the envelope without ever guessing the passphrase.
    let vault_key = match envelope.open(passphrase.as_bytes()) {
        Ok(key) => key,
        Err(_) => return Err(record_failed_unlock_attempt(&mut lifecycle, runtime)),
    };

    let mut vault = Vault::open_existing(&runtime.paths.database, &vault_key)
        .map_err(|error| format!("failed to open the encrypted vault database: {error}"))?;
    finish_interrupted_destruction(&mut vault, &runtime.paths)?;

    // A correct passphrase resets the counter: only *consecutive* wrong attempts should ever
    // be able to trigger destruction, not a lifetime total across many successful sessions.
    let _ = write_failed_attempts(&runtime.paths.attempts, 0);

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

/// Drive any Burn Conversation a previous run left incomplete to `Complete`, then delete the
/// attachment objects whose keys a burn already destroyed (Phase R6). Runs on every unlock,
/// before the vault is handed to anything else.
///
/// Resuming the burn is fail-closed - the unlock is refused if it cannot finish, so a
/// conversation the user ordered destroyed is never shown again. Deleting the already-unreadable
/// ciphertext files is best-effort: a name stays queued until its file is confirmed gone, so it
/// is retried on the next unlock.
fn finish_interrupted_destruction(vault: &mut Vault, paths: &VaultPaths) -> Result<(), String> {
    secure_storage::burn::resume_incomplete_conversation_burns(vault).map_err(|error| {
        format!("could not finish an interrupted conversation burn ({error}) - vault left locked")
    })?;
    cleanup_burned_attachment_objects(vault, paths);
    Ok(())
}

fn cleanup_burned_attachment_objects(vault: &mut Vault, paths: &VaultPaths) {
    let Ok(store) = AttachmentStore::open(&paths.attachments) else {
        return;
    };
    let _ = store.sweep_partials();
    let Ok(pending) = vault.pending_object_deletions() else {
        return;
    };
    for name in pending {
        // An invalid name can only come from a damaged row; it can never address a file, so it
        // is dropped from the queue rather than retried forever.
        let removed = match store.remove_object(&name) {
            Ok(()) | Err(secure_attachments::AttachmentError::InvalidObjectName) => true,
            Err(_) => false,
        };
        if removed {
            let _ = vault.acknowledge_object_deleted(&name);
        }
    }
}

/// Increment the persisted failed-unlock counter and, once it reaches
/// [`MAX_FAILED_UNLOCK_ATTEMPTS`], drive a full Burn Identity before returning. Always returns
/// an error message describing what happened - a wrong passphrase is a failure either way, the
/// only question is whether it was *just* a wrong passphrase or the wipe threshold besides.
///
/// The caller must hold `lifecycle` locked with the application currently `Locked`.
fn record_failed_unlock_attempt(lifecycle: &mut AppLifecycle, runtime: &AppRuntime) -> String {
    let attempts = read_failed_attempts(&runtime.paths.attempts) + 1;
    let _ = write_failed_attempts(&runtime.paths.attempts, attempts);

    if attempts < MAX_FAILED_UNLOCK_ATTEMPTS {
        return format!(
            "incorrect passphrase ({attempts} of {MAX_FAILED_UNLOCK_ATTEMPTS} attempts used - \
             all local data will be permanently destroyed after {MAX_FAILED_UNLOCK_ATTEMPTS} \
             consecutive incorrect attempts)"
        );
    }

    // Threshold reached: this is no longer a normal unlock failure, it is the failsafe firing.
    let begin_result = begin_identity_burn(lifecycle, runtime);

    match begin_result.and_then(|()| enter_fresh_provisioning(lifecycle)) {
        Ok(()) => format!(
            "too many incorrect passphrase attempts ({attempts} of {MAX_FAILED_UNLOCK_ATTEMPTS}) \
             - all local vault data has been permanently destroyed"
        ),
        Err(error) => format!(
            "too many incorrect passphrase attempts, but the destruction failsafe itself \
             failed ({error}) - treat this vault as compromised and do not rely on it"
        ),
    }
}

/// Lock the application: drop the open database handle and zero the vault master key before
/// reporting success, so no runtime secret state outlives the transition back to `Locked`.
pub(crate) fn lock_application_impl(runtime: &AppRuntime) -> Result<AppStatus, String> {
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

/// Enter Ghost Session (Phase 7): a deliberately ephemeral mode with no intentional persistent
/// state. Only valid from `Locked` - not `Unlocked`, so a Ghost session never begins alongside
/// an already-open normal vault handle, and not `Ghost` itself, since a session is either
/// active or it is not.
///
/// The generated [`GhostSession`] key is never written anywhere. There is no envelope file, no
/// database file, no journal - the only place this key exists is `runtime.ghost`, for as long
/// as `end_ghost` or an identity burn has not yet cleared it. A process restart while a Ghost
/// session is active constructs a fresh `AppRuntime` with `ghost: None`, from
/// [`AppRuntime::new`]'s normal startup path (there is no ghost-specific file for it to find) -
/// so "Ghost session restart does not recover previous session state" holds by construction,
/// not by an explicit check.
pub(crate) fn start_ghost_impl(runtime: &AppRuntime) -> Result<AppStatus, String> {
    let mut lifecycle = runtime
        .lifecycle
        .lock()
        .map_err(|_| "application lifecycle lock poisoned".to_owned())?;

    if lifecycle.state() != AppState::Locked {
        return Err(format!(
            "cannot start a Ghost session from {:?}",
            lifecycle.state()
        ));
    }

    let key =
        VaultKey::generate().map_err(|_| "failed to generate Ghost session key".to_owned())?;

    // Clear any ghost-messaging store left behind by a previous session before this one could
    // possibly reuse the same file prefix (see `VaultPaths::ghost_messaging_prefix`'s doc
    // comment) - a fresh session's newly-generated key would not open old ciphertext anyway,
    // but leaving it on disk unreferenced is exactly the residue this phase's Ghost checklist
    // asks not to accumulate.
    #[cfg(feature = "simplex-native")]
    remove_prefixed_files(&runtime.paths.ghost_messaging_prefix);

    lifecycle
        .apply(AppEvent::StartGhost)
        .map_err(|error| error.to_string())?;

    let mut ghost = runtime
        .ghost
        .lock()
        .map_err(|_| "ghost session lock poisoned".to_owned())?;
    *ghost = Some(GhostSession { key });

    Ok(status_for(lifecycle.state()))
}

/// Exit Ghost Session, destroying its ephemeral key. Only valid from `Ghost`. Ends up `Locked`,
/// the same place [`lock_application_impl`] returns to from `Unlocked` - Ghost and normal
/// unlocked access both collapse back to the same "nothing sensitive is open" resting state.
pub(crate) fn end_ghost_impl(runtime: &AppRuntime) -> Result<AppStatus, String> {
    let mut lifecycle = runtime
        .lifecycle
        .lock()
        .map_err(|_| "application lifecycle lock poisoned".to_owned())?;

    if lifecycle.state() != AppState::Ghost {
        return Err(format!(
            "cannot end a Ghost session from {:?}",
            lifecycle.state()
        ));
    }

    lifecycle
        .apply(AppEvent::EndGhost)
        .map_err(|error| error.to_string())?;

    let mut ghost = runtime
        .ghost
        .lock()
        .map_err(|_| "ghost session lock poisoned".to_owned())?;
    // Dropping the previous value here zeroes the Ghost session key (`VaultKey` wraps its
    // bytes in `Zeroizing`), matching `lock_application_impl`'s handling of `unlocked`.
    *ghost = None;
    drop(ghost);

    // Best-effort delete this session's ephemeral SimpleX store, if it ever started one. Must
    // run after the key above is dropped, not before: the key's presence is not required for
    // this, but the file cleanup is the *lower*-priority step of the two (matching burn's own
    // "keys before files" order), and there is no reason to delay zeroing the key on it.
    #[cfg(feature = "simplex-native")]
    remove_prefixed_files(&runtime.paths.ghost_messaging_prefix);

    Ok(status_for(lifecycle.state()))
}

/// Deliberately destroy this installation's identity and all local vault data, on request.
///
/// Until now the *only* path into Burn Identity was the wipe-on-three-wrong-passphrases failsafe
/// in [`record_failed_unlock_attempt`], which meant a user who wanted to destroy their data on
/// purpose had to either deliberately fail their own passphrase three times or delete files by
/// hand - neither of which runs the ordered destruction sequence (stop networking, revoke runtime
/// secrets, destroy key access, then clean up). This is that same sequence, reached on purpose.
///
/// Permitted from `Locked`, `Unlocked` and `Ghost`, matching `AppEvent::BeginIdentityBurn`'s own
/// accepted states: notably it does **not** require the passphrase. Someone who can already
/// operate the running application can destroy its data, and demanding the passphrase first
/// would make destruction unavailable in exactly the circumstances a burn feature exists for -
/// including the case where the user genuinely no longer knows it.
///
/// There is no undo, no confirmation step and no grace period at this layer, by design: the
/// caller (the UI) owns confirming intent before invoking this. Once it returns, the vault key
/// envelope is gone and the encrypted database cannot be decrypted by any passphrase.
///
/// # Replacement identity
///
/// When `replacement_passphrase` is `Some`, a brand-new vault is provisioned in place once
/// destruction has fully completed, and the application ends up `Locked` on that new identity
/// rather than `Destroyed`.
///
/// The replacement shares *nothing* with what it replaces. [`provision_new_vault`] generates a
/// fresh random vault master key; it is not derived from the old one, from the new passphrase,
/// or from anything that survived the burn. Reusing the same file paths is a filesystem detail,
/// not a cryptographic relationship - the new database is keyed by a key that did not exist
/// until after the old one was destroyed, so no amount of access to the new vault reveals
/// anything about the old.
///
/// Two things this ordering deliberately guarantees:
///
/// - **Provisioning happens strictly after the destruction journal is cleared**, never as a
///   destruction stage. If it ran inside the sequence, a crash between provisioning and clearing
///   the journal would make the *next* launch resume the burn and destroy the brand-new vault
///   the user had just created. Doing it afterwards means the worst case is a crash that leaves
///   no replacement - recoverable by onboarding normally - rather than one that eats it.
/// - **A failed replacement never resurrects the destroyed identity.** If provisioning fails,
///   the burn still happened and stands; the error says so, and the application stays
///   `Destroyed`.
///
/// # What the replacement is and is not
///
/// It is a real, usable, cryptographically unrelated identity, and the overwrite-before-unlink
/// in [`shred_file_best_effort`] means its files can genuinely land on the space the old ones
/// occupied. It is **not** a deniability mechanism, and must not be described to users as one.
/// A replacement vault is a vault with a recent creation date and no history; an adversary who
/// knows this software has this feature - it is open source - learns nothing from its presence
/// except that Secure is installed. Fabricating a *plausible-looking* history to survive
/// coercion is a materially different and much harder problem, with a well-documented tendency
/// to leave the user worse off than an obviously-empty install would, and nothing here attempts
/// it.
pub(crate) fn burn_identity_impl(
    replacement_passphrase: Option<String>,
    runtime: &AppRuntime,
) -> Result<AppStatus, String> {
    // Validate before destroying anything: a replacement passphrase too short to be accepted
    // must fail here, while the vault still exists, rather than after the burn has already made
    // the failure irreversible.
    let replacement_passphrase = replacement_passphrase.map(Zeroizing::new);
    if let Some(passphrase) = &replacement_passphrase
        && passphrase.len() < MIN_PASSPHRASE_LEN
    {
        return Err(format!(
            "replacement passphrase must be at least {MIN_PASSPHRASE_LEN} characters - \
             nothing has been destroyed"
        ));
    }

    let mut lifecycle = runtime
        .lifecycle
        .lock()
        .map_err(|_| "application lifecycle lock poisoned".to_owned())?;

    match lifecycle.state() {
        // Already terminal: report success rather than an error. A caller asking to destroy
        // something that is already destroyed has got what it asked for - the same idempotency
        // reasoning `lock_application_impl` and `stop_tor_impl` already apply.
        AppState::Destroyed => return Ok(status_for(lifecycle.state())),
        AppState::Locked | AppState::Unlocked | AppState::Ghost => {}
        state => return Err(format!("cannot burn identity from {state:?}")),
    }

    begin_identity_burn(&mut lifecycle, runtime)?;

    // Destruction is complete and the journal is cleared. Only now is it safe to provision a
    // replacement - see this function's docs for why this cannot be a destruction stage.
    match replacement_passphrase {
        Some(passphrase) => {
            debug_assert_eq!(lifecycle.state(), AppState::Destroyed);
            if let Err(error) = provision_new_vault(&passphrase, runtime) {
                // The old identity stays destroyed; resume fresh provisioning rather than leave a
                // dead end (self-destruct-semantics.md invariant 9).
                enter_fresh_provisioning(&mut lifecycle)?;
                return Err(format!(
                    "the previous identity was destroyed successfully, but the replacement could \
                     not be created ({error}) - create a new identity to continue"
                ));
            }

            // The destroyed lifecycle is never reopened: the runtime adopts a fresh lifecycle
            // over a data directory that now contains a different vault entirely - precisely
            // what a relaunch would do at this point.
            *lifecycle = AppLifecycle::new(AppState::Starting);
            lifecycle
                .apply(AppEvent::ExistingVault)
                .map_err(|error| error.to_string())?;
        }
        None => enter_fresh_provisioning(&mut lifecycle)?,
    }

    Ok(status_for(lifecycle.state()))
}

pub(crate) fn tor_status_impl(runtime: &AppRuntime) -> TorStatus {
    tor_status_for(&runtime.transport())
}

/// Routes delivered `ChatEvent`s into the same unlocked vault `lock`/`messaging_key` use - see
/// [`AppRuntime::unlocked`]'s doc comment for why this shares the handle instead of opening a
/// second connection. Best-effort: a write failure (e.g. the vault was locked out from under a
/// message still in flight) is dropped rather than panicking a background task, since there is
/// no caller left to report it to by the time this runs.
#[cfg(feature = "simplex-native")]
struct VaultEventSink(Arc<Mutex<Option<UnlockedVault>>>);

#[cfg(feature = "simplex-native")]
impl crate::messaging::ChatEventSink for VaultEventSink {
    fn record(&self, event: secure_messaging::ChatEvent) {
        use secure_messaging::ChatEvent;

        let Ok(mut guard) = self.0.lock() else {
            return;
        };
        let Some(unlocked) = guard.as_mut() else {
            return;
        };
        let vault = &mut unlocked.vault;

        match event {
            ChatEvent::IncomingMessage(message) => {
                let fallback_alias = format!("contact-{}", message.contact_id);
                if let Ok(conversation_id) =
                    vault.conversation_for_protocol_contact(message.contact_id, &fallback_alias)
                {
                    if let Ok(ciphertext) = secure_crypto::seal_messaging_record(
                        &unlocked.key,
                        &conversation_id,
                        "incoming",
                        message.text.as_bytes(),
                    ) {
                        let _ = vault.insert_incoming_message(&conversation_id, &ciphertext);
                    }
                }
            }
            ChatEvent::ContactConnected(contact) => {
                let _ = vault
                    .conversation_for_protocol_contact(contact.contact_id, &contact.display_name);
            }
            // Peer-initiated disconnects, sent-message delivery-status updates, and events this
            // crate does not yet parse have no persistence action defined for them yet - see
            // `secure_messaging::events`'s own doc comments on `ContactDisconnected` and
            // `MessageDelivery` for why (no vault-side connection-state column, and no stored
            // mapping from a sent message's local id to the protocol's `item_id` to update
            // yet). Routing them is a separate increment, not a silent gap: nothing here claims
            // to persist them.
            ChatEvent::ContactDisconnected(_)
            | ChatEvent::MessageDelivery(_)
            | ChatEvent::Unrecognised(_) => {}
        }
    }
}

/// Ghost Session's messaging sink: deliberately drops every delivered `ChatEvent` rather than
/// routing it anywhere, including the normal vault [`VaultEventSink`] writes to. Global
/// constraint (this phase's plan): "Ghost Session never intentionally persists recoverable
/// identity/message state." The SimpleX native store under `ghost_messaging_prefix` still holds
/// the session's live message state for its own operation while the session runs (SimpleX
/// requires a filesystem-backed database) and is deleted best-effort at Ghost end/restart - this
/// sink only governs whether *this crate's own storage layer* also gets a copy, and the answer
/// is never.
#[cfg(feature = "simplex-native")]
struct GhostEventSink;

#[cfg(feature = "simplex-native")]
impl crate::messaging::ChatEventSink for GhostEventSink {
    fn record(&self, _event: secure_messaging::ChatEvent) {}
}

/// Lower-hex encode key material into one exact-capacity, zeroizing buffer. Formatting each byte
/// through `format!` (as an earlier version did) leaves short-lived un-wiped copies of the key on
/// the heap, and a growing `String` can reallocate and leave another.
#[cfg(any(test, feature = "simplex-native"))]
fn hex_key(key: &[u8]) -> Zeroizing<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = Zeroizing::new(String::with_capacity(key.len() * 2));
    for byte in key {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

#[cfg(feature = "simplex-native")]
fn messaging_key(runtime: &AppRuntime) -> Result<Zeroizing<String>, String> {
    let unlocked = runtime
        .unlocked
        .lock()
        .map_err(|_| "vault handle lock poisoned".to_owned())?;
    let vault = unlocked
        .as_ref()
        .ok_or_else(|| "application is not unlocked".to_owned())?;
    let key = vault
        .key
        .derive_subkey(secure_crypto::SubkeyPurpose::MessagingDatabaseV1)
        .map_err(|_| "failed to derive messaging database key".to_owned())?;
    Ok(hex_key(key.as_slice()))
}

/// Same derivation as [`messaging_key`], off the Ghost session's own random key instead of the
/// normal vault's - a completely unrelated subkey (HKDF domain separation is per root key, not
/// just per purpose), never persisted, matching [`GhostSession`]'s own guarantees.
#[cfg(feature = "simplex-native")]
fn ghost_messaging_key(runtime: &AppRuntime) -> Result<Zeroizing<String>, String> {
    let ghost = runtime
        .ghost
        .lock()
        .map_err(|_| "ghost session lock poisoned".to_owned())?;
    let session = ghost
        .as_ref()
        .ok_or_else(|| "no active Ghost session".to_owned())?;
    let key = session
        .key
        .derive_subkey(secure_crypto::SubkeyPurpose::MessagingDatabaseV1)
        .map_err(|_| "failed to derive Ghost messaging database key".to_owned())?;
    Ok(hex_key(key.as_slice()))
}

/// Which lifecycle state `start_messaging_impl` was called from - determines which vault (if
/// any), which SimpleX store, and which [`crate::messaging::ChatEventSink`] the session uses.
/// Messaging is valid from exactly these two states; everything else is refused.
#[cfg(feature = "simplex-native")]
enum MessagingContext {
    Unlocked,
    Ghost,
}

#[cfg(feature = "simplex-native")]
fn messaging_context(runtime: &AppRuntime) -> Result<MessagingContext, String> {
    let lifecycle = runtime
        .lifecycle
        .lock()
        .map_err(|_| "application lifecycle lock poisoned".to_owned())?;
    match lifecycle.state() {
        AppState::Unlocked => Ok(MessagingContext::Unlocked),
        AppState::Ghost => Ok(MessagingContext::Ghost),
        other => Err(format!("cannot start messaging from {other:?}")),
    }
}

#[cfg(feature = "simplex-native")]
pub(crate) async fn start_messaging_impl(runtime: &AppRuntime) -> Result<MessagingStatus, String> {
    let context = messaging_context(runtime)?;

    let transport = runtime.transport();
    if transport.state() != TransportState::Ready {
        return Err("Tor must be ready before messaging can start".to_owned());
    }
    if runtime.messaging.lock().await.is_some() {
        return Ok(MessagingStatus { state: "ready" });
    }

    let proxy = transport
        .start_socks_proxy()
        .await
        .map_err(|error| error.to_string())?;

    let (db_file_prefix, key, sink): (
        PathBuf,
        Zeroizing<String>,
        Arc<dyn crate::messaging::ChatEventSink>,
    ) = match context {
        MessagingContext::Unlocked => (
            runtime.paths.messaging_prefix.clone(),
            messaging_key(runtime)?,
            Arc::new(VaultEventSink(Arc::clone(&runtime.unlocked))),
        ),
        // Never `runtime.unlocked`, never `runtime.paths.messaging_prefix` - see this
        // phase's Ghost checklist: Ghost must never open the normal vault or reuse its
        // SimpleX database.
        MessagingContext::Ghost => (
            runtime.paths.ghost_messaging_prefix.clone(),
            ghost_messaging_key(runtime)?,
            Arc::new(GhostEventSink),
        ),
    };
    let started = MessagingRuntime::start(proxy, db_file_prefix, key, sink)
        .await
        .map_err(|MessagingStartError { proxy, error }| {
            // The proxy is intentionally returned by MessagingRuntime so this failure path does
            // not leak a listening SOCKS socket. Shutdown is awaited before the error escapes.
            (proxy, error.to_string())
        });
    let messaging = match started {
        Ok(messaging) => messaging,
        Err((proxy, error)) => {
            proxy.shutdown().await;
            return Err(error);
        }
    };

    let mut slot = runtime.messaging.lock().await;
    if slot.is_some() {
        drop(slot);
        messaging.stop().await;
    } else {
        *slot = Some(messaging);
    }
    Ok(MessagingStatus { state: "ready" })
}

#[cfg(feature = "simplex-native")]
pub(crate) async fn unlock_application_with_messaging(
    passphrase: String,
    runtime: &AppRuntime,
) -> Result<AppStatus, String> {
    unlock_application_impl(passphrase, runtime)?;

    // A previous lock stopped the old transport for good; bring up a fresh one rather than
    // failing every unlock after the first until the application is restarted.
    let transport = match runtime.startable_transport() {
        Ok(transport) => transport,
        Err(error) => {
            let _ = lock_application_impl(runtime);
            return Err(error);
        }
    };
    if matches!(
        transport.state(),
        TransportState::NotStarted | TransportState::Failed
    ) && let Err(error) = start_tor_impl(runtime).await
    {
        let _ = lock_application_impl(runtime);
        return Err(format!("unlocked vault but could not start Tor: {error}"));
    }

    if let Err(error) = start_messaging_impl(runtime).await {
        stop_messaging_impl(runtime).await;
        let _ = lock_application_impl(runtime);
        return Err(format!(
            "unlocked vault but messaging startup failed: {error}"
        ));
    }

    Ok(status_for(AppState::Unlocked))
}

#[cfg(feature = "simplex-native")]
pub(crate) fn messaging_status_impl(runtime: &AppRuntime) -> MessagingStatus {
    let ready = runtime
        .messaging
        .try_lock()
        .map(|messaging| messaging.is_some())
        .unwrap_or(false);
    MessagingStatus {
        state: if ready { "ready" } else { "unavailable" },
    }
}

#[cfg(feature = "simplex-native")]
pub(crate) async fn create_invitation_impl(runtime: &AppRuntime) -> Result<String, String> {
    let messaging = runtime.messaging.lock().await;
    let messaging = messaging
        .as_ref()
        .ok_or_else(|| "messaging is not ready".to_owned())?
        .create_invitation()
        .await
        .map_err(|error| error.to_string())?;
    Ok(messaging)
}

#[cfg(feature = "simplex-native")]
pub(crate) async fn stop_messaging_impl(runtime: &AppRuntime) {
    let messaging = runtime.messaging.lock().await.take();
    if let Some(messaging) = messaging {
        messaging.stop().await;
    }
}

#[cfg(feature = "simplex-native")]
pub(crate) async fn accept_invitation_impl(runtime: &AppRuntime, link: &str) -> Result<(), String> {
    let messaging = runtime.messaging.lock().await;
    let messaging = messaging
        .as_ref()
        .ok_or_else(|| "messaging is not ready".to_owned())?;
    messaging
        .accept_invitation(link)
        .await
        .map_err(|error| error.to_string())
}

#[cfg(feature = "simplex-native")]
pub(crate) async fn send_text_message_impl(
    runtime: &AppRuntime,
    chat_id: i64,
    message: &str,
) -> Result<(), String> {
    {
        let messaging = runtime.messaging.lock().await;
        let messaging = messaging
            .as_ref()
            .ok_or_else(|| "messaging is not ready".to_owned())?;
        messaging
            .send_text_message(chat_id, message)
            .await
            .map_err(|error| error.to_string())?;
    }

    let mut unlocked = runtime
        .unlocked
        .lock()
        .map_err(|_| "vault handle lock poisoned".to_owned())?;
    let unlocked = unlocked
        .as_mut()
        .ok_or_else(|| "message was sent but the vault is no longer unlocked".to_owned())?;
    let fallback_alias = format!("contact-{chat_id}");
    let conversation_id = unlocked
        .vault
        .conversation_for_protocol_contact(chat_id, &fallback_alias)
        .map_err(|error| format!("message was sent but contact mapping failed: {error}"))?;
    let ciphertext = secure_crypto::seal_messaging_record(
        &unlocked.key,
        &conversation_id,
        "outgoing",
        message.as_bytes(),
    )
    .map_err(|error| format!("message was sent but encryption failed: {error}"))?;
    unlocked
        .vault
        .insert_outgoing_message(&conversation_id, &ciphertext)
        .map_err(|error| format!("message was sent but local persistence failed: {error}"))?;
    Ok(())
}

/// Bootstrap the managed Tor transport. Idempotent in the sense that calling it again from
/// `Ready` is simply refused by the underlying lifecycle (`start` only accepts `NotStarted` or
/// `Failed`); calling it again from `Failed` retries, which is the intended retry policy.
pub(crate) async fn start_tor_impl(runtime: &AppRuntime) -> Result<TorStatus, String> {
    runtime
        .transport()
        .start()
        .await
        .map_err(|error| error.to_string())?;
    Ok(tor_status_for(&runtime.transport()))
}

/// Stop the managed Tor transport. Idempotent: stopping an already-`Stopped` transport is a
/// no-op success rather than surfacing the underlying lifecycle's "invalid transition" error,
/// matching `lock_application`'s idempotency for the same reason - a caller asking to stop
/// something that is already stopped is not an error condition.
pub(crate) fn stop_tor_impl(runtime: &AppRuntime) -> Result<TorStatus, String> {
    let transport = runtime.transport();
    if transport.state() != TransportState::Stopped {
        transport.stop().map_err(|error| error.to_string())?;
    }
    Ok(tor_status_for(&runtime.transport()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSPHRASE: &str = "correct horse battery staple";

    fn runtime_in(dir: &std::path::Path) -> AppRuntime {
        AppRuntime::new(
            VaultPaths::new(dir.to_path_buf()),
            dir.join("tor-state"),
            dir.join("tor-cache"),
        )
        .expect("build test runtime")
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
        assert!(error.contains("incorrect passphrase"));
        assert!(error.contains("1 of 3"));

        // Lifecycle must remain Locked, not silently advance to Unlocked, after a failed
        // unlock attempt.
        let status = app_status_impl(&runtime).expect("status");
        assert_eq!(status.state, "locked");
    }

    #[test]
    fn a_correct_unlock_resets_the_failed_attempt_counter() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");

        // Two wrong attempts, then a correct one.
        unlock_application_impl("wrong one".to_owned(), &runtime).expect_err("wrong");
        unlock_application_impl("wrong two".to_owned(), &runtime).expect_err("wrong");
        unlock_application_impl(PASSPHRASE.to_owned(), &runtime).expect("correct unlock succeeds");
        lock_application_impl(&runtime).expect("lock back down for the next attempt");

        // Two more wrong attempts after the reset must not be attempts 3 and 4 of a still-live
        // streak - the counter must have gone back to zero on the successful unlock, so this
        // pair alone must not trigger destruction.
        let error = unlock_application_impl("wrong three".to_owned(), &runtime).expect_err("wrong");
        assert!(error.contains("1 of 3"), "counter must have reset: {error}");
        unlock_application_impl("wrong four".to_owned(), &runtime).expect_err("wrong");

        let status = app_status_impl(&runtime).expect("status");
        assert_eq!(
            status.state, "locked",
            "only 2 consecutive wrong attempts since the reset must not trigger destruction"
        );
        assert!(
            runtime.paths.envelope.exists(),
            "vault must still exist - the wipe threshold was never reached post-reset"
        );
    }

    #[test]
    fn three_consecutive_wrong_attempts_destroys_the_vault() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");
        assert!(runtime.paths.envelope.is_file());
        assert!(runtime.paths.database.is_file());

        unlock_application_impl("wrong one".to_owned(), &runtime).expect_err("wrong 1");
        unlock_application_impl("wrong two".to_owned(), &runtime).expect_err("wrong 2");
        let error = unlock_application_impl("wrong three".to_owned(), &runtime)
            .expect_err("wrong 3 triggers the wipe");
        assert!(error.contains("permanently destroyed"));
        assert!(error.contains("3 of 3"));

        let status = app_status_impl(&runtime).expect("status");
        assert_eq!(status.state, "onboarding");

        assert!(
            !runtime.paths.envelope.exists(),
            "the vault key envelope - the actual security boundary - must be gone"
        );
        assert!(
            !runtime.paths.database.exists(),
            "the encrypted database must be removed by best-effort cleanup"
        );
        assert!(
            !runtime.paths.attempts.exists(),
            "the attempt counter itself must be cleaned up too"
        );

        // Even the correct passphrase must no longer work - there is nothing left to unlock,
        // and the lifecycle itself refuses any further unlock from a non-Locked state.
        let error = unlock_application_impl(PASSPHRASE.to_owned(), &runtime)
            .expect_err("destroyed vault cannot be unlocked with any passphrase");
        assert!(error.contains("cannot unlock from"));
    }

    #[test]
    fn the_failed_attempt_counter_survives_an_application_restart() {
        // The counter must not be bypassable by simply relaunching the application, which is
        // exactly the scenario a real attacker would try first against an in-memory-only
        // counter.
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");

        unlock_application_impl("wrong one".to_owned(), &runtime).expect_err("wrong 1");
        unlock_application_impl("wrong two".to_owned(), &runtime).expect_err("wrong 2");

        // Simulate the application being closed and relaunched against the same data
        // directory: a brand-new AppRuntime, with no in-memory state carried over at all.
        let restarted = runtime_in(dir.path());
        assert!(
            restarted.paths.envelope.exists(),
            "vault must still exist - only 2 attempts have been made so far"
        );

        let error = unlock_application_impl("wrong three".to_owned(), &restarted)
            .expect_err("the 3rd consecutive wrong attempt, even across a restart, must wipe");
        assert!(error.contains("permanently destroyed"));
        assert!(!restarted.paths.envelope.exists());
    }

    #[test]
    fn a_fresh_onboarding_starts_with_a_clean_attempt_counter() {
        // Simulates onboarding reusing a data directory that still has a stale attempts file
        // left over from a previous identity (e.g. best-effort cleanup partially failed after
        // an earlier Burn Identity). The new vault must not inherit that old count.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(ATTEMPTS_FILE_NAME), b"2").expect("seed stale counter");

        let runtime = runtime_in(dir.path());
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");

        let error = unlock_application_impl("wrong one".to_owned(), &runtime).expect_err("wrong");
        assert!(
            error.contains("1 of 3"),
            "stale counter must not have carried over: {error}"
        );
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
        let runtime = runtime_in(dir.path());

        let error = complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime)
            .expect_err("database creation must fail");
        assert!(error.contains("failed to create the encrypted vault database"));
        assert!(
            !runtime.paths.envelope.exists(),
            "the orphaned envelope must be cleaned up after a failed onboarding"
        );
    }

    // ---------------------------------------------------------------------------------------
    // Burn Identity: deliberate trigger, and crash-consistency across the destruction sequence.
    //
    // A real crash cannot be induced from inside a unit test, but what a crash *leaves behind*
    // can be reproduced exactly: a journal recording some stage, plus the on-disk file state
    // that stage implies. Recovery is then driven by constructing a fresh `AppRuntime` against
    // that directory - the same code path a real relaunch takes, with no in-memory state carried
    // over. That is the property that was previously untested and, before the journal existed,
    // untrue.
    // ---------------------------------------------------------------------------------------

    /// Reproduce the on-disk state a crash immediately after `stage` was journalled would leave.
    ///
    /// Because a stage is recorded only once its work has run, a journal naming
    /// `PersistentKeyAccessDestroyed` or later implies the envelope shred already happened; every
    /// earlier stage implies the envelope is still fully intact and openable, which is the harder
    /// case for recovery to get right.
    fn simulate_crash_mid_burn(runtime: &AppRuntime, stage: DestructionStage) {
        if stage.rank() >= DestructionStage::PersistentKeyAccessDestroyed.rank() {
            let _ = fs::remove_file(&runtime.paths.envelope);
        }
        destruction_journal::record_stage(&runtime.paths.journal, stage)
            .expect("record simulated crash stage");
    }

    #[test]
    fn a_burn_interrupted_at_any_stage_resumes_forward_to_destroyed_on_restart() {
        for stage in [
            DestructionStage::Armed,
            DestructionStage::UiSealed,
            DestructionStage::NetworkStopped,
            DestructionStage::RuntimeSecretsRevoked,
            DestructionStage::PersistentKeyAccessDestroyed,
            DestructionStage::Complete,
        ] {
            let dir = tempfile::tempdir().expect("tempdir");
            let runtime = runtime_in(dir.path());
            complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");
            simulate_crash_mid_burn(&runtime, stage);
            drop(runtime);

            // The relaunch.
            let restarted = runtime_in(dir.path());
            let status = app_status_impl(&restarted).expect("status");

            assert_eq!(
                status.state, "onboarding",
                "a burn interrupted at {stage:?} must resume to Destroyed, not offer an unlock"
            );
            assert!(
                !restarted.paths.envelope.exists(),
                "key access must be destroyed after resuming from {stage:?}"
            );
            assert!(
                !restarted.paths.database.exists(),
                "cleanup must complete after resuming from {stage:?}"
            );
            assert!(
                !restarted.paths.attempts.exists(),
                "the attempt counter must be cleaned up after resuming from {stage:?}"
            );
            assert!(
                !restarted.paths.journal.exists(),
                "a completed burn must clear its own journal (resumed from {stage:?})"
            );

            // "old key access never reappears": the original, correct passphrase must not
            // unlock anything, and the lifecycle must refuse the attempt outright.
            let error = unlock_application_impl(PASSPHRASE.to_owned(), &restarted)
                .expect_err("a resumed burn must leave nothing unlockable");
            assert!(error.contains("cannot unlock from"), "{error}");
        }
    }

    #[test]
    fn a_burn_interrupted_before_key_destruction_still_destroys_the_key_on_restart() {
        // The single most important case, isolated for clarity: the crash landed early enough
        // that the vault key envelope is still on disk and still openable with the correct
        // passphrase. Before the destruction journal existed, this restarted as a normal Locked
        // application and the burn simply never happened.
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");
        simulate_crash_mid_burn(&runtime, DestructionStage::NetworkStopped);

        // Prove the vault really was still recoverable at the moment of the crash, so the test
        // below is demonstrating recovery being *taken away*, not an already-dead vault.
        let envelope_bytes = fs::read(&runtime.paths.envelope).expect("envelope still on disk");
        VaultKeyEnvelope::from_bytes(&envelope_bytes)
            .expect("parses")
            .open(PASSPHRASE.as_bytes())
            .expect("the correct passphrase still opens the envelope pre-restart");
        drop(runtime);

        let restarted = runtime_in(dir.path());
        assert_eq!(
            app_status_impl(&restarted).expect("status").state,
            "onboarding"
        );
        assert!(!restarted.paths.envelope.exists());
    }

    #[test]
    fn a_journal_that_understates_progress_re_runs_the_step_harmlessly() {
        // The other side of the ordering rule: a stage is recorded only after its work runs, so
        // a crash in that gap leaves the journal one step behind reality. Recovery must re-run
        // the already-completed step without failing - here, shredding an envelope that is
        // already gone - and still reach the terminal state.
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");

        // Journal says the envelope has not been destroyed yet; the filesystem says it has.
        destruction_journal::record_stage(
            &runtime.paths.journal,
            DestructionStage::RuntimeSecretsRevoked,
        )
        .expect("record");
        fs::remove_file(&runtime.paths.envelope).expect("envelope already destroyed pre-crash");
        drop(runtime);

        let restarted = runtime_in(dir.path());
        assert_eq!(
            app_status_impl(&restarted).expect("status").state,
            "onboarding"
        );
        assert!(!restarted.paths.journal.exists());
        assert!(!restarted.paths.database.exists());
    }

    #[test]
    fn a_damaged_journal_cannot_cancel_a_pending_burn() {
        // Corrupting the journal is the cheapest attack on this design, so it must fail closed:
        // the file's existence is the signal, and unreadable contents only mean "resume from the
        // beginning", never "there was nothing to resume".
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");
        simulate_crash_mid_burn(&runtime, DestructionStage::RuntimeSecretsRevoked);
        fs::write(&runtime.paths.journal, b"\x00\xffnot a journal").expect("damage the journal");
        drop(runtime);

        let restarted = runtime_in(dir.path());
        assert_eq!(
            app_status_impl(&restarted).expect("status").state,
            "onboarding",
            "a damaged journal must still resume the burn"
        );
        assert!(!restarted.paths.envelope.exists());
    }

    #[test]
    fn a_completed_burn_leaves_a_data_directory_that_looks_like_a_fresh_install() {
        // "as if it never existed": after the burn and one more relaunch, nothing in the data
        // directory records that an identity was ever created here - including any tombstone
        // saying one was destroyed. The application offers onboarding, exactly as it would on a
        // machine that had never run it.
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");
        burn_identity_impl(None, &runtime).expect("burn");
        drop(runtime);

        let restarted = runtime_in(dir.path());
        assert_eq!(
            app_status_impl(&restarted).expect("status").state,
            "onboarding"
        );
        for path in [
            &restarted.paths.envelope,
            &restarted.paths.database,
            &restarted.paths.attempts,
            &restarted.paths.journal,
            &restarted.paths.attachments,
        ] {
            assert!(!path.exists(), "{} must not survive a burn", path.display());
        }
    }

    /// The temp-file path `destruction_journal::write_durably` creates before renaming into the
    /// journal. Occupying it with a directory makes every journal *write* fail while leaving
    /// reads (and an already-present journal) untouched.
    fn journal_write_blocker(runtime: &AppRuntime) -> PathBuf {
        let mut name = runtime
            .paths
            .journal
            .file_name()
            .expect("name")
            .to_os_string();
        name.push(".tmp");
        runtime.paths.journal.with_file_name(name)
    }

    #[test]
    fn burn_refuses_to_start_when_journal_cannot_be_armed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");
        fs::create_dir(journal_write_blocker(&runtime)).expect("block journal writes");

        let error = burn_identity_impl(None, &runtime).expect_err("arm failure must abort");
        assert!(error.contains("nothing has been destroyed"), "{error}");

        assert!(
            runtime.paths.envelope.is_file(),
            "envelope must be untouched"
        );
        assert!(
            runtime.paths.database.is_file(),
            "database must be untouched"
        );
        assert!(
            !runtime.paths.journal.exists(),
            "no journal may have been created"
        );
        assert_eq!(app_status_impl(&runtime).expect("status").state, "locked");

        fs::remove_dir(journal_write_blocker(&runtime)).expect("clear fault");
        unlock_application_impl(PASSPHRASE.to_owned(), &runtime)
            .expect("the untouched vault still unlocks with its original passphrase");
    }

    #[test]
    fn failed_stage_journal_write_is_replayed_after_restart() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");
        let blocker = journal_write_blocker(&runtime);
        drop(runtime);

        // Armed normally (the burn was ordered and recorded), then the filesystem starts refusing
        // writes, so the very first per-stage record fails.
        destruction_journal::record_stage(
            &dir.path().join(BURN_JOURNAL_FILE_NAME),
            DestructionStage::Armed,
        )
        .expect("arm");
        fs::create_dir(&blocker).expect("block journal writes");

        let runtime = runtime_in(dir.path());
        {
            let mut lifecycle = runtime.lifecycle.lock().expect("lifecycle");
            let error = destroy_identity_locked(&mut lifecycle, &runtime)
                .expect_err("a failed stage record must abort the live sequence");
            assert!(error.contains("burn paused"), "{error}");
        }
        assert_eq!(
            destruction_journal::read_stage(&runtime.paths.journal),
            Some(DestructionStage::Armed),
            "the journal must still name the earlier stage"
        );
        assert!(
            runtime.paths.envelope.is_file(),
            "aborting before the key-destruction step must not have reached it"
        );
        drop(runtime);

        fs::remove_dir(&blocker).expect("clear fault");
        let restarted = runtime_in(dir.path());
        assert_eq!(
            app_status_impl(&restarted).expect("status").state,
            "onboarding"
        );
        assert!(!restarted.paths.envelope.exists());
        assert!(!restarted.paths.database.exists());
    }

    #[test]
    fn durable_envelope_write_round_trips_after_simulated_restart() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");
        drop(runtime);

        let restarted = runtime_in(dir.path());
        let mut leftover = restarted.paths.envelope.clone().into_os_string();
        leftover.push(".tmp");
        assert!(
            !PathBuf::from(leftover).exists(),
            "no temp file may be left behind"
        );
        unlock_application_impl(PASSPHRASE.to_owned(), &restarted).expect("unlock after restart");
    }

    #[test]
    fn burn_identity_removes_the_simplex_store_and_attachment_objects() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");
        let store = AttachmentStore::open(&runtime.paths.attachments).expect("store");
        store.ingest("x/y", 1, b"z".as_slice()).expect("ingest");
        let chat_db = dir.path().join("simplex_chat.db");
        let agent_db = dir.path().join("simplex_agent.db");
        fs::write(&chat_db, b"ciphertext").expect("seed chat db");
        fs::write(&agent_db, b"ciphertext").expect("seed agent db");

        burn_identity_impl(None, &runtime).expect("burn");

        assert!(
            !runtime.paths.attachments.exists(),
            "attachment objects must be removed"
        );
        assert!(!chat_db.exists(), "SimpleX chat store must be removed");
        assert!(!agent_db.exists(), "SimpleX agent store must be removed");
    }

    #[test]
    fn unlock_deletes_attachment_objects_left_behind_by_an_interrupted_conversation_burn() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");
        unlock_application_impl(PASSPHRASE.to_owned(), &runtime).expect("unlock");

        let store = AttachmentStore::open(&runtime.paths.attachments).expect("store");
        let object = store.ingest("x/y", 1, b"z".as_slice()).expect("ingest");
        {
            let mut unlocked = runtime.unlocked.lock().expect("lock");
            let vault = &mut unlocked.as_mut().expect("unlocked").vault;
            let conversation = vault.insert_conversation("c").expect("conversation");
            let message = vault
                .insert_outgoing_message(&conversation, b"ct")
                .expect("message");
            vault
                .insert_attachment(
                    &message,
                    &object.object_name,
                    "x/y",
                    1,
                    object.key.as_bytes(),
                )
                .expect("attachment");
            // Keys destroyed and rows removed, but the process "dies" before deleting the file.
            secure_storage::burn::burn_conversation(vault, &conversation).expect("burn");
        }
        assert!(store.root().join(&object.object_name).exists());
        lock_application_impl(&runtime).expect("lock");

        unlock_application_impl(PASSPHRASE.to_owned(), &runtime).expect("unlock again");

        assert!(
            !store.root().join(&object.object_name).exists(),
            "ciphertext of a burned attachment must be deleted on the next unlock"
        );
        let unlocked = runtime.unlocked.lock().expect("lock");
        let vault = &unlocked.as_ref().expect("unlocked").vault;
        assert!(
            vault
                .pending_object_deletions()
                .expect("pending")
                .is_empty()
        );
    }

    #[test]
    fn a_stopped_transport_is_replaced_by_a_fresh_one_for_the_next_unlock() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());

        let original = runtime.startable_transport().expect("transport");
        assert!(
            Arc::ptr_eq(&original, &runtime.transport()),
            "a transport that was never stopped must be kept, not replaced"
        );

        // What lock does: the old instance becomes permanently `Stopped`.
        stop_tor_impl(&runtime).expect("stop");
        assert_eq!(original.state(), TransportState::Stopped);

        let fresh = runtime.startable_transport().expect("fresh transport");
        assert!(!Arc::ptr_eq(&original, &fresh));
        assert_eq!(fresh.state(), TransportState::NotStarted);
        assert_eq!(
            original.state(),
            TransportState::Stopped,
            "the stopped instance itself is never revived"
        );
    }

    #[test]
    fn hex_key_matches_lower_hex_and_never_reallocates() {
        let key = [0x00_u8, 0x0f, 0xa5, 0xff];
        let encoded = hex_key(&key);
        assert_eq!(encoded.as_str(), "000fa5ff");
        assert_eq!(
            encoded.capacity(),
            key.len() * 2,
            "exact capacity: no reallocation copies"
        );
    }

    /// `docs/self-destruct-semantics.md` invariant 5, verbatim. Restoring a pre-burn copy of the
    /// application-data directory must not resurrect the burned identity, even with its correct
    /// passphrase. This FAILS today: every secret the identity needs lives in the data directory,
    /// so the copy is sufficient. Making it pass requires device-bound anti-rollback state that is
    /// not stored there (`docs/backup-snapshot-hardening.md`) - a platform primitive (e.g. a TPM
    /// NV monotonic counter) and a reviewed key-combining design that have not been chosen yet.
    /// Kept as an executable release blocker; `docs/release-checklist.md` section 4.
    #[test]
    #[ignore = "RELEASE BLOCKER: device-bound anti-rollback state is not implemented yet"]
    fn restoring_a_pre_burn_copy_cannot_resurrect_the_burned_identity() {
        fn copy_dir(from: &Path, to: &Path) {
            fs::create_dir_all(to).expect("mkdir");
            for entry in fs::read_dir(from).expect("read dir").flatten() {
                let target = to.join(entry.file_name());
                if entry.file_type().expect("type").is_dir() {
                    copy_dir(&entry.path(), &target);
                } else {
                    fs::copy(entry.path(), &target).expect("copy");
                }
            }
        }
        let root = tempfile::tempdir().expect("tempdir");
        let data = root.path().join("data");
        let snapshot = root.path().join("snapshot");
        fs::create_dir(&data).expect("mkdir");

        let runtime = runtime_in(&data);
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("identity A");
        drop(runtime);
        copy_dir(&data, &snapshot);

        let runtime = runtime_in(&data);
        burn_identity_impl(Some(REPLACEMENT_PASSPHRASE.to_owned()), &runtime)
            .expect("burn A, replace with B");
        drop(runtime);

        fs::remove_dir_all(&data).expect("remove current data");
        copy_dir(&snapshot, &data);
        let restored = runtime_in(&data);
        assert!(
            unlock_application_impl(PASSPHRASE.to_owned(), &restored).is_err(),
            "a pre-burn snapshot plus the old passphrase must not recover identity A"
        );
    }

    #[test]
    fn burn_identity_destroys_an_unlocked_vault_on_request() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");
        unlock_application_impl(PASSPHRASE.to_owned(), &runtime).expect("unlock");

        let status = burn_identity_impl(None, &runtime).expect("burn from Unlocked");

        assert_eq!(status.state, "onboarding");
        assert!(!runtime.paths.envelope.exists());
        assert!(!runtime.paths.database.exists());
        // The open vault handle and vault master key must have been dropped, not merely
        // orphaned, by the RuntimeSecretsRevoked stage.
        assert!(
            runtime.unlocked.lock().expect("lock").is_none(),
            "burning must drop the open vault handle and zero the vault master key"
        );
    }

    #[test]
    fn burn_identity_destroys_a_locked_vault_without_needing_the_passphrase() {
        // A burn must not require the passphrase: destruction has to remain available in exactly
        // the situations it exists for, including one where the user no longer knows it.
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");

        let status = burn_identity_impl(None, &runtime).expect("burn from Locked");

        assert_eq!(status.state, "onboarding");
        assert!(!runtime.paths.envelope.exists());
    }

    #[test]
    fn burn_leaves_the_application_ready_for_a_fresh_identity_not_a_dead_end() {
        // self-destruct-semantics.md: after Burn, Secure returns to a clean usable state. With
        // no replacement passphrase supplied, that is fresh provisioning - not a terminal state
        // that needs a restart, and never the old identity.
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");

        let status = burn_identity_impl(None, &runtime).expect("burn");
        assert_eq!(status.state, "onboarding");

        // There is no identity left to burn, so a second request destroys nothing.
        assert!(burn_identity_impl(None, &runtime).is_err());

        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime)
            .expect("a fresh identity can be created in the same session");
        unlock_application_impl(PASSPHRASE.to_owned(), &runtime)
            .expect("the fresh identity unlocks with its own passphrase");
        let unlocked = runtime.unlocked.lock().expect("lock");
        let vault = &unlocked.as_ref().expect("unlocked").vault;
        assert!(
            vault.pending_object_deletions().expect("queue").is_empty(),
            "nothing from the destroyed identity carries over"
        );
    }

    const REPLACEMENT_PASSPHRASE: &str = "an entirely different passphrase";

    #[test]
    fn a_replacement_identity_takes_the_destroyed_one_s_place() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");

        let status = burn_identity_impl(Some(REPLACEMENT_PASSPHRASE.to_owned()), &runtime)
            .expect("burn with replacement");

        // Not `destroyed`: the application is live again on a different identity.
        assert_eq!(status.state, "locked");
        assert!(runtime.paths.envelope.is_file());
        assert!(runtime.paths.database.is_file());
        assert!(
            !runtime.paths.journal.exists(),
            "the replacement must not be left inside a pending burn - a resumed burn would \
             destroy it on the next launch"
        );

        // The replacement is usable with its own passphrase...
        let status =
            unlock_application_impl(REPLACEMENT_PASSPHRASE.to_owned(), &runtime).expect("unlock");
        assert_eq!(status.state, "unlocked");
    }

    #[test]
    fn the_destroyed_identity_s_passphrase_is_worthless_against_the_replacement() {
        // The security claim behind "a whole new lockbox": the replacement is keyed by a freshly
        // generated random vault master key, so it has no cryptographic relationship to what it
        // replaced. The old passphrase must be simply wrong against it - not a partial match, not
        // a fallback, just wrong.
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");

        let old_envelope = fs::read(&runtime.paths.envelope).expect("read the original envelope");

        burn_identity_impl(Some(REPLACEMENT_PASSPHRASE.to_owned()), &runtime).expect("burn");

        let new_envelope = fs::read(&runtime.paths.envelope).expect("read the new envelope");
        assert_ne!(
            old_envelope, new_envelope,
            "the replacement envelope must not be the destroyed one"
        );

        let error = unlock_application_impl(PASSPHRASE.to_owned(), &runtime)
            .expect_err("the destroyed identity's passphrase must not open the replacement");
        assert!(error.contains("incorrect passphrase"), "{error}");
    }

    #[test]
    fn a_replacement_identity_starts_with_no_history_and_a_clean_attempt_counter() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");

        // Burn part-way through a failed-attempt streak, so a counter is definitely on disk.
        unlock_application_impl("wrong one".to_owned(), &runtime).expect_err("wrong");
        assert!(runtime.paths.attempts.exists());

        burn_identity_impl(Some(REPLACEMENT_PASSPHRASE.to_owned()), &runtime).expect("burn");

        // The replacement must not inherit the destroyed identity's strike count - otherwise a
        // burn could hand the new vault a vault that is already one wrong guess from wiping.
        let error = unlock_application_impl("wrong against the replacement".to_owned(), &runtime)
            .expect_err("wrong");
        assert!(error.contains("1 of 3"), "counter must be clean: {error}");
    }

    #[test]
    fn a_rejected_replacement_passphrase_destroys_nothing() {
        // Validation happens before the burn precisely so a typo cannot cost the user their data
        // in an operation that has no undo.
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");

        let error = burn_identity_impl(Some("short".to_owned()), &runtime)
            .expect_err("a too-short replacement passphrase must be rejected");
        assert!(error.contains("nothing has been destroyed"), "{error}");

        assert_eq!(app_status_impl(&runtime).expect("status").state, "locked");
        assert!(runtime.paths.envelope.is_file());
        unlock_application_impl(PASSPHRASE.to_owned(), &runtime)
            .expect("the original vault must still open");
    }

    #[test]
    fn a_replacement_identity_survives_a_restart_as_a_normal_vault() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");
        burn_identity_impl(Some(REPLACEMENT_PASSPHRASE.to_owned()), &runtime).expect("burn");
        drop(runtime);

        // Nothing about the replacement may look like an interrupted burn to the next launch.
        let restarted = runtime_in(dir.path());
        assert_eq!(app_status_impl(&restarted).expect("status").state, "locked");
        unlock_application_impl(REPLACEMENT_PASSPHRASE.to_owned(), &restarted)
            .expect("the replacement opens normally after a restart");
    }

    #[test]
    fn burn_identity_is_refused_before_a_vault_exists() {
        // Nothing to destroy from Onboarding, and `AppEvent::BeginIdentityBurn` does not accept
        // that state - the command must say so rather than pretending to have burned something.
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());

        let error = burn_identity_impl(None, &runtime)
            .expect_err("cannot burn an identity that does not exist");
        assert!(error.contains("cannot burn identity from"), "{error}");
    }

    #[test]
    fn the_envelope_is_overwritten_before_it_is_unlinked() {
        // `shred_file_best_effort`'s overwrite pass is best-effort against the filesystem, but
        // it must at least genuinely happen: this pins that the bytes are replaced and synced
        // before the unlink, rather than the function silently degrading to a plain remove.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secret");
        let secret = b"vault key envelope contents that must not survive";
        fs::write(&path, secret).expect("write");

        // Hard-link a second name to the same inode, so the file's data outlives the unlink of
        // the first name and can actually be inspected after shredding.
        let witness = dir.path().join("witness");
        fs::hard_link(&path, &witness).expect("hard link");

        shred_file_best_effort(&path);

        assert!(!path.exists(), "the shredded path must be unlinked");
        let surviving = fs::read(&witness).expect("the witness link still resolves");
        assert_eq!(
            surviving.len(),
            secret.len(),
            "the overwrite must cover the whole file"
        );
        assert_ne!(
            surviving.as_slice(),
            secret.as_slice(),
            "the file's bytes must have been overwritten in place before unlinking"
        );
        // Random, not zeros: a zero-filled run advertises that something was deliberately
        // erased here, which is precisely the signal the cover pattern exists to avoid.
        assert!(
            surviving.iter().any(|byte| *byte != 0),
            "the overwrite must use random cover bytes, not an obvious zero fill"
        );
    }

    // Real Tor bootstrap requires outbound network access this environment does not have, so
    // start_tor's success path is not exercised here. What is tested is the wiring that does
    // not require a network: constructing the transport, its initial status, and stop's
    // idempotent no-network refusal path.

    #[test]
    fn tor_status_before_any_start_is_not_started_with_no_progress() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());

        let status = tor_status_impl(&runtime);
        assert_eq!(status.state, "not_started");
        assert_eq!(status.bootstrap_fraction, None);
    }

    #[test]
    fn stop_tor_before_start_transitions_to_stopped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());

        let status = stop_tor_impl(&runtime).expect("stop before start");
        assert_eq!(status.state, "stopped");
    }

    #[test]
    fn stop_tor_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());

        stop_tor_impl(&runtime).expect("first stop");
        let status = stop_tor_impl(&runtime).expect("second stop must not error");
        assert_eq!(status.state, "stopped");
    }

    #[tokio::test]
    async fn start_tor_after_stop_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());

        stop_tor_impl(&runtime).expect("stop");
        let error = start_tor_impl(&runtime)
            .await
            .expect_err("cannot restart a stopped transport");
        assert!(error.contains("Stopped"));
    }

    #[test]
    fn ghost_session_starts_from_locked_and_ends_back_to_locked() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");

        let status = start_ghost_impl(&runtime).expect("start ghost");
        assert_eq!(status.state, "ghost");
        assert!(
            runtime.ghost.lock().unwrap().is_some(),
            "an active ghost session must be tracked in memory"
        );

        let status = end_ghost_impl(&runtime).expect("end ghost");
        assert_eq!(status.state, "locked");
        assert!(
            runtime.ghost.lock().unwrap().is_none(),
            "ending the session must clear its key"
        );
    }

    #[test]
    fn ghost_session_is_refused_before_onboarding_completes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());

        let error = start_ghost_impl(&runtime).expect_err("no vault exists yet");
        assert!(error.contains("cannot start a Ghost session from"));
    }

    #[test]
    fn ghost_session_is_refused_while_the_normal_vault_is_unlocked() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");
        unlock_application_impl(PASSPHRASE.to_owned(), &runtime).expect("unlock");

        let error = start_ghost_impl(&runtime)
            .expect_err("must not start a ghost session over an open normal vault");
        assert!(error.contains("cannot start a Ghost session from"));
    }

    #[test]
    fn ending_a_ghost_session_that_was_never_started_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");

        let error = end_ghost_impl(&runtime).expect_err("no ghost session is active");
        assert!(error.contains("cannot end a Ghost session from"));
    }

    #[test]
    fn normal_unlock_and_onboarding_are_refused_while_in_a_ghost_session() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");
        start_ghost_impl(&runtime).expect("start ghost");

        let error = unlock_application_impl(PASSPHRASE.to_owned(), &runtime)
            .expect_err("must not unlock the normal vault from inside a ghost session");
        assert!(error.contains("cannot unlock from"));
        assert!(
            runtime.unlocked.lock().unwrap().is_none(),
            "the normal vault must remain untouched while in a ghost session"
        );
    }

    #[test]
    fn a_restart_during_a_ghost_session_does_not_recover_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");
        start_ghost_impl(&runtime).expect("start ghost");

        // A "restart" is a brand-new AppRuntime over the same on-disk directory. Ghost has no
        // file of its own for the new process to find, so it must come back Locked, never
        // Ghost, regardless of what the crashed process's in-memory state was.
        let restarted = runtime_in(dir.path());
        let status = app_status_impl(&restarted).expect("status");
        assert_eq!(status.state, "locked");
        assert!(restarted.ghost.lock().unwrap().is_none());
    }

    #[test]
    fn burning_identity_from_a_ghost_session_destroys_the_ghost_key_too() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");
        start_ghost_impl(&runtime).expect("start ghost");
        assert!(runtime.ghost.lock().unwrap().is_some());

        let status = burn_identity_impl(None, &runtime).expect("burn from ghost");
        assert_eq!(status.state, "onboarding");
        assert!(
            runtime.ghost.lock().unwrap().is_none(),
            "burning identity must also clear an active ghost session's key"
        );
        assert!(!runtime.paths.envelope.exists());
    }

    #[cfg(feature = "simplex-native")]
    #[test]
    fn ghost_and_normal_messaging_prefixes_are_distinct_paths() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        assert_ne!(
            runtime.paths.messaging_prefix, runtime.paths.ghost_messaging_prefix,
            "a Ghost session must never be able to open the normal SimpleX store"
        );
    }

    #[cfg(feature = "simplex-native")]
    #[test]
    fn messaging_context_matches_lifecycle_state() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());

        // Starting/Onboarding: neither context is valid yet.
        assert!(messaging_context(&runtime).is_err());

        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");
        // Locked: neither context is valid.
        assert!(messaging_context(&runtime).is_err());

        unlock_application_impl(PASSPHRASE.to_owned(), &runtime).expect("unlock");
        assert!(matches!(
            messaging_context(&runtime),
            Ok(MessagingContext::Unlocked)
        ));

        lock_application_impl(&runtime).expect("lock");
        start_ghost_impl(&runtime).expect("start ghost");
        assert!(matches!(
            messaging_context(&runtime),
            Ok(MessagingContext::Ghost)
        ));
    }

    #[cfg(feature = "simplex-native")]
    #[test]
    fn ghost_messaging_key_requires_an_active_ghost_session() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");

        let error = ghost_messaging_key(&runtime).expect_err("no ghost session is active");
        assert!(error.contains("no active Ghost session"));

        start_ghost_impl(&runtime).expect("start ghost");
        ghost_messaging_key(&runtime).expect("derives once a Ghost session is active");
    }

    #[cfg(feature = "simplex-native")]
    #[test]
    fn ghost_and_normal_messaging_keys_never_match() {
        // Same `SubkeyPurpose::MessagingDatabaseV1` derivation, off two independently random
        // root keys (the normal vault's and the Ghost session's) - HKDF domain separation is
        // per root key, so these must never collide even though nothing else distinguishes the
        // derivation call.
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");
        unlock_application_impl(PASSPHRASE.to_owned(), &runtime).expect("unlock");
        let normal_key = messaging_key(&runtime).expect("derive normal messaging key");
        lock_application_impl(&runtime).expect("lock");

        start_ghost_impl(&runtime).expect("start ghost");
        let ghost_key = ghost_messaging_key(&runtime).expect("derive ghost messaging key");

        assert_ne!(*normal_key, *ghost_key);
    }

    #[cfg(feature = "simplex-native")]
    #[test]
    fn ending_a_ghost_session_deletes_its_messaging_store_best_effort() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");
        start_ghost_impl(&runtime).expect("start ghost");

        // Simulate a SimpleX native store having been created at the Ghost prefix (this test
        // does not bootstrap a real Tor/SimpleX stack - `remove_prefixed_files` itself is
        // exercised directly here rather than through a live `start_messaging_impl` call).
        let prefix = &runtime.paths.ghost_messaging_prefix;
        std::fs::write(format!("{}_chat.db", prefix.display()), b"ciphertext")
            .expect("write fake chat db");
        std::fs::write(format!("{}_agent.db", prefix.display()), b"ciphertext")
            .expect("write fake agent db");
        // A file that merely shares the parent directory, not the prefix, must survive.
        let unrelated = prefix.parent().unwrap().join("unrelated.txt");
        std::fs::write(&unrelated, b"keep me").expect("write unrelated file");

        end_ghost_impl(&runtime).expect("end ghost");

        assert!(!std::path::Path::new(&format!("{}_chat.db", prefix.display())).exists());
        assert!(!std::path::Path::new(&format!("{}_agent.db", prefix.display())).exists());
        assert!(unrelated.exists(), "cleanup must not touch unrelated files");
    }

    #[cfg(feature = "simplex-native")]
    #[test]
    fn restarting_after_an_interrupted_ghost_session_cleans_up_its_messaging_store() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");
        start_ghost_impl(&runtime).expect("start ghost");

        let prefix = &runtime.paths.ghost_messaging_prefix;
        std::fs::write(format!("{}_chat.db", prefix.display()), b"ciphertext")
            .expect("write fake chat db left behind by a crash");

        // No `end_ghost` - simulate the process dying mid-session. A fresh `AppRuntime` over
        // the same directory (a restart) must clean the orphaned store up on its own, since
        // Ghost never recovers across a restart and nothing else ever will.
        let restarted = runtime_in(dir.path());
        assert!(!std::path::Path::new(&format!("{}_chat.db", prefix.display())).exists());
        let _ = restarted;
    }

    // R5's "unlock -> Tor -> SOCKS -> messaging-ready happy path" required test and its
    // per-stage-failure siblings all need `runtime.transport` to reach `TransportState::Ready`
    // first (`start_messaging_impl` refuses otherwise, deliberately, before touching anything
    // else) - and that requires a real Tor client actually completing a network bootstrap, the
    // same reason `secure-transport`'s own `tests/live_bootstrap.rs` is `#[ignore]`d. The one
    // stage below that needs no network at all - "Tor not yet Ready" itself - is a plain `#[test]`.

    #[cfg(feature = "simplex-native")]
    #[tokio::test]
    async fn starting_messaging_before_tor_is_ready_fails_with_no_fallback() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");
        unlock_application_impl(PASSPHRASE.to_owned(), &runtime).expect("unlock");

        // A fresh `TorTransport` starts `NotStarted`, never `Ready`, without an explicit
        // `start_tor_impl` call - which this test deliberately never makes.
        let error = start_messaging_impl(&runtime)
            .await
            .expect_err("messaging must refuse to start before Tor is Ready");
        assert!(error.contains("Tor must be ready"));
        assert!(
            runtime.messaging.lock().await.is_none(),
            "a refused start must leave no messaging session behind to fall back to"
        );
    }

    /// Full R5 happy path: onboard, unlock, bootstrap a real Tor client to `Ready`, bring up
    /// messaging behind it, and confirm `messaging_status_impl` reports `"ready"`. Requires
    /// outbound network access to the live Tor network (see this module's own note above) and
    /// `SECURE_SIMPLEX_NATIVE_LIB_DIR` pointing at a `scripts/build-simplex-native.sh` build -
    /// `cargo test --features simplex-native -- --ignored` from an environment with both.
    /// `#[ignore]`d for CI/sandboxes without network, not because it is unverified: it has
    /// actually been run to completion (see this phase's plan doc for what running it here
    /// found and fixed - a link-time symbol collision and a `bootstrap`/`configure_network`
    /// ordering bug, both real, both now fixed).
    #[cfg(feature = "simplex-native")]
    #[tokio::test]
    #[ignore = "requires live Tor network bootstrap; see this test's own doc comment"]
    async fn unlock_tor_socks_messaging_ready_happy_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");
        unlock_application_impl(PASSPHRASE.to_owned(), &runtime).expect("unlock");

        start_tor_impl(&runtime)
            .await
            .expect("Tor client bootstraps against the live network");
        assert_eq!(tor_status_impl(&runtime).state, "ready");

        let status = start_messaging_impl(&runtime)
            .await
            .expect("messaging starts behind a Ready Tor transport");
        assert_eq!(status.state, "ready");
        assert_eq!(messaging_status_impl(&runtime).state, "ready");

        stop_messaging_impl(&runtime).await;
        assert_eq!(messaging_status_impl(&runtime).state, "unavailable");
    }

    /// R5's "restart restores normal encrypted messaging state" required test, for the native
    /// SimpleX store specifically (the genuinely new risk this phase introduced - the vault's
    /// own restart durability is already covered by `full_onboard_lock_unlock_lock_cycle`).
    /// Creates a real invitation (proving a real user exists), locks, simulates a process
    /// restart with a brand-new `AppRuntime` over the same on-disk directory, unlocks again,
    /// re-bootstraps Tor, and confirms messaging comes back `"ready"` *and* can create another
    /// invitation immediately - proving `NativeSimplexAdapter::bootstrap`'s `ShowActiveUser`
    /// path found the same persisted user rather than its `CreateActiveUser` fallback silently
    /// creating a second, distinct one (see `bootstrap`'s own doc comment on why that
    /// distinction matters). Bootstraps Tor twice, so this is the slowest test in this module.
    #[cfg(feature = "simplex-native")]
    #[tokio::test]
    #[ignore = "requires live Tor network bootstrap, twice; see this test's own doc comment"]
    async fn restart_restores_native_messaging_state() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");
        unlock_application_impl(PASSPHRASE.to_owned(), &runtime).expect("unlock");
        start_tor_impl(&runtime).await.expect("tor bootstrap");
        start_messaging_impl(&runtime)
            .await
            .expect("messaging ready");

        let invitation_before = create_invitation_impl(&runtime)
            .await
            .expect("create invitation before restart");
        assert!(!invitation_before.is_empty());

        stop_messaging_impl(&runtime).await;
        let _ = stop_tor_impl(&runtime);
        lock_application_impl(&runtime).expect("lock");

        // A "restart" is a brand-new AppRuntime over the same on-disk directory - the same
        // simulation `full_onboard_lock_unlock_lock_cycle` and the Ghost restart tests use.
        let restarted = runtime_in(dir.path());
        unlock_application_impl(PASSPHRASE.to_owned(), &restarted).expect("unlock after restart");
        start_tor_impl(&restarted)
            .await
            .expect("tor bootstrap after restart");
        start_messaging_impl(&restarted)
            .await
            .expect("messaging ready after restart - reopens the same native store");

        let invitation_after = create_invitation_impl(&restarted)
            .await
            .expect("create invitation after restart - proves the same user persisted");
        assert!(!invitation_after.is_empty());

        stop_messaging_impl(&restarted).await;
    }

    /// The remaining unwritten half of "failure at each startup stage leaves messaging
    /// unavailable with no fallback": a failure *after* Tor is genuinely `Ready` (the
    /// `configure_network`/`bootstrap` ordering bug this phase found and fixed covered the
    /// adapter-level failure mode; this covers `NativeSimplexAdapter::open` itself failing
    /// through the full `start_messaging_impl` stack). Pre-corrupts the native store's chat
    /// database file before `open` ever touches it - a database file cannot be silently
    /// recreated over one that already exists with different content, so `open` must fail
    /// closed rather than falling back to a fresh, unencrypted, or otherwise wrong store.
    #[cfg(feature = "simplex-native")]
    #[tokio::test]
    #[ignore = "requires live Tor network bootstrap; see this test's own doc comment"]
    async fn adapter_open_failure_after_tor_ready_leaves_messaging_unavailable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_in(dir.path());
        complete_onboarding_impl(PASSPHRASE.to_owned(), &runtime).expect("onboarding");
        unlock_application_impl(PASSPHRASE.to_owned(), &runtime).expect("unlock");
        start_tor_impl(&runtime).await.expect("tor bootstrap");
        assert_eq!(tor_status_impl(&runtime).state, "ready");

        std::fs::write(
            format!("{}_chat.db", runtime.paths.messaging_prefix.display()),
            b"not a valid SQLCipher database",
        )
        .expect("write a corrupt store ahead of open");

        let error = start_messaging_impl(&runtime).await.expect_err(
            "open must fail closed against a corrupt store, not fall back to a fresh one",
        );
        assert!(!error.is_empty());
        assert!(
            runtime.messaging.lock().await.is_none(),
            "a failed open must leave no messaging session to fall back to"
        );
        assert_eq!(
            messaging_status_impl(&runtime).state,
            "unavailable",
            "messaging_status_impl must agree there is nothing running"
        );
    }
}
