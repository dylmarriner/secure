//! Crash-consistent on-disk progress tracking for Burn Identity (Phase 6, sequence step 5).
//!
//! `secure_core::AppLifecycle`'s `DestructionStage` lives in memory. On its own that means a
//! crash, power loss or forced kill *during* a burn loses the record of how far the sequence got:
//! the next launch sees an application data directory, finds whatever files the interrupted burn
//! had not yet removed, and starts up as if nothing had been requested. If the crash landed
//! before the envelope was deleted, that is an application that was told to destroy itself and
//! then quietly came back offering the normal unlock prompt.
//!
//! This module closes that gap the same way `secure_storage::burn` already does for
//! per-conversation burns: progress is written to durable storage as the sequence advances, and
//! startup resumes forward from the recorded stage rather than from the beginning.
//!
//! Three deliberate choices worth stating plainly:
//!
//! - **The journal is armed before any work begins, but each stage is recorded only after its
//!   work has run.** These are two different writes doing two different jobs. Arming - recording
//!   `Armed` up front - is what makes the burn survive a crash at all: from that moment the
//!   file's existence commits the application to finishing. Per-stage records are pure
//!   optimisation of *where* to resume, and they must lag the work rather than lead it. A crash
//!   between a step and its record leaves the journal understating progress, so recovery re-runs
//!   that one step - harmless, because every step in this sequence is idempotent (stopping an
//!   already-stopped transport, dropping an already-dropped handle, deleting an already-deleted
//!   file). Recording first would produce the opposite error: a journal claiming a step ran when
//!   the crash prevented it, and recovery would skip it. For the stage that deletes the vault key
//!   envelope, "skip it" means the envelope survives a burn - so the safe direction is not
//!   symmetric, and this is the one that is safe.
//!
//! - **An unreadable or unrecognised journal means "a burn was in progress", never "no burn".**
//!   A corrupt journal is a fail-closed condition: the file's *existence* is the signal, its
//!   contents only refine where to resume. Treating a damaged journal as absent would hand an
//!   attacker a way to cancel a burn by scribbling on one file, which is precisely the
//!   possibility this module exists to remove.
//!
//! - **A completed burn removes its own journal.** Once the sequence reaches `Complete` there is
//!   no envelope, no database and nothing left to protect; the data directory should look like a
//!   fresh install, because for every practical purpose it now is one. Leaving a "this identity
//!   was destroyed" marker behind would be a durable, unauthenticated record that this machine
//!   once ran Secure and burned an identity - exactly the metadata the project's own engineering
//!   rule 8 ("minimise retained metadata") says not to keep.

use std::fs;
use std::io;
use std::path::Path;

use secure_core::DestructionStage;

/// Magic + format version. Rule 6 of the project's engineering rules: persistent formats carry
/// an explicit version marker, so a future stage set can be distinguished from this one rather
/// than silently mis-parsed.
const JOURNAL_MAGIC: &str = "SDJ1";

/// On-disk name for each stage. Owned here rather than in `secure-core` deliberately: the
/// lifecycle crate defines the state machine, the layer that persists it owns its encoding -
/// the same split `secure_storage::burn::BurnStage` uses for its own database strings.
fn stage_to_str(stage: DestructionStage) -> &'static str {
    match stage {
        DestructionStage::Armed => "armed",
        DestructionStage::UiSealed => "ui_sealed",
        DestructionStage::NetworkStopped => "network_stopped",
        DestructionStage::RuntimeSecretsRevoked => "runtime_secrets_revoked",
        DestructionStage::PersistentKeyAccessDestroyed => "persistent_key_access_destroyed",
        DestructionStage::Complete => "complete",
    }
}

fn stage_from_str(value: &str) -> Option<DestructionStage> {
    match value {
        "armed" => Some(DestructionStage::Armed),
        "ui_sealed" => Some(DestructionStage::UiSealed),
        "network_stopped" => Some(DestructionStage::NetworkStopped),
        "runtime_secrets_revoked" => Some(DestructionStage::RuntimeSecretsRevoked),
        "persistent_key_access_destroyed" => Some(DestructionStage::PersistentKeyAccessDestroyed),
        "complete" => Some(DestructionStage::Complete),
        _ => None,
    }
}

/// Read the recorded destruction stage.
///
/// Returns `None` only when no journal file exists at all - i.e. no identity burn has been
/// started, or the last one ran to completion and cleaned up after itself.
///
/// Any journal that exists but cannot be understood - unreadable, truncated, wrong magic,
/// unrecognised stage name - resolves to `Some(DestructionStage::Armed)`, the *earliest* stage,
/// so recovery re-runs the whole sequence from the start. Re-running is safe (every step is
/// idempotent) and is the only interpretation that cannot be exploited: the alternative, treating
/// a damaged journal as "no burn pending", would let anyone who can corrupt a single file resurrect
/// an identity that was already committed to destruction.
pub fn read_stage(path: &Path) -> Option<DestructionStage> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        // Distinguish "there is no journal" from "there is a journal I cannot read". Only the
        // former means no burn is pending; any other I/O error is a journal that exists and
        // must be honoured, so it resolves to the fail-closed earliest stage.
        Err(error) if error.kind() == io::ErrorKind::NotFound => return None,
        Err(_) => return Some(DestructionStage::Armed),
    };

    let mut lines = contents.lines();
    let magic_ok = lines.next() == Some(JOURNAL_MAGIC);
    let stage = lines.next().and_then(stage_from_str);

    match (magic_ok, stage) {
        (true, Some(stage)) => Some(stage),
        _ => Some(DestructionStage::Armed),
    }
}

/// Record `stage` as the destruction sequence's current position, durably.
///
/// Monotonic: a stage at or behind whatever is already recorded is ignored rather than written,
/// so no ordering mistake by a caller - and no replay of an earlier step - can rewind a burn's
/// recorded progress. This is the file-level counterpart to `DestructionStage` itself only being
/// advanceable through the lifecycle's own transitions.
///
/// Durability matters more here than for ordinary application state: the whole point is to
/// survive an abrupt power loss, so this fsyncs the file *and* its parent directory before
/// returning. A rename that is not itself synced can be lost by the filesystem even though the
/// data it points at was written, which would leave exactly the missing-journal case this
/// module exists to prevent.
pub fn record_stage(path: &Path, stage: DestructionStage) -> io::Result<()> {
    if let Some(current) = read_stage(path)
        && stage.rank() <= current.rank()
    {
        return Ok(());
    }

    let body = format!("{JOURNAL_MAGIC}\n{}\n", stage_to_str(stage));
    write_durably(path, body.as_bytes())
}

/// Remove the journal once destruction is complete. Best-effort by design: by the time this
/// runs the vault key envelope is already gone, so a journal left behind is a stale marker, not
/// a security failure - it would cause the next launch to harmlessly re-run a sequence of
/// no-op deletions and then clear itself.
pub fn clear(path: &Path) {
    let _ = fs::remove_file(path);
    let _ = sync_parent_dir(path);
}

/// Write `bytes` to `path` atomically *and* durably: temp file, fsync the temp file's contents,
/// rename into place, then fsync the containing directory so the rename itself survives a power
/// loss. Atomic rename alone guarantees only that a reader never sees a torn file; this
/// additionally guarantees the result is still there after the machine loses power, which
/// is the property a destruction journal actually depends on.
pub(crate) fn write_durably(path: &Path, bytes: &[u8]) -> io::Result<()> {
    // Validated up front so a path with no parent fails here rather than half-way through,
    // after a temp file has already been created somewhere unexpected.
    path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "journal path has no parent directory",
        )
    })?;

    let mut tmp_path = path.to_path_buf();
    let mut name = path
        .file_name()
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "journal path has no file name")
        })?
        .to_os_string();
    name.push(".tmp");
    tmp_path.set_file_name(name);

    {
        let file = fs::File::create(&tmp_path)?;
        io::Write::write_all(&mut &file, bytes)?;
        file.sync_all()?;
    }

    fs::rename(&tmp_path, path)?;
    sync_parent_dir(path)
}

/// fsync the directory containing `path`, so a `rename`/`unlink` within it is durable.
///
/// Opening a directory read-only and calling `fsync` on it is the portable-on-Unix idiom for
/// this. On Windows there is no equivalent operation on a directory handle obtained this way and
/// `File::open` on a directory fails outright, so this is a no-op there - NTFS's own metadata
/// journalling covers the rename-durability case that fsync-the-directory buys on Unix.
pub fn sync_parent_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let Some(parent) = path.parent() else {
            return Ok(());
        };
        fs::File::open(parent)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn journal_in(dir: &Path) -> std::path::PathBuf {
        dir.join("vault.burn")
    }

    #[test]
    fn no_journal_means_no_burn_is_pending() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(read_stage(&journal_in(dir.path())), None);
    }

    #[test]
    fn a_recorded_stage_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = journal_in(dir.path());

        record_stage(&path, DestructionStage::NetworkStopped).expect("record");

        assert_eq!(read_stage(&path), Some(DestructionStage::NetworkStopped));
    }

    #[test]
    fn recorded_progress_only_ever_moves_forward() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = journal_in(dir.path());

        record_stage(&path, DestructionStage::RuntimeSecretsRevoked).expect("record");
        // An out-of-order or replayed earlier stage must not rewind the record.
        record_stage(&path, DestructionStage::UiSealed).expect("earlier stage is ignored");
        assert_eq!(
            read_stage(&path),
            Some(DestructionStage::RuntimeSecretsRevoked)
        );

        // Re-recording the same stage is likewise a no-op, not an error.
        record_stage(&path, DestructionStage::RuntimeSecretsRevoked).expect("same stage");
        assert_eq!(
            read_stage(&path),
            Some(DestructionStage::RuntimeSecretsRevoked)
        );

        record_stage(&path, DestructionStage::Complete).expect("forward");
        assert_eq!(read_stage(&path), Some(DestructionStage::Complete));
    }

    #[test]
    fn a_corrupt_journal_still_means_a_burn_is_pending() {
        // The security-relevant case: an attacker who can write to the data directory must not
        // be able to cancel a pending burn by damaging this file. Every form of damage must
        // resolve to "resume from the earliest stage", never to "nothing to do".
        for damaged in [
            "",
            "garbage",
            "SDJ1",
            "SDJ1\n",
            "SDJ1\nnot_a_real_stage\n",
            "SDJ9\ncomplete\n",
            "complete\n",
            "\0\0\0\0",
        ] {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = journal_in(dir.path());
            fs::write(&path, damaged).expect("write damaged journal");

            assert_eq!(
                read_stage(&path),
                Some(DestructionStage::Armed),
                "damaged journal {damaged:?} must resume from the earliest stage, not vanish"
            );
        }
    }

    #[test]
    fn a_journal_that_cannot_be_read_at_all_still_means_a_burn_is_pending() {
        // A directory in the journal's place is not `NotFound`; it is a journal that exists and
        // cannot be parsed, which must fail closed the same way corrupt contents do.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = journal_in(dir.path());
        fs::create_dir(&path).expect("create a directory where the journal belongs");

        assert_eq!(read_stage(&path), Some(DestructionStage::Armed));
    }

    #[test]
    fn clearing_removes_the_journal_and_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = journal_in(dir.path());
        record_stage(&path, DestructionStage::Complete).expect("record");

        clear(&path);
        assert_eq!(read_stage(&path), None);

        // Clearing an already-cleared journal must not panic or error.
        clear(&path);
        assert_eq!(read_stage(&path), None);
    }

    #[test]
    fn every_stage_name_round_trips() {
        // Guards against a future stage being added to the enum with a `stage_to_str` arm but no
        // matching `stage_from_str` arm, which would silently downgrade a real recorded stage to
        // `Armed` and re-run destruction work that had already completed.
        for stage in [
            DestructionStage::Armed,
            DestructionStage::UiSealed,
            DestructionStage::NetworkStopped,
            DestructionStage::RuntimeSecretsRevoked,
            DestructionStage::PersistentKeyAccessDestroyed,
            DestructionStage::Complete,
        ] {
            assert_eq!(
                stage_from_str(stage_to_str(stage)),
                Some(stage),
                "{stage:?} does not round-trip through its on-disk name"
            );
        }
    }
}
