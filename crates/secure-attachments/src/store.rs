//! On-disk encrypted attachment objects and transactional plaintext export
//! (`docs/security-remediation-plan.md` Phase R6).
//!
//! Every object lives directly under one store directory, named by [`random_object_name`] and
//! nothing else: the original filename, content type and size never appear in a path. Objects are
//! written to a hidden sibling temp file first and renamed into place only after the whole
//! ciphertext has been written and fsynced, so a crash mid-ingest leaves at most an orphaned
//! `.partial` file (swept by [`AttachmentStore::sweep_partials`]), never a truncated object under a
//! real name.
//!
//! Export ([`decrypt_to_file_atomically`]) follows the same pattern for plaintext: the destination
//! path only ever appears once decryption has fully authenticated, and every failure path deletes
//! the temporary plaintext. What that deletion cannot do, stated honestly: an unlinked file's
//! blocks may still be recoverable from the underlying device (journalling/copy-on-write
//! filesystems, SSD wear-levelling, snapshots), exactly as for every other best-effort deletion in
//! this project. The guarantee is that Secure never *publishes* unauthenticated plaintext, not
//! that no bytes ever touched the disk.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use crate::{
    AttachmentError, AttachmentKey, AttachmentMetadata, decrypt_stream, encrypt_stream,
    random_object_name,
};

const PARTIAL_SUFFIX: &str = ".partial";

/// Whether `name` has exactly the shape [`random_object_name`] produces (32 lower-hex chars).
/// Checked on every path built from a name, so a name read back from storage can never escape
/// the store directory (`../`, absolute paths, separators) or address a temp file.
#[must_use]
pub fn is_valid_object_name(name: &str) -> bool {
    name.len() == 32 && name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The result of [`AttachmentStore::ingest`]. The caller must persist `key` only inside the
/// encrypted vault (`attachments.attachment_key`) alongside `object_name`.
pub struct IngestedObject {
    pub object_name: String,
    pub key: AttachmentKey,
}

/// A directory of encrypted attachment objects.
#[derive(Debug, Clone)]
pub struct AttachmentStore {
    root: PathBuf,
}

impl AttachmentStore {
    /// Use `root` as the store directory, creating it (owner-only on Unix) if needed.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, AttachmentError> {
        let root = root.into();
        create_private_dir(&root)?;
        Ok(Self { root })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn object_path(&self, name: &str) -> Result<PathBuf, AttachmentError> {
        if !is_valid_object_name(name) {
            return Err(AttachmentError::InvalidObjectName);
        }
        Ok(self.root.join(name))
    }

    /// Encrypt `reader` under a fresh random [`AttachmentKey`] into a new object with a fresh
    /// random name. The object only appears under its name once fully written and fsynced.
    pub fn ingest<R: Read>(
        &self,
        content_type: &str,
        expected_size: u64,
        reader: R,
    ) -> Result<IngestedObject, AttachmentError> {
        let key = AttachmentKey::generate()?;
        let object_name = random_object_name()?;
        let final_path = self.object_path(&object_name)?;
        let partial = self.root.join(format!(".{object_name}{PARTIAL_SUFFIX}"));

        let result = (|| {
            let mut file = create_private_file(&partial)?;
            encrypt_stream(&key, content_type, expected_size, reader, &mut file)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&partial, &final_path)?;
            sync_dir(&self.root);
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&partial);
        }
        result.map(|()| IngestedObject { object_name, key })
    }

    /// Open an object's ciphertext for reading (e.g. to hand to [`decrypt_to_file_atomically`]).
    pub fn open_object(&self, name: &str) -> Result<File, AttachmentError> {
        Ok(File::open(self.object_path(name)?)?)
    }

    /// Delete an object. Idempotent: an object that is already gone is success, so cleanup that
    /// was interrupted after deleting can simply be retried.
    pub fn remove_object(&self, name: &str) -> Result<(), AttachmentError> {
        match fs::remove_file(self.object_path(name)?) {
            Ok(()) => {
                sync_dir(&self.root);
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// Delete leftover `.partial` files from ingests that were interrupted by a crash. They hold
    /// ciphertext under a key that was never persisted, so they are unreadable; this is disk
    /// hygiene.
    pub fn sweep_partials(&self) -> Result<usize, AttachmentError> {
        let mut removed = 0;
        for entry in fs::read_dir(&self.root)?.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with('.')
                && name.ends_with(PARTIAL_SUFFIX)
                && fs::remove_file(entry.path()).is_ok()
            {
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// Delete the whole store directory and everything in it (Burn Identity cleanup). Idempotent.
    pub fn destroy_all(root: &Path) -> Result<(), AttachmentError> {
        match fs::remove_dir_all(root) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

/// Decrypt `reader` under `key` and publish the plaintext at `destination` only after the whole
/// object has authenticated. Plaintext is first written to an owner-only, randomly named
/// temporary file beside `destination` (same directory, so the final rename is atomic), fsynced,
/// then renamed into place. On any authentication or I/O failure the temporary file is deleted and
/// `destination` is left exactly as it was.
pub fn decrypt_to_file_atomically<R: Read>(
    key: &AttachmentKey,
    reader: R,
    destination: &Path,
) -> Result<AttachmentMetadata, AttachmentError> {
    let parent = match destination.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        Some(_) => PathBuf::from("."),
        None => return Err(AttachmentError::InvalidDestination),
    };
    if destination.file_name().is_none() {
        return Err(AttachmentError::InvalidDestination);
    }
    let temp = parent.join(format!(
        ".secure-export-{}{PARTIAL_SUFFIX}",
        random_object_name()?
    ));

    let result = (|| {
        let mut file = create_private_file(&temp)?;
        let metadata = decrypt_stream(key, reader, &mut file)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, destination)?;
        sync_dir(&parent);
        Ok(metadata)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

/// Create a new file that must not already exist, readable/writable by the owner only on Unix.
/// On Windows, files under the per-user application-data directory inherit that directory's
/// owner-only ACL; an exported file inherits the ACL of the directory the user chose.
fn create_private_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn create_private_dir(path: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

/// Best-effort fsync of a directory so a rename/unlink inside it survives power loss (a no-op on
/// Windows, where a directory cannot be opened this way and NTFS journals the metadata change).
fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(handle) = File::open(dir) {
        let _ = handle.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, AttachmentStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = AttachmentStore::open(dir.path().join("attachments")).expect("store");
        (dir, store)
    }

    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<_> = fs::read_dir(dir)
            .expect("read dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn ingest_then_export_round_trips() {
        let (dir, store) = store();
        let object = store
            .ingest("text/plain", 5, b"hello".as_slice())
            .expect("ingest");

        let destination = dir.path().join("out.txt");
        let metadata = decrypt_to_file_atomically(
            &object.key,
            store.open_object(&object.object_name).expect("open"),
            &destination,
        )
        .expect("export");
        assert_eq!(fs::read(&destination).expect("read"), b"hello");
        assert_eq!(metadata.content_type, "text/plain");
        assert_eq!(entries(dir.path()), ["attachments", "out.txt"]);
    }

    #[test]
    fn original_filename_does_not_appear_in_encrypted_object_names() {
        let (_dir, store) = store();
        // The store API never even receives the original filename - only content - so the only
        // names it can produce are random ones; this pins that the directory holds nothing else.
        store
            .ingest("image/png", 3, b"abc".as_slice())
            .expect("ingest");
        let names = entries(store.root());
        assert_eq!(names.len(), 1);
        assert!(is_valid_object_name(&names[0]), "{:?}", names[0]);
        assert!(!names[0].contains("png"));
    }

    #[test]
    fn tampered_ciphertext_never_publishes_the_final_plaintext_path() {
        let (dir, store) = store();
        let object = store
            .ingest("text/plain", 200_000, vec![7_u8; 200_000].as_slice())
            .expect("ingest");
        let path = store.root().join(&object.object_name);
        let mut bytes = fs::read(&path).expect("read");
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        fs::write(&path, &bytes).expect("tamper");

        let destination = dir.path().join("out.bin");
        let error = decrypt_to_file_atomically(&object.key, bytes.as_slice(), &destination)
            .expect_err("tampered object must fail");
        assert!(matches!(error, AttachmentError::Decryption));
        assert!(!destination.exists(), "final path must never appear");
        assert_eq!(
            entries(dir.path()),
            ["attachments"],
            "failed export must remove its temporary plaintext"
        );
    }

    #[test]
    fn truncated_ciphertext_never_publishes_and_removes_its_temporary_plaintext() {
        let (dir, store) = store();
        let object = store
            .ingest("text/plain", 200_000, vec![7_u8; 200_000].as_slice())
            .expect("ingest");
        let bytes = fs::read(store.root().join(&object.object_name)).expect("read");
        let truncated = &bytes[..bytes.len() / 2];

        let destination = dir.path().join("out.bin");
        assert!(decrypt_to_file_atomically(&object.key, truncated, &destination).is_err());
        assert!(!destination.exists());
        assert_eq!(entries(dir.path()), ["attachments"]);
    }

    #[test]
    fn failed_export_leaves_an_existing_destination_untouched() {
        let (dir, store) = store();
        let object = store
            .ingest("text/plain", 5, b"hello".as_slice())
            .expect("ingest");
        let destination = dir.path().join("keep.txt");
        fs::write(&destination, b"original").expect("seed");

        let wrong_key = AttachmentKey::generate().expect("key");
        assert!(
            decrypt_to_file_atomically(
                &wrong_key,
                store.open_object(&object.object_name).expect("open"),
                &destination
            )
            .is_err()
        );
        assert_eq!(fs::read(&destination).expect("read"), b"original");
    }

    #[test]
    fn object_names_that_could_escape_the_store_are_rejected() {
        let (_dir, store) = store();
        for name in [
            "../vault.key",
            "/etc/passwd",
            "",
            ".0123456789abcdef0123456789abcdef.partial",
            "0123456789ABCDEF0123456789ABCDEF",
            "0123456789abcdef0123456789abcde/",
        ] {
            assert!(matches!(
                store.open_object(name),
                Err(AttachmentError::InvalidObjectName)
            ));
            assert!(matches!(
                store.remove_object(name),
                Err(AttachmentError::InvalidObjectName)
            ));
        }
    }

    #[test]
    fn remove_object_is_idempotent() {
        let (_dir, store) = store();
        let object = store.ingest("x/y", 1, b"z".as_slice()).expect("ingest");
        store.remove_object(&object.object_name).expect("remove");
        store
            .remove_object(&object.object_name)
            .expect("second remove is success");
        assert!(entries(store.root()).is_empty());
    }

    #[test]
    fn interrupted_ingest_leaves_only_a_sweepable_partial() {
        struct FailingReader;
        impl Read for FailingReader {
            fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("source vanished"))
            }
        }
        let (_dir, store) = store();
        assert!(store.ingest("x/y", 1, FailingReader).is_err());
        assert!(
            entries(store.root()).is_empty(),
            "failed ingest cleans up after itself"
        );

        // A crash (rather than an error) would leave the partial behind; sweep removes it.
        fs::write(
            store
                .root()
                .join(".0123456789abcdef0123456789abcdef.partial"),
            b"x",
        )
        .expect("simulate crash leftover");
        assert_eq!(store.sweep_partials().expect("sweep"), 1);
        assert!(entries(store.root()).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn objects_and_store_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, store) = store();
        let object = store.ingest("x/y", 1, b"z".as_slice()).expect("ingest");
        let mode = |p: &Path| fs::metadata(p).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode(store.root()), 0o700);
        assert_eq!(mode(&store.root().join(&object.object_name)), 0o600);
    }

    #[test]
    fn destroy_all_removes_the_store_and_is_idempotent() {
        let (_dir, store) = store();
        store.ingest("x/y", 1, b"z".as_slice()).expect("ingest");
        AttachmentStore::destroy_all(store.root()).expect("destroy");
        assert!(!store.root().exists());
        AttachmentStore::destroy_all(store.root()).expect("idempotent");
    }
}
