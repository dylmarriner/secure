//! In-memory FFI binding to upstream simplex-chat's native core (`libsimplex.so`), feature-gated
//! behind `simplex-native` (see `Cargo.toml` and `build.rs`).
//!
//! This is the production secret-delivery boundary `docs/security-remediation-plan.md` Phase R3
//! requires: [`SimplexCore::open`] passes the database key to `chat_migrate_init_key` through a
//! C function-call argument in this process's own memory, never through argv or an environment
//! variable the way `client.rs`'s CLI subprocess harness necessarily does (see that module's
//! docs for why the CLI has no better option). Do not add a launch path that shells out to the
//! `simplex-chat` binary and calls it production; that path stays dev/integration-test-only.
//!
//! # Provenance
//!
//! Built from `github.com/simplex-chat/simplex-chat` commit `4df04bdb3ff94059734ad2da7d2766de6dba2cc7`
//! (tagged version 7.0.0.12), AGPLv3 - see `scripts/build-simplex-native.sh`, which reproduces
//! this exact build from source. The FFI signatures below are transcribed from that commit's
//! `src/Simplex/Chat/Mobile.hs` `foreign export ccall` declarations and `src/Simplex/Chat/Mobile/Shared.hs`
//! (`CJSONString = CString`), not machine-generated from a C header upstream does not ship for
//! this target - re-check them by hand against that file if `SIMPLEX_CHAT_COMMIT` in the build
//! script above is ever bumped.
//!
//! # What has been verified against the real library
//!
//! This module's own `#[cfg(test)]` tests below have been run against a real `libsimplex.so`
//! built by the script above and confirm: a store opened with a generated key cannot be reopened
//! with a different key (`errorNotADatabase`, not `ok`), and the raw `.db` file on disk does not
//! contain a planted plaintext marker. Not yet exercised end-to-end: sending a real chat command
//! and receiving a real event through `chat_send_cmd`/`chat_recv_msg_wait` against a live SimpleX
//! server - that needs Phase R4/R5's Tor-routed network path, not just the FFI boundary this
//! module owns.
//!
//! # A real bug this verification caught
//!
//! The first build via `scripts/build-simplex-native.sh` linked and ran without any error and
//! `chat_migrate_init_key` reported `ok` for every key tried, including a wrong one against an
//! already-provisioned store - the `.db` files it wrote had a plain `SQLite format 3\0` header,
//! not SQLCipher ciphertext. Root cause: `direct-sqlcipher`'s `-DSQLITE_HAS_CODEC` (the #define
//! that compiles encryption support into its bundled sqlite3 amalgamation at all) is gated behind
//! its `commoncrypto`/`openssl`/`tomcrypt` cabal flags, all `default: False` - so a build with no
//! flags set silently produces a fully functional, entirely *unencrypted* library, with no error
//! anywhere to say so. Upstream's own build script snippet (`scripts/desktop/build-lib-linux.sh`)
//! does not set this either; only its CI workflow does, via a `cabal.project.local` written
//! immediately before the build step. `scripts/build-simplex-native.sh` now does the same. No
//! amount of reading the FFI signatures or type-checking against them would have caught this -
//! only actually opening a store, trying the wrong key against it, and inspecting the raw file
//! bytes did.

// Not yet called from anywhere in this crate outside its own tests: wiring a runtime that opens
// a `SimplexCore` and derives its key from the vault's VMK is Phase R5's job (see this module's
// top-level docs), not this one's - R3 is "the production secret-delivery boundary exists and is
// verified against the real library", which the tests below do independently of any caller.
#![allow(dead_code)]

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::path::Path;
use std::sync::Once;
use std::time::Duration;

use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("database file prefix path is not valid UTF-8/contains a NUL byte")]
    InvalidPath,
    #[error("database key contains a NUL byte")]
    InvalidKey,
    #[error("command string contains a NUL byte")]
    InvalidCommand,
    #[error("chat_migrate_init_key returned invalid UTF-8/JSON: {0}")]
    MalformedResponse(#[from] serde_json::Error),
    #[error("database migration did not succeed: {result}")]
    MigrationFailed { result: serde_json::Value },
    #[error("chat_migrate_init_key reported success but did not return a controller handle")]
    NoController,
}

// Transcribed from `foreign export ccall` in `src/Simplex/Chat/Mobile.hs` at the commit recorded
// in this module's doc comment. `CJSONString = CString` (`Mobile/Shared.hs`): every JSON-string
// return value here is a NUL-terminated, heap-allocated (Haskell `mallocBytes`, i.e. libc
// `malloc`-compatible) C string that the caller must free with `libc::free`.
unsafe extern "C" {
    fn chat_migrate_init_key(
        db_file_prefix: *const c_char,
        db_key: *const c_char,
        keep_key: c_int,
        confirm: *const c_char,
        background: c_int,
        ctrl: *mut *mut c_void,
    ) -> *mut c_char;

    fn chat_close_store(ctrl: *mut c_void) -> *mut c_char;

    fn chat_send_cmd(ctrl: *mut c_void, cmd: *const c_char) -> *mut c_char;

    fn chat_recv_msg_wait(ctrl: *mut c_void, timeout_micros: c_int) -> *mut c_char;
}

// The GHC RTS backing `libsimplex.so` (`-flink-rts -threaded`, see `build.rs`) must be
// initialised with `hs_init` before any `chat_*` call, exactly once per process - calling it
// twice or calling a `chat_*` function first corrupts RTS state rather than erroring cleanly, so
// this is not optional bookkeeping.
unsafe extern "C" {
    fn hs_init(argc: *mut c_int, argv: *mut *mut *mut c_char);
}

static RTS_INIT: Once = Once::new();

fn ensure_rts_initialised() {
    RTS_INIT.call_once(|| unsafe {
        hs_init(std::ptr::null_mut(), std::ptr::null_mut());
    });
}

/// Reads a `chat_*` function's returned `CJSONString`, freeing the underlying Haskell-allocated
/// buffer regardless of whether parsing succeeds - every `chat_*` call in this module returns a
/// string it does not otherwise take ownership of.
fn take_json_response(raw: *mut c_char) -> Result<serde_json::Value, CoreError> {
    debug_assert!(!raw.is_null(), "chat_* JSON functions do not return NULL");
    let text = unsafe { CStr::from_ptr(raw) }
        .to_string_lossy()
        .into_owned();
    unsafe { libc::free(raw.cast::<c_void>()) };
    Ok(serde_json::from_str(&text)?)
}

fn cstring(value: &str, invalid: CoreError) -> Result<CString, CoreError> {
    CString::new(value).map_err(|_| invalid)
}

/// An open handle to upstream simplex-chat's native core - one `ChatController` (a `StablePtr`
/// on the Haskell side, opaque here) backed by an on-disk SQLCipher-encrypted database.
#[derive(Debug)]
pub struct SimplexCore {
    controller: *mut c_void,
}

// `ChatController` is a `StablePtr` to a value the Haskell RTS treats as safe to hand across
// threads (upstream's own mobile/desktop bindings call `chat_send_cmd`/`chat_recv_msg_wait` from
// different OS threads without additional external locking); this wrapper only ever hands out
// one `&SimplexCore` at a time to `async` callers via `tokio::task::spawn_blocking`, never
// concurrent direct calls, so `Send` without `Sync` is the honest bound here.
unsafe impl Send for SimplexCore {}

impl SimplexCore {
    /// Open (creating and migrating if necessary) a SQLCipher-encrypted simplex-chat database at
    /// `db_file_prefix` (a path *prefix*: upstream creates `<prefix>_chat.db`/`<prefix>_agent.db`
    /// etc. under it, same convention as `client.rs`'s CLI `-d` flag), encrypted with `key`.
    ///
    /// `key` should be a domain-separated subkey derived from the vault's VMK
    /// (`secure_crypto::SubkeyPurpose::MessagingDatabaseV1`), never the user's raw passphrase -
    /// deriving and passing that key is the caller's responsibility (the runtime wiring that
    /// calls this belongs to Phase R5, once a runtime exists to own it), not this module's: this
    /// function takes whatever `Zeroizing<String>` it is given and does not otherwise inspect its
    /// origin, matching `client.rs::SimplexClient::launch`'s existing contract.
    pub fn open(db_file_prefix: &Path, key: &Zeroizing<String>) -> Result<Self, CoreError> {
        ensure_rts_initialised();

        let prefix = db_file_prefix.to_str().ok_or(CoreError::InvalidPath)?;
        let prefix = cstring(prefix, CoreError::InvalidPath)?;
        // Not `CString::new`: that copy would outlive this call un-wiped (and may reallocate to
        // append the NUL, leaving a second copy behind). One exact-capacity buffer, zeroed on drop.
        if key.as_bytes().contains(&0) {
            return Err(CoreError::InvalidKey);
        }
        let mut key_c = Zeroizing::new(Vec::with_capacity(key.len() + 1));
        key_c.extend_from_slice(key.as_bytes());
        key_c.push(0);
        // "yesUp" (`MCYesUp`): apply forward schema migrations automatically rather than
        // blocking on an interactive confirmation this process has no console for - the same
        // choice upstream's own `defaultMobileConfig` makes for mobile/desktop clients.
        let confirm = cstring("yesUp", CoreError::InvalidPath).expect("literal has no NUL byte");

        let mut controller: *mut c_void = std::ptr::null_mut();
        let response = unsafe {
            chat_migrate_init_key(
                prefix.as_ptr(),
                key_c.as_ptr().cast::<c_char>(),
                0, // keep_key: false - the native core need not retain the key past opening.
                confirm.as_ptr(),
                0, // background: false - this is a foreground open, not a background migration.
                &mut controller,
            )
        };
        let result = take_json_response(response)?;

        if result.get("type").and_then(serde_json::Value::as_str) != Some("ok") {
            return Err(CoreError::MigrationFailed { result });
        }
        if controller.is_null() {
            return Err(CoreError::NoController);
        }

        Ok(Self { controller })
    }

    /// Send a raw chat protocol command string (the same textual API `client.rs` sends over its
    /// WebSocket) and receive its immediate JSON response.
    pub fn send_cmd(&self, cmd: &str) -> Result<serde_json::Value, CoreError> {
        let cmd = cstring(cmd, CoreError::InvalidCommand)?;
        let response = unsafe { chat_send_cmd(self.controller, cmd.as_ptr()) };
        take_json_response(response)
    }

    /// Block waiting for the next chat event (or `Ok(Value::Null)`-shaped timeout, per upstream's
    /// own "returns empty string if times out" contract) for up to `timeout`.
    pub fn recv_msg_wait(&self, timeout: Duration) -> Result<serde_json::Value, CoreError> {
        let timeout_micros = c_int::try_from(timeout.as_micros()).unwrap_or(c_int::MAX);
        let response = unsafe { chat_recv_msg_wait(self.controller, timeout_micros) };
        let raw = unsafe { CStr::from_ptr(response) }.to_bytes();
        if raw.is_empty() {
            unsafe { libc::free(response.cast::<c_void>()) };
            return Ok(serde_json::Value::Null);
        }
        take_json_response(response)
    }
}

impl Drop for SimplexCore {
    fn drop(&mut self) {
        // `chat_close_store` returns a plain `CString` (not `CJSONString`) status message this
        // wrapper has no caller left to report to by the time `Drop` runs; freeing it is the only
        // remaining obligation.
        let status = unsafe { chat_close_store(self.controller) };
        if !status.is_null() {
            unsafe { libc::free(status.cast::<c_void>()) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn open_rejects_a_key_containing_a_nul_byte() {
        let dir = tempfile::tempdir().expect("tempdir");
        let prefix = dir.path().join("store");
        let key = Zeroizing::new("bad\0key".to_string());

        let error = SimplexCore::open(&prefix, &key).expect_err("NUL byte must be rejected");
        assert!(matches!(error, CoreError::InvalidKey));
    }

    // The two tests below link and run the real `libsimplex.so` (see this module's build.rs
    // requirement) rather than mocking anything, per `docs/security-remediation-plan.md` Phase
    // R3's required regression tests: proving the on-disk store is genuinely SQLCipher-encrypted
    // with the key this module passed it, not merely that this wrapper's Rust types compile.

    #[test]
    fn store_created_with_a_generated_key_cannot_be_reopened_with_another_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let prefix = dir.path().join("store");
        let key = Zeroizing::new("correct horse battery staple".to_string());

        let core = SimplexCore::open(&prefix, &key).expect("open with the real key");
        drop(core);

        let wrong_key = Zeroizing::new("a different key entirely".to_string());
        let error = SimplexCore::open(&prefix, &wrong_key)
            .expect_err("reopening an existing store with the wrong key must fail");
        match error {
            CoreError::MigrationFailed { result } => {
                let tag = result.get("type").and_then(serde_json::Value::as_str);
                assert_ne!(tag, Some("ok"), "wrong key must not report success");
            }
            other => panic!("expected a reported migration failure, got {other:?}"),
        }
    }

    #[test]
    fn raw_database_file_does_not_contain_a_planted_plaintext_marker() {
        let dir = tempfile::tempdir().expect("tempdir");
        let prefix = dir.path().join("store");
        let key = Zeroizing::new("correct horse battery staple".to_string());
        const MARKER: &str = "SECURE-PLAINTEXT-MARKER-DO-NOT-LEAK";

        let core = SimplexCore::open(&prefix, &key).expect("open with the real key");
        // A real chat command that writes user-controlled text into the store: an invalid
        // command still round-trips through the same JSON-encoding/DB-persistence path as a
        // valid one for anything upstream chooses to log or persist verbatim.
        let _ = core.send_cmd(&format!("/_this_is_not_a_real_command {MARKER}"));
        drop(core);

        let mut found_a_db_file = false;
        for entry in std::fs::read_dir(dir.path()).expect("read temp dir") {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("db") {
                continue;
            }
            found_a_db_file = true;
            let mut contents = Vec::new();
            std::fs::File::open(&path)
                .expect("open db file")
                .read_to_end(&mut contents)
                .expect("read db file");
            assert!(
                !contents
                    .windows(MARKER.len())
                    .any(|window| window == MARKER.as_bytes()),
                "plaintext marker leaked into {path:?}"
            );
        }
        assert!(found_a_db_file, "expected at least one *.db file to exist");
    }
}
