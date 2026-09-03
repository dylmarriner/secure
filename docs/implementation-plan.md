# Secure Messenger Implementation Plan

This document is the execution roadmap for Secure. It is deliberately versioned in the repository so architecture, implementation status, security gates and unresolved decisions evolve with the code instead of living in chat history.

The governing security model is `docs/security-architecture.md`. If this roadmap and the security architecture ever conflict, the security architecture wins until both are deliberately reconciled in the same pull request.

## Goal

Build a production-grade private messenger for Windows and Linux with:

- no phone number, email address, global username or public user directory;
- end-to-end encrypted messaging using a mature, externally reviewed protocol substrate rather than bespoke cryptography;
- pairwise / invitation-based contact establishment;
- mandatory fail-closed Tor transport in strict mode;
- encrypted application-controlled local state;
- cryptographic destruction for conversation and identity burn operations;
- an ephemeral Ghost Session mode with no intentionally persistent identity or message state;
- a narrow Tauri UI boundary that never receives long-term secret keys;
- no analytics, advertising, remote fonts, CDNs or production secret logging.

Secure does not promise perfect anonymity, forensic invisibility, guaranteed remote deletion or the ability to erase data copied or cached by the operating system, storage firmware, another application or another participant.

---

# Engineering rules

Every phase below follows these rules.

1. **No invented messaging cryptography.** Use mature reviewed protocol components behind an adapter boundary.
2. **Fail closed.** Security-sensitive failures must not silently downgrade transport, storage protection or destruction semantics.
3. **Keys before files.** Burn operations invalidate cryptographic access before best-effort bulk file cleanup.
4. **No decorative implementation.** A component is not considered implemented until its real runtime path and tests execute successfully.
5. **Test security invariants before convenience behaviour.** Regression tests should pin properties that must remain true.
6. **Version persistent formats.** Key envelopes, encrypted object formats, migrations and protocol adapter state must be explicitly versioned.
7. **Keep the WebView untrusted.** Long-term identity, vault and session keys remain in Rust-owned memory.
8. **Minimise retained metadata.** Do not collect data merely because it may be useful later.
9. **Document platform leakage.** Windows/Linux behaviour involving swap, hibernation, dumps, keyrings, filesystem semantics and notifications must be explicit.
10. **Do not merge known-broken platform targets.** Linux and Windows compile/test gates must remain green for release branches.

---

# Phase 0 - Security foundation

**Status:** In progress

## Scope

- Rust workspace and crate boundaries.
- Tauri 2 desktop shell.
- application lifecycle state machine;
- monotonic destruction state machine;
- random vault master key generation;
- Argon2id passphrase-derived wrapping key;
- versioned authenticated vault-key envelope;
- XChaCha20-Poly1305 local wrapping;
- HKDF-SHA-256 domain-separated subkeys;
- zeroising secret wrappers;
- restrictive frontend CSP;
- CI format/test/clippy gates;
- threat model and security architecture;
- licensing decision gate for the messaging substrate.

## Remaining work

- close any review findings before merge.

All other Phase 0 remaining-work items are complete: the Linux and Windows Tauri
compile gates both run in CI, required application icons/bundle resources exist,
and `cargo fmt`, `cargo test --workspace --all-targets` and
`cargo clippy --workspace --all-targets --all-features -- -D warnings` all pass
locally against the PR head.

## Exit criteria

- `cargo fmt --all -- --check` passes;
- `cargo test --workspace --all-targets` passes;
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` passes;
- Linux Tauri host compiles in CI;
- Windows Tauri host compiles in CI;
- no lifecycle state can be constructed in an internally invalid destruction condition;
- no persistent secret format exists without an explicit version marker.

---

# Phase 1 - Encrypted vault persistence

**Status:** In progress

## Objective

Replace in-memory-only security state with an encrypted application vault without allowing plaintext persistence paths to appear as implementation shortcuts.

## Work

### Storage engine

- select SQLCipher or an equivalently mature encrypted SQLite implementation;
- integrate through a Rust storage abstraction;
- enable foreign keys and defensive SQLite settings;
- explicitly configure journal mode and document encrypted sidecar behaviour;
- prohibit accidental plaintext fallback database creation;
- add schema versioning and migrations.

### Initial schema

Store encrypted records for:

- local identity metadata;
- contacts and local aliases;
- invitations;
- protocol adapter state;
- conversations;
- messages;
- drafts where enabled;
- attachment metadata and attachment keys;
- application configuration containing sensitive values;
- destruction tombstones / cleanup continuation state.

### Key handling

- derive the database key from the random vault master key using a domain-separated HKDF label;
- keep the wrapped vault master key separate from the encrypted database;
- never write the raw vault master key to disk;
- wipe transient key buffers where practical;
- investigate memory locking independently on Windows and Linux and document limitations.

## Implemented (`crates/secure-storage`)

- `Vault::create_new` / `Vault::open_existing` over `rusqlite` with the
  `bundled-sqlcipher-vendored-openssl` feature (SQLCipher 4, vendored OpenSSL - no system
  SQLCipher/OpenSSL dependency);
- database key is `VaultKey::derive_subkey(SubkeyPurpose::DatabaseV1)`, passed to SQLCipher via
  raw-key syntax (`PRAGMA key = "x'...'"`) rather than re-deriving through SQLCipher's own
  PBKDF2, since the input is already a uniformly random 256-bit key;
- key material is force-validated immediately after keying the connection (`verify_key`, a
  `SELECT` against `sqlite_master`) before any pragma or migration work runs, so a wrong key or
  tampered file is reported as `StorageError::WrongKeyOrCorrupt` rather than a confusing
  downstream SQLite error;
- `create_new` refuses to touch a path that already exists (file or directory) and deletes any
  half-initialised file it created itself if key derivation/validation/migration fails partway
  through, so a failed create never leaves a file that looks like a usable - or plaintext -
  vault;
- `open_existing` never creates a file and never deletes an existing one, even on failure;
- schema versioning via `PRAGMA user_version` with an explicit, ordered `Migration` list; each
  migration runs inside a SQL transaction, so a crash mid-migration cannot leave the schema at
  a version between two known states; opening a vault whose stored version is newer than the
  build supports fails closed (`SchemaTooNew`) instead of guessing;
- baseline defensive pragmas: `foreign_keys = ON`, `secure_delete = ON`, `trusted_schema = OFF`;
  journal mode is left at the default rollback journal (not WAL) deliberately, to keep the
  vault as a single on-disk file rather than adding `-wal`/`-shm` sidecars that destruction
  cleanup would also have to find and remove;
- initial schema (`migrations/0001_initial_schema.sql`) covering local identity metadata,
  contacts, invitations, protocol adapter state, conversations, messages, drafts, attachment
  metadata/keys, app config and destruction tombstones, exactly as scoped below. All record ids
  are random 128-bit opaque tokens rather than sequential integers;
- a second migration (`migrations/0002_foreign_key_indexes.sql`, schema version 2) adds indexes
  on `attachments.message_id` and `invitations.resulting_contact_id` - SQLite does not
  auto-index foreign key columns, and Burn Conversation/Burn Identity cascading deletes need
  these to not be full table scans. This is real schema work the vault needed regardless of
  wanting a second migration to test against; it was not invented just to exercise the
  migration path.

## Tests (passing)

- wrong database key cannot open the vault (`wrong_key_cannot_open_vault`);
- tampered ciphertext fails authentication (`tampered_file_fails_authentication`);
- app cannot accidentally create/overwrite a database when a path already exists, file or
  directory (`create_new_rejects_existing_path`,
  `create_new_refuses_to_touch_a_pre_existing_directory`);
- app cannot accidentally leave a usable-looking file behind after a failed open
  (`failed_migration_does_not_leave_a_file_behind`);
- opening a missing vault fails closed rather than creating one (`open_existing_rejects_missing_path`);
- correct key round-trips create -> close -> reopen (`round_trips_with_correct_key`);
- plaintext message content inserted through the schema layer cannot be found anywhere in the
  raw on-disk file after the vault is closed (`no_application_controlled_plaintext_message_persistence`);
- a vault rolled back to look exactly like an existing user's on-disk file from before
  migration 0002 shipped (real inserted conversation/message data, `user_version` reset to 1,
  0002's indexes dropped) migrates forward to the current schema on `open_existing`, ends up
  with 0002's indexes present, and keeps every row inserted before the migration ran
  (`migrating_forward_preserves_existing_encrypted_state`);
- a migration step whose SQL fails partway through leaves `user_version` untouched and none of
  its schema changes applied - proving the transaction-per-step design is safe against a crash
  or forced interruption at any point during a migration, independent of which SQL any future
  migration happens to contain (`migrations::tests::a_failing_migration_step_leaves_user_version_and_schema_untouched`);
- calling the migration runner again once a database is already at the latest schema version is
  a no-op rather than re-running (and failing) already-applied migrations
  (`migrations::tests::migrate_to_latest_is_a_no_op_once_already_current`).

`wrong passphrase cannot produce a usable vault key` is already covered in
`crates/secure-crypto` (Phase 0), one layer below this crate.

## Remaining work

- typed read/write record APIs beyond the test-only insert helpers in `schema.rs` belong to
  whichever later-phase crate (messaging, attachments) actually needs to persist that data.

## Memory locking (`crates/secure-crypto/src/memlock.rs`)

Implemented for the vault master key specifically, not for every derived buffer:

- `VaultKey` is heap-allocated (`Box<[u8; 32]>`) rather than stack-allocated. This is the part
  that actually matters: `mlock`/`VirtualLock` pin a page range at a fixed address, and an
  ordinary Rust value can move (on return, on reassignment) after being locked, leaving the
  lock on a now-unrelated page while the real data sits unlocked at its new address. A `Box`'s
  heap allocation does not move when the `Box` handle itself moves, so locking it once, right
  after allocation, stays valid for the value's whole lifetime;
- locked via `libc::mlock`/`munlock` on Unix and `VirtualLock`/`VirtualUnlock` (via
  `windows-sys`) on Windows, both best-effort - failures (missing privilege, `RLIMIT_MEMLOCK`
  exceeded, locked-pages quota) are ignored rather than fatal, matching the project's stated
  position that this is used "where practical without pretending this defeats a hostile OS";
  verified to compile for Windows via `cargo check --target x86_64-pc-windows-gnu` in this
  environment, since there is no Windows machine available here to actually run it - that
  remains to be exercised on real Windows;
- `Drop for VaultKey` unlocks the range and then zeroes it manually (`[u8;32]::zeroize()`) -
  not via `Zeroizing<Box<...>>`, because `zeroize`'s `Box<T>` impl requires
  `T: DefaultIsZeroes`, which fixed-size arrays deliberately do not implement (they zero
  element-by-element instead), so that combination does not compile;
- deliberately **not** applied to subkeys returned by `VaultKey::derive_subkey` (the database
  and local-config subkeys): those are short-lived, stack-allocated, single-use buffers (e.g.
  handed to SQLCipher as a hex string and dropped immediately), and locking them would mean
  boxing every derived subkey for comparatively little benefit against the swap/hibernation
  threat this defends against. This is a scoping decision, not an oversight;
- there is no test that proves the buffer's contents are physically zero after `Drop` - doing
  that from safe Rust would require reading freed memory, which is undefined behaviour. What
  *is* tested (`repeated_generate_and_drop_does_not_panic` in
  `crates/secure-crypto/tests/vault_keys.rs`) is that repeated lock/unlock/drop cycles never
  panic, including when the underlying platform call itself fails.

## Wired into the Tauri host (`apps/desktop/src-tauri`)

`secure-storage` and `secure-crypto` are now driven by real onboarding/unlock/lock commands,
not left as an unwired library:

- `complete_onboarding(passphrase)`: only valid from `AppState::Onboarding`; generates a vault
  master key, seals it under the passphrase (`Argon2Profile::RECOMMENDED_V1`), writes the
  envelope atomically (temp file + rename), then calls `Vault::create_new`. If database
  creation fails, the just-written envelope is deleted again so a half-finished attempt is
  never mistaken for an existing vault on the next launch. Enforces a 12-character passphrase
  floor (a sanity floor, not a strength meter - Argon2id does the real work);
- `unlock_application(passphrase)`: only valid from `AppState::Locked`; reads and parses the
  envelope, unwraps the vault master key, and opens the database with the derived subkey. The
  vault master key and open `Vault` handle are held in `AppRuntime.unlocked`, a
  `Mutex<Option<UnlockedVault>>` that the WebView has no path to reach - only `AppStatus`
  crosses the IPC boundary;
- `lock_application`: on `Unlocked -> Locked`, sets `unlocked` back to `None`, which drops the
  SQLCipher connection and zeroes the vault master key (`VaultKey` wraps its bytes in
  `Zeroizing`);
- on startup, `AppRuntime::new` checks whether the envelope file exists to decide between the
  `NeedsOnboarding` and `ExistingVault` lifecycle transitions, so a relaunch after onboarding
  correctly starts `Locked` instead of offering onboarding again.

All command bodies are plain functions over `&AppRuntime` (`*_impl`), with `#[tauri::command]`
as a thin IPC adapter, specifically so this logic is unit-testable without a running Tauri
application - there is no display available in this environment to drive the WebView by hand,
so this is how the flow was actually verified rather than only compiled. 8 tests in
`apps/desktop/src-tauri/src/main.rs` cover: fresh install starts in onboarding; a full
onboard -> lock -> unlock -> lock -> simulated-restart -> unlock cycle; rejecting a short
passphrase without writing an envelope; onboarding cannot run twice; wrong passphrase is
rejected and lifecycle stays `Locked`; unlock before onboarding is rejected; locking an
already-locked app is idempotent; a failed database creation cleans up its orphaned envelope.

The frontend (`apps/desktop/ui`) now has real onboarding and unlock forms wired to these
commands, replacing the earlier status-only UI, still with no remote resources and the same
restrictive CSP.

## Exit criteria

A clean install can create, lock, unlock, close and reopen an encrypted vault on Windows and Linux with no application-controlled plaintext message persistence.

---

# Phase 2 - Managed Tor transport

**Status:** In progress

## Objective

Make network access security-enforcing rather than advisory.

## Work

- ~~choose supported Tor integration strategy~~ - **decided: Arti**, the Tor Project's own
  pure-Rust implementation (`arti-client` 0.46), embedded directly rather than bundling and
  supervising the reference C `tor` daemon as a subprocess. No platform binary to package/sign,
  no subprocess lifecycle to supervise, no local SOCKS port; `TorClient::connect` is called
  in-process;
- start and supervise Tor from Rust - `TorTransport::start` calls
  `TorClient::create_bootstrapped`;
- expose only narrowly scoped access to the messaging layer - `TorTransport::connect` is the
  *only* network entry point `secure-transport` exposes; there is no other function anywhere in
  the crate that performs network I/O;
- prohibit WebView direct networking - unchanged from Phase 0 (`connect-src 'none'` CSP; no
  networking capability granted to the WebView);
- prohibit direct DNS resolution for messaging destinations - `connect` only accepts
  `(host, port)` via `arti_client::IntoTorAddr`, never `DangerouslyIntoTorAddr`'s raw-IP
  variants, so a caller cannot bypass Tor-side name resolution;
- implement bootstrap state, failure state and retry policy - see `TransportState` below;
- implement strict-mode network state machine - see `TransportLifecycle` below;
- ensure transport errors never fall back to clearnet - structural, not a runtime check: this
  crate contains no other network path to fall back to;
- shutdown sequencing so sensitive network activity stops before lock/burn cleanup -
  `TorTransport::stop` transitions to the terminal `Stopped` state synchronously, so every
  `connect` call after `stop` returns refuses immediately, before this crate's caller goes on
  to run any lock/burn cleanup.

**Not yet done:** isolating unrelated circuits per-conversation
(`TorClient::isolated_client`/`IsolationToken` exist in the `arti-client` API and are a natural
fit for one isolation token per contact) has no caller yet, because there is no messaging layer
above this crate yet to decide the isolation boundary.

## Wired into the Tauri host (`apps/desktop/src-tauri`)

`AppRuntime` now owns a `TorTransport`, constructed at startup against
`<app_data_dir>/tor/state` and `<app_data_dir>/tor/cache` (separate from the vault's own
directories, matching the same separation-of-concerns the vault key/database split already
uses). Construction never performs network I/O; three commands drive the rest explicitly:

- `tor_status`: current `TransportState` plus `bootstrap_fraction()`, purely informational;
- `start_tor`: bootstraps. Async, since `TorClient::create_bootstrapped` is async and must run
  inside a Tokio context - Tauri provides one, so this did not require adding a runtime;
- `stop_tor`: terminal, idempotent (stopping an already-`Stopped` transport is a no-op success,
  matching `lock_application`'s existing idempotency for the same reason).

Deliberately **not** wired: there is no interlock between vault lock/unlock and Tor start/stop.
Locking the vault does not stop Tor, and unlocking does not start it. The security architecture
document's Lock semantics say to "stop sensitive networking", but with no messaging layer yet
there is no sensitive networking happening to stop, and guessing at that interlock's exact
shape now - before Phase 3 exists to define what "sensitive" means here - would be encoding an
assumption rather than a decision. This is intentionally deferred to Phase 3, not forgotten.

12 desktop-host tests now pass (up from 8): the four new ones cover `tor_status` before any
start, `stop_tor` before start (transitions to `Stopped`), `stop_tor` twice (idempotent), and
`start_tor` after `stop_tor` (refused - the lifecycle rejects `Start` from the terminal
`Stopped` state before any network call is attempted, so this is testable without network
access). The frontend (`apps/desktop/ui`) gained a Tor status badge and start/stop buttons on
the unlocked panel; like the rest of this phase, this has not been visually verified in a real
window since this environment has no display.

## Implemented (`crates/secure-transport`)

- `TransportLifecycle` (`src/lifecycle.rs`): a pure, network-free state machine -
  `NotStarted -> Bootstrapping -> Ready`, `Bootstrapping -> Failed` (with `Failed -> Bootstrapping`
  allowed as the retry path), and `Stop` reachable from every non-terminal state into the
  terminal `Stopped`. `can_connect()` is `true` in exactly one state (`Ready`) and is the single
  enforcement point behind strict mode and "no clearnet fallback". Modelled the same way
  `secure_core::AppLifecycle` separates lifecycle bookkeeping from I/O, specifically so it can
  be fully unit-tested without a live Tor bootstrap;
- `TorTransport` (`src/lib.rs`): wraps `Arc<TorClient<PreferredRuntime>>` and one
  `TransportLifecycle` behind a `Mutex`. `new` builds config via
  `TorClientConfigBuilder::from_directories` (separate state/cache directories, matching the
  vault's own separation of concerns); `start` bootstraps and drives the lifecycle; `connect`
  checks `can_connect()` before doing anything else and refuses with no network I/O attempted
  if the transport isn't `Ready`; `stop` is terminal and synchronous from the caller's
  perspective - it does not await Arti's own background task teardown, only guarantees that no
  *new* connection can be initiated once it returns, which is the actual security property
  shutdown sequencing needs;
- `bootstrap_fraction()` exposes `TorClient::bootstrap_status().as_frac()` for a future status
  indicator; nothing in this crate uses it to decide whether to allow a connection - that
  decision belongs to `TransportLifecycle::can_connect()` alone.

## What has and has not actually been run

The `TransportLifecycle` state machine is unit-tested (10 tests, network-free). The real Arti
integration - `TorTransport::new`/`start`/`connect` actually talking to `arti-client` - compiles
and type-checks against the real 0.46 API (verified against that crate's source directly, not
just docs.rs summaries, after two rounds of real compiler errors: `TorClient<R>` has no default
runtime parameter, so `PreferredRuntime` must be named explicitly from `tor_rtcompat`; and
`TorClientConfigBuilder::from_directories` is an associated function, not a builder method).
**It has not been run against the live Tor network or exercised a real bootstrap.** This
development environment has no outbound network access, so that verification is still
outstanding on a machine that has one - this is analogous to the Windows `mlock` gap from
Phase 1: type-correct and cross-checked as far as this environment allows, not yet empirically
run.

## A known upstream risk, documented rather than hidden

`arti-client`'s own documentation for `TorClient::create_bootstrapped` states that Arti can call
`process::exit(1)` and terminate the whole process if the Tor network consensus marks the
running Arti version as obsolete. That is "fail catastrophic", not "fail closed" - this crate
cannot intercept or downgrade that behaviour from the outside, since it happens inside Arti's
own code. This must be re-checked against upstream's plans to change it before Secure is
described as production-ready; it is not something a message-layer retry policy can work around.

## A real dependency conflict this phase surfaced

`arti-client`'s directory-cache manager (`tor-dirmgr`) also depends on `rusqlite`, and Cargo
only permits one crate in the dependency graph to link the native `sqlite3` library
(`links = "sqlite3"`). `secure-storage`'s `rusqlite` was bumped from 0.32 to 0.36 to satisfy
`tor-dirmgr`'s `>=0.36.0, <0.40.0` requirement; 0.36 still carries the
`bundled-sqlcipher-vendored-openssl` feature `secure-storage` depends on, so this was a
version bump, not a design change. All `secure-storage` tests still pass unmodified.

## Tests (remaining, network-dependent - not yet written)

- Tor process/task death immediately disables messaging transport (this environment cannot
  induce a real bootstrap to then kill);
- DNS leakage tests for supported network paths;
- restart recovery tests against a real persisted state/cache directory;
- firewall/proxy integration tests, practical only in CI or a dedicated integration runner with
  real network access.

## Exit criteria

All messaging traffic supported by the application is forced through the managed Tor path in strict configuration and failure is visibly fail-closed.

---

# Phase 3 - Messaging substrate integration

## Objective

Add real asynchronous E2EE messaging without creating a custom cryptographic protocol.

## Licensing gate

Before importing or linking upstream implementation code:

- resolve the SimpleX / selected substrate licensing model;
- determine whether upstream libraries, subprocess integration, protocol compatibility or a clean adapter implementation is appropriate;
- document resulting obligations in `docs/licensing.md`;
- do not proceed on assumptions about AGPL or commercial licensing.

## Adapter boundary

Create a protocol-neutral Rust interface for:

- identity/session bootstrap;
- invitation creation;
- invitation acceptance;
- connection status;
- message send;
- message receive;
- delivery acknowledgement where available;
- session/key rotation events;
- attachment transport references;
- disconnect / conversation destruction;
- protocol state export into the encrypted vault.

The UI must not depend directly on upstream protocol-specific objects.

## Contact model

- one-time invitations and QR representation;
- local aliases only;
- no searchable global directory;
- safety-code / fingerprint verification;
- explicit contact verification state;
- no automatic contact discovery from phone/email/address books.

## Tests

- two fresh test clients can establish contact using an invitation;
- messages survive offline recipient delivery where supported;
- relay compromise does not expose message plaintext under the selected protocol's model;
- malformed protocol events cannot corrupt the vault lifecycle;
- adapter restart restores required encrypted session state;
- contact removal and burn behaviour are deterministic.

## Exit criteria

Two Secure clients can communicate end-to-end through the selected substrate over the Tor transport with state persisted only in the encrypted vault.

---

# Phase 4 - Attachment pipeline

## Objective

Support media/files without turning the filesystem into a plaintext side channel.

## Work

- independent random encryption key per attachment;
- authenticated streaming encryption suitable for large files;
- random opaque ciphertext object names;
- attachment key stored only inside the encrypted vault;
- authenticated metadata including content type and expected size;
- bounded-memory streaming ingest/export;
- encrypted or transient thumbnails;
- no automatic external media fetching;
- safe temporary-view workflow with explicit warning when opening in external applications;
- attachment cleanup integrated with conversation and identity burn.

## Tests

- ciphertext mutation fails authentication;
- filename does not reveal original name;
- attachment plaintext does not remain in app cache after normal close;
- burn removes attachment keys before deleting ciphertext;
- interrupted download/upload cannot be mistaken for a valid complete object;
- oversized/malformed objects do not exhaust memory.

## Exit criteria

Files can be sent, received and viewed through the application without application-controlled plaintext-at-rest copies.

---

# Phase 5 - Burn Conversation

## Objective

Make local conversation destruction a cryptographic operation, not a delete-button animation.

## Required sequence

1. freeze new sends/receives for the target conversation;
2. mark the conversation destruction operation as monotonic/in-progress;
3. destroy protocol/session secrets for the target relationship where supported;
4. destroy local attachment keys;
5. remove message/contact relationship records required by the burn scope;
6. delete encrypted attachment ciphertext best-effort;
7. persist terminal local destruction state;
8. optionally request cooperative remote deletion only if the protocol supports it, without representing that request as enforceable.

## Tests

- application restart during every destruction stage resumes forward, never backward;
- destroyed attachment keys cannot be reconstructed from remaining application state;
- conversation cannot silently reconnect using old session state;
- repeated burn request is idempotent;
- remote failure does not undo successful local destruction.

## Exit criteria

After a completed local burn, the application has no remaining usable local cryptographic material required to recover the targeted conversation or its attachments.

---

# Phase 6 - Burn Identity

## Objective

Provide application-wide cryptographic destruction with crash consistency.

## Required sequence

1. enter `Destroying` state;
2. stop messaging and Tor activity;
3. revoke normal runtime vault access;
4. atomically invalidate/delete the persistent wrapped vault-master-key envelope;
5. persist sufficient destruction/tombstone state without recreating the destroyed envelope;
6. zero in-memory vault/subkeys where feasible;
7. close database handles;
8. best-effort delete encrypted database, sidecars, attachment ciphertext and sensitive configuration;
9. reach terminal `Destroyed` state.

The critical security boundary is step 4. Files left behind after that point should be cryptographically useless to the application if the design is functioning correctly.

## Tests

Inject restart/crash/failure between every pair of stages and verify:

- old key access never reappears;
- restart only resumes cleanup;
- no code path regenerates an envelope for the destroyed identity;
- final state is terminal;
- incomplete best-effort filesystem deletion does not invalidate the claim of application-key destruction.

## Exit criteria

Destruction has a tested monotonic crash-consistent implementation on Windows and Linux.

---

# Phase 7 - Ghost Session

## Objective

Provide a deliberately ephemeral session mode that does not intentionally persist identity, contact or conversation state.

## Work

- generate session-only identity and keys;
- use memory-backed protocol/session storage where possible;
- if disk-backed protocol state is unavoidable, encrypt it under a random ephemeral key that is never persisted;
- prohibit normal vault writes from Ghost mode;
- disable durable drafts/history/contact aliases;
- destroy session material on exit;
- expose clear UI distinction between normal and Ghost modes;
- document that swap, hibernation, crash dumps, EDR, screenshots and hostile endpoint acquisition remain outside guaranteed control.

## Tests

- Ghost mode cannot access normal persistent identity state without an explicit permitted bridge;
- Ghost session restart does not recover previous identity/session state;
- normal database remains unchanged by Ghost conversations;
- exit destroys runtime key access;
- crash recovery does not accidentally promote ephemeral state to persistent state.

## Exit criteria

Ghost sessions are disposable by design and have no intentional persistent application identity/history path.

---

# Phase 8 - Desktop UX and operational hardening

## Work

- onboarding and local vault creation;
- lock/unlock UX;
- invitation/QR workflow;
- verified-contact UX;
- conversation list and message composer;
- attachment workflow;
- Tor readiness/failure status without leaking sensitive destinations;
- burn confirmation flows that explain local vs remote semantics accurately;
- Ghost Session entry/exit UX;
- notification privacy controls;
- clipboard timeout/clearing where useful and platform-supported;
- screen-capture protection where the OS exposes meaningful controls, documented as best effort;
- safe external-link and external-file handling;
- accessibility and keyboard navigation;
- deterministic update mechanism design before automatic updates are enabled.

## Exit criteria

Security-critical state is understandable without exposing sensitive detail or encouraging false assumptions about anonymity or deletion guarantees.

---

# Phase 9 - Platform hardening

## Windows

Review and test:

- DPAPI / Credential Manager only where architecturally appropriate;
- pagefile behaviour;
- hibernation;
- Windows Error Reporting/crash dumps;
- Defender/EDR interactions;
- notification history;
- recent-file/indexing behaviour;
- installer/uninstaller cleanup semantics;
- filesystem permissions on app-controlled directories.

## Linux

Review and test:

- Secret Service/keyring use only where architecturally appropriate;
- swap and hibernation behaviour;
- core dumps;
- systemd-coredump;
- desktop notification history;
- tracker/baloo/search indexing interactions;
- X11 vs Wayland screenshot/input limitations;
- filesystem permissions;
- AppImage/deb packaging differences.

## Exit criteria

Platform-specific security assumptions are documented and security-sensitive defaults are enforced where the application can enforce them.

---

# Phase 10 - Security validation and release gate

No release should be described as production-ready solely because feature tests pass.

## Automated validation

- unit tests;
- state-machine property tests;
- persistence/migration tests;
- destruction fault-injection tests;
- protocol integration tests;
- Tor fail-closed tests;
- attachment fuzz/property tests;
- parser/input fuzzing for untrusted network/file data;
- dependency audit;
- secret scanning;
- reproducible or at minimum well-documented release builds;
- Windows and Linux build matrix.

## Manual validation

- inspect application-controlled files while locked/unlocked/burned;
- inspect process/network behaviour;
- inspect logs and crash paths for sensitive material;
- inspect temporary directories;
- verify notifications and clipboard behaviour;
- review installer/uninstaller leftovers;
- perform threat-model review against the actual implementation rather than the intended design.

## External review

Before recommending Secure for high-risk communication:

- independent cryptographic/protocol integration review;
- application security review;
- local-storage/destruction review;
- Tor/network privacy review;
- remediation of material findings;
- publish a scoped security assessment and unresolved limitations.

---

# CI / quality gates

The target CI matrix should eventually include:

| Gate | Linux | Windows |
| --- | --- | --- |
| rustfmt | required | required |
| unit/integration tests | required | required |
| clippy `-D warnings` | required | required |
| Tauri compile | required | required |
| storage integration | required | required |
| destruction fault tests | required | required |
| Tor integration | required where runner permits | required where runner permits |
| dependency/security audit | required | required |

Security-critical pull requests should contain tests demonstrating the invariant being added or fixed. A passing test added only after a bug fix is weaker evidence than a red-green regression sequence when that sequence is practical to capture.

---

# Repository target structure

```text
apps/
  desktop/
    ui/
    src-tauri/

crates/
  secure-core/          lifecycle, lock/burn/ghost policy
  secure-crypto/        key hierarchy, envelopes, attachment crypto
  secure-storage/       encrypted vault + migrations
  secure-transport/     Tor process/proxy enforcement
  secure-messaging/     protocol-neutral messaging adapter
  secure-attachments/   encrypted streaming object pipeline
  secure-platform/      narrow Windows/Linux security integrations

docs/
  security-architecture.md
  implementation-plan.md
  licensing.md
  platform-security.md
  protocol-integration.md
  release-security-checklist.md
```

Crates should be introduced when they own real behaviour, not pre-created as empty architecture theatre.

---

# Current priority order

The implementation order is deliberately dependency-driven:

1. finish and merge Phase 0 foundation;
2. encrypted vault persistence;
3. managed fail-closed Tor transport;
4. resolve messaging licensing and integrate the protocol adapter;
5. encrypted attachments;
6. Burn Conversation real I/O path;
7. Burn Identity real I/O path + fault injection;
8. Ghost Session runtime;
9. full desktop UX and platform hardening;
10. independent security review and release hardening.

Do not move Burn Identity or Ghost Session ahead of the storage and transport foundations merely to make the UI look feature-complete. Their security meaning depends on those lower layers being real.

---

# Definition of production-ready

Secure is not production-ready until all of the following are true:

- Windows and Linux builds are continuously tested;
- encrypted vault persistence is complete;
- strict Tor transport is demonstrably fail-closed;
- messaging uses a mature reviewed E2EE substrate under a resolved licence model;
- attachment storage is independently encrypted;
- burn operations have crash/fault-injection coverage;
- Ghost Session has no intentional persistent state path;
- security-sensitive logs/caches/temp files have been audited;
- the threat model has been reconciled against the final implementation;
- material findings from independent security review are resolved or explicitly documented;
- user-facing claims remain narrower than what the implementation and audit evidence can actually support.
