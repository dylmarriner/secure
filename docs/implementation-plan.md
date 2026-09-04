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

**Status:** In progress

## Objective

Add real asynchronous E2EE messaging without creating a custom cryptographic protocol.

## Licensing gate - resolved

Secure ships as an AGPLv3 open-source client, monetized through optional hosted services
rather than the client itself; full decision and reasoning in `docs/licensing.md`. SimpleX
(`simplex-chat/simplex-chat`) is confirmed AGPLv3, which is now license-compatible: its
implementation code may be integrated directly, under the same license, where technically
appropriate. This gate no longer blocks the phase.

Being licensed to link SimpleX code directly does not change the adapter boundary decision
below - `secure-messaging` remains the only crate permitted to depend on SimpleX-derived code,
for the architectural reasons (replaceability, small auditable AGPL-linking surface) recorded
in `docs/licensing.md`, independent of what the license itself permits.

## Adapter boundary

Create a protocol-neutral Rust interface for:

- [x] identity/session bootstrap;
- [x] invitation creation;
- [x] invitation acceptance;
- [x] connection status - typed as `ChatEvent::ContactConnected { contact_id, display_name }`,
      parsed from the `contactConnected` event via `parse_chat_event`. Push-based (arrives as
      an event), not a synchronous per-contact query - `simplex-chat`'s API doesn't offer the
      latter, so this is the correct shape for the underlying protocol, not a shortcut;
- [x] message send (plain text only);
- [x] message receive - typed as `ChatEvent::IncomingMessage { contact_id, text }`, parsed from
      `newChatItems` events, restricted to plain-text messages received (not sent) in a direct
      (not group) chat. Anything else inside a `newChatItems` envelope (group messages, files,
      reactions, sent-message echoes) is silently skipped rather than misparsed;
- [x] delivery acknowledgement where available - typed as
      `ChatEvent::MessageDelivery { contact_id, item_id, status }`, parsed from
      `chatItemsStatusesUpdated` events, restricted to status updates on messages *this client
      sent* (`chatDir.type == "directSnd"`) in a direct chat. `DeliveryStatus` collapses
      `CIStatus`'s `sndNew`/`sndSent`/`sndRcvd`/`sndErrorAuth`/`sndError`/`sndWarning` variants
      into `Pending`/`Sent`/`Received`/`Failed` - the two SimpleX error variants and the warning
      variant all become `Failed` since a caller needs "delivery did not succeed", not
      SimpleX's internal agent-error taxonomy, at this boundary. A status update on a *received*
      item (`directRcv`), a group chat, or a status type this crate does not recognise is
      silently skipped rather than misparsed, matching the "message receive" scoping above;
- [ ] session/key rotation events - SimpleX's double-ratchet rotation is internal and automatic;
      `simplex-chat`'s own bot event reference (`bots/api/EVENTS.md`, checked 2026-09-04) does
      not surface a ratchet/key-rotation event to bot clients at all, so there is nothing this
      crate can parse here without inventing an event that does not exist upstream. Left
      unchecked rather than closed-as-not-applicable until that is re-confirmed against a newer
      `simplex-chat` release;
- [ ] attachment transport references;
- [x] disconnect (peer-initiated) - typed as
      `ChatEvent::ContactDisconnected { contact_id, display_name }`, parsed from the
      `contactDeletedByContact` event. Per `simplex-chat`'s own documentation this fires when
      *the other party* deletes their side of the connection and conversation history is kept
      locally; this crate only surfaces the event; deciding what it means for stored
      conversation state is deferred to whichever later-phase crate owns the vault-backed
      contact model;
- [ ] disconnect (local, per-conversation) / conversation destruction -
      `SimplexAdapter::shutdown` still only stops the whole subprocess (disconnect-everything),
      not a single conversation; that is Phase 5/6 (Burn Conversation/Identity) territory;
- [ ] protocol state export into the encrypted vault.

The UI must not depend directly on upstream protocol-specific objects. Enforced structurally:
`secure-messaging`'s `simplex` module is private (`mod simplex;`, not `pub mod`), so only
`SimplexAdapter`, `Invitation`, `AdapterError`, `EventReceiver`, `ChatEvent`,
`IncomingMessage`/`ContactConnected`/`ContactDisconnected`/`MessageDelivery` and
`parse_chat_event` - re-exported at the crate root -
are visible outside this crate at all. `ChatEvent` itself carries no SimpleX-specific field
names or types (its `Unrecognised(serde_json::Value)` variant is the one place raw JSON survives
past this crate's boundary, deliberately, so a caller isn't blocked on this crate parsing every
event type before it can observe that *something* happened).

## What SimpleX integration actually means here

SimpleX Chat's implementation is Haskell, not Rust - there is no Rust library to `cargo`-link,
regardless of the licensing decision. The documented integration path for any non-Haskell
client is running the `simplex-chat` CLI as a local subprocess with `-p <port>`, which then
serves a JSON-over-WebSocket API (`simplex-chat`'s own `bots/README.md`). `secure-messaging`
implements exactly that: `simplex::client::SimplexClient` spawns the subprocess and speaks the
documented `{"corrId", "cmd"}` / `{"corrId", "resp"}` correlation protocol over the WebSocket;
`simplex::commands` builds the exact command strings (`/_start`, `/_create user <json>`,
`/_address`/`/_connect` for addresses/invitations, `/_send ... json ...` for messages), each
checked against `simplex-chat/simplex-chat`'s generated `bots/api/COMMANDS.md`/`TYPES.md`
(`stable` branch, 2026-09-04) rather than guessed; `simplex::adapter::SimplexAdapter` ties it
together into the narrow public surface above.

27 tests cover everything that does not require a live `simplex-chat` process: every command
string is checked against the documented syntax (`simplex::commands`), the `corrId` correlation
bookkeeping is checked including the stale-response-after-dropped-waiter case
(`simplex::protocol`), response-shape parsing is checked against realistic sample JSON matching
the documented response records (`simplex::adapter`), and typed event parsing is checked
against realistic sample JSON matching the documented event shapes, including the negative
cases - a sent-message echo, a group message, non-text content - that must be silently skipped
rather than misparsed as an incoming direct text message (`simplex::events`).

**What has not been run:** the actual process-spawn-then-WebSocket-connect sequence and any
real command/response round trip. Building the Haskell `simplex-chat` CLI is impractical in
this development environment (no Haskell toolchain; building GHC/cabal dependencies from
scratch is a multi-hour undertaking even with network access). This is the same category of gap
as `secure-transport`'s unexercised live Tor bootstrap: type-correct and protocol-correct as
far as this environment allows, confirmed against upstream's own generated API reference rather
than assumed, but not yet empirically run. Verifying this against a real `simplex-chat` binary
on a machine that can build or install one is the natural next step before this phase can be
called done, and before `secure-messaging` is wired into the Tauri host the way
`secure-storage`/`secure-crypto`/`secure-transport` were.

## Contact model

- [x] one-time invitations - `SimplexAdapter::create_invitation`/`accept_invitation`;
- [ ] QR representation (UI work, not yet done);
- [ ] local aliases (no vault integration yet - `secure-messaging` has no dependency on
      `secure-storage`);
- no searchable global directory: by construction, since only one-time invitations are
  implemented (no `/_address` long-term-address command is wired up);
- [ ] safety-code / fingerprint verification;
- [ ] explicit contact verification state;
- no automatic contact discovery from phone/email/address books: true by omission, nothing in
  this crate reads a phone/email/address book.

## Tests

- two fresh test clients can establish contact using an invitation - **not yet run**, needs a
  real `simplex-chat` process (see above);
- messages survive offline recipient delivery where supported - not yet run, same reason;
- relay compromise does not expose message plaintext under the selected protocol's model - not
  yet run, same reason; also not really this crate's test to write, since SimpleX's own
  end-to-end encryption is what provides this property, not code in `secure-messaging`;
- malformed protocol events cannot corrupt the vault lifecycle - not yet applicable, since
  `secure-messaging` has no vault integration yet (see "protocol state export" above);
- adapter restart restores required encrypted session state - not yet applicable, same reason;
- contact removal and burn behaviour are deterministic - not yet applicable, this is Phase 5/6
  territory.

## Exit criteria

Two Secure clients can communicate end-to-end through the selected substrate over the Tor transport with state persisted only in the encrypted vault.

---

# Phase 4 - Attachment pipeline

**Status:** In progress

## Objective

Support media/files without turning the filesystem into a plaintext side channel.

## Work

- [x] independent random encryption key per attachment - `AttachmentKey::generate`, a fresh
      random 256-bit key per call, never derived from the vault master key;
- [x] authenticated streaming encryption suitable for large files - XChaCha20-Poly1305 under
      the STREAM online-AEAD construction (`chacha20poly1305::aead::stream`), the same
      well-reviewed construction tools like `age` use for this exact problem, not invented here;
- [x] random opaque ciphertext object names - `random_object_name`, a 128-bit random id,
      lower-hex encoded, matching the naming convention `secure-storage` already uses for
      record ids;
- [ ] attachment key stored only inside the encrypted vault - `AttachmentKey`/`from_bytes` are
      ready for a caller to persist into `attachments.attachment_key`, but nothing yet calls
      that; `secure-attachments` has no dependency on `secure-storage` (deliberately - encryption
      primitives and persistence stay separate crates, same boundary discipline as
      `secure-crypto`/`secure-storage`);
- [x] authenticated metadata including content type and expected size - both fields live in a
      header that is itself the AAD for every chunk, so tampering with either invalidates every
      chunk's authentication tag, not just an adjacent unauthenticated field;
- [x] bounded-memory streaming ingest/export - exactly one 64 KiB (plaintext) / 64 KiB+16 byte
      (ciphertext) chunk held at a time; `expected_size` is carried as authenticated metadata,
      never trusted for allocation;
- [ ] encrypted or transient thumbnails - not started; this is image-processing work, out of
      scope for an encryption-primitives crate;
- no automatic external media fetching: true by construction, this crate has no networking code
  at all;
- [ ] safe temporary-view workflow with explicit warning when opening in external applications -
      UI work, Phase 8;
- [ ] attachment cleanup integrated with conversation and identity burn - `secure-storage::burn`
      already destroys `attachments.attachment_key` at the database-row level (Phase 5/6), but
      deleting the actual on-disk ciphertext object this crate would produce is not wired up
      anywhere yet, because nothing yet calls `encrypt_stream` against a real file path with a
      real `random_object_name` - there is no ingest path to wire cleanup to.

## Tests (passing, 11 tests)

- ciphertext mutation fails authentication (`tampered_chunk_content_fails_authentication`);
- tampering with the authenticated header (content type/size) fails authentication, proving the
  header is bound into the AAD and not just carried alongside the ciphertext
  (`tampered_header_fails_authentication`);
- wrong key fails authentication (`wrong_key_fails_authentication`);
- filename does not reveal original name - object names are random and unrelated to any
  filename (`object_names_are_random_and_do_not_reveal_a_filename`);
- interrupted download/upload cannot be mistaken for a valid complete object - a ciphertext
  truncated before its properly last-block-flagged final chunk fails authentication rather than
  decrypting as a shorter-but-valid object, because the STREAM construction binds the
  last-block flag into the tag (`truncated_ciphertext_is_rejected_not_accepted_as_a_shorter_valid_object`);
- round-trips at the chunk-size boundary itself: empty, smaller than one chunk, exactly one
  chunk, and spanning multiple chunks - the exact-multiple-of-chunk-size EOF-detection edge
  case is real and was worth its own test, not just "large file works";
- plaintext does not appear anywhere in the raw ciphertext bytes
  (`plaintext_does_not_appear_anywhere_in_the_ciphertext`);
- invalid magic/version is rejected as a structurally invalid header before any AEAD work runs
  (`invalid_magic_is_rejected`).

"Oversized/malformed objects do not exhaust memory" is satisfied by construction rather than by
a specific test: `expected_size` is read from the (untrusted, attacker-controlled) header but
never used to size a buffer or pre-allocate anything - the only allocations in the ingest/export
path are the two fixed-size chunk buffers. "Attachment plaintext does not remain in app cache
after normal close" and "burn removes attachment keys before deleting ciphertext" are
integration-level properties that depend on a real ingest path and burn wiring that do not exist
yet (see "Work" above) - not testable at this crate's level in isolation.

## Exit criteria

Files can be sent, received and viewed through the application without application-controlled plaintext-at-rest copies.

---

# Phase 5 - Burn Conversation

**Status:** In progress

## Objective

Make local conversation destruction a cryptographic operation, not a delete-button animation.

## Required sequence

1. [x] freeze new sends/receives for the target conversation;
2. [x] mark the conversation destruction operation as monotonic/in-progress;
3. [x] destroy protocol/session secrets for the target relationship where supported;
4. [x] destroy local attachment keys;
5. [x] remove message/contact relationship records required by the burn scope;
6. [ ] delete encrypted attachment ciphertext best-effort - not yet applicable, attachment
       ciphertext storage is Phase 4, not yet implemented;
7. [x] persist terminal local destruction state;
8. [ ] optionally request cooperative remote deletion - out of scope for this crate by design
       (no network access), and there is no messaging-layer caller yet to make the request.

## Implemented (`crates/secure-storage/src/burn.rs`)

- `BurnStage` (`Requested -> Frozen -> ProtocolSecretsDestroyed -> AttachmentKeysDestroyed ->
  RecordsRemoved -> Complete`): a strictly-ordered stage enum where only `BurnStage::next()` can
  advance it, modelled the same way `secure_core::AppLifecycle`'s `DestructionStage` separates
  destruction bookkeeping into an explicit state machine rather than an ad-hoc sequence of
  function calls;
- `burn_conversation(vault, conversation_id)` drives a conversation's `destruction_tombstones`
  row (`scope = 'conversation'`, added in the Phase 1 schema specifically for this) from
  whatever stage it currently holds through to `Complete`, one stage at a time. Each stage's
  database work and the tombstone's advanced `stage` column commit inside the *same* SQL
  transaction - the same "transaction-per-step" pattern `migrations.rs` uses - so a crash
  between stages can never leave the tombstone claiming a stage whose work didn't actually
  commit;
- `resume_incomplete_conversation_burns(vault)` finds every tombstone with
  `scope = 'conversation'` not yet at `Complete` and resumes each from its recorded stage; meant
  to be called once, early, whenever the vault is opened;
- stage semantics: `Frozen` sets `conversations.destroyed_at_unix_ms` (a caller such as the
  future messaging layer is expected to refuse sending/receiving once this is set - this crate
  has no network path to enforce that itself); `ProtocolSecretsDestroyed` deletes the
  conversation's `protocol_adapter_state` row, which is the only session/protocol secret this
  crate currently knows about (`secure-messaging` is not wired to this schema yet - "protocol
  state export into the encrypted vault" is a still-open Phase 3 item, so any *in-memory*
  adapter session state is out of this crate's reach today); `AttachmentKeysDestroyed`
  overwrites every attachment's `attachment_key` with an empty blob *before* `RecordsRemoved`
  deletes the underlying messages (whose `ON DELETE CASCADE` removes the now-key-less attachment
  rows too) - "keys before files" applied to database rows, not just filesystem objects;
  `Complete` persists the terminal marker itself, with no further data changes;
- the conversation row and its contact are deliberately *not* deleted - `conversations` already
  had a nullable `destroyed_at_unix_ms` column from the Phase 1 schema for exactly this: a
  frozen, content-empty tombstone record survives locally (so e.g. a UI can still show "this
  conversation was destroyed"), while every piece of cryptographic material needed to read its
  former content or resume its former session is gone;
- burning a conversation id that does not exist is a reported `StorageError::ConversationNotFound`
  rather than a silent no-op; a corrupted/unrecognised `stage` value already in the database is
  `StorageError::CorruptDestructionStage` rather than a panic.

## Tests (passing, `crates/secure-storage/src/burn.rs`)

- a full burn reaches `Complete` (`burn_reaches_complete_and_is_idempotent`);
- calling burn again on an already-complete conversation is a no-op, not an error and not
  re-run work (same test) - "repeated burn request is idempotent" from the Phase 5 test list;
- burning an unknown conversation id fails rather than silently succeeding
  (`burn_unknown_conversation_is_an_error_not_a_silent_no_op`);
- an attachment's key is verifiably blanked by the `AttachmentKeysDestroyed` stage *before* the
  `RecordsRemoved` stage ever runs, checked by driving the stages individually rather than only
  inspecting the end state (`burn_destroys_attachment_keys_before_removing_rows`) - "destroyed
  attachment keys cannot be reconstructed from remaining application state";
- `protocol_adapter_state` for the conversation's contact is deleted by the burn
  (`burn_deletes_protocol_adapter_state_for_the_contact`) - "conversation cannot silently
  reconnect using old session state";
- the conversation row survives as a destroyed-marked tombstone rather than being deleted
  (`burn_freezes_the_conversation_row_rather_than_deleting_it`);
- a burn resumed after being interrupted immediately after the `Frozen` stage committed
  continues forward from `Frozen` (never re-runs `Requested -> Frozen`) and reaches `Complete`
  (`resuming_from_a_mid_burn_crash_continues_forward_and_completes`) - "application restart
  during every destruction stage resumes forward, never backward";
- resuming when nothing is pending is a no-op (`resume_with_nothing_pending_is_a_no_op`);
- a corrupted stage value already in the database is reported, not panicked on
  (`corrupt_stage_value_is_reported_not_panicked_on`).

"remote failure does not undo successful local destruction" is not yet applicable: there is no
remote-deletion request implemented at all yet (sequence step 8), so there is nothing whose
failure could roll back local state - this crate has no code path that would do so regardless.

## Remaining work

- wire `burn_conversation`/`resume_incomplete_conversation_burns` into the Tauri host once there
  is a UI affordance to trigger a burn (no `#[tauri::command]` calls into this yet, matching the
  project's pattern of landing a crate's real logic and tests before wiring it into the host -
  see `secure-transport`'s own history for the same sequencing);
- attachment ciphertext cleanup (sequence step 6), once Phase 4 exists to define what that
  ciphertext even is;
- cooperative remote deletion (sequence step 8), once a messaging-layer caller exists that could
  make such a request.

## Exit criteria

After a completed local burn, the application has no remaining usable local cryptographic material required to recover the targeted conversation or its attachments.

---

# Phase 6 - Burn Identity

**Status:** In progress

## Objective

Provide application-wide cryptographic destruction with crash consistency.

## Required sequence

1. [x] enter `Destroying` state;
2. [x] stop messaging and Tor activity - Tor only; there is no messaging activity to stop yet
       (`secure-messaging` is not wired into the desktop host). Once it is, its shutdown belongs
       in `perform_destruction_step`'s `NetworkStopped` arm, alongside the transport stop;
3. [x] revoke normal runtime vault access;
4. [x] atomically invalidate/delete the persistent wrapped vault-master-key envelope;
5. [x] persist sufficient destruction/tombstone state without recreating the destroyed envelope -
       a durable destruction journal (`vault.burn`), see "Crash-consistent destruction journal"
       below. Deliberately *not* a permanent tombstone: it is deleted once the burn completes,
       because a lasting "an identity was destroyed here" marker is exactly the retained metadata
       engineering rule 8 forbids, and there is nothing left to protect by that point;
6. [x] zero in-memory vault/subkeys where feasible - via `UnlockedVault`'s own `Drop`;
7. [x] close database handles - same `Drop`;
8. [x] best-effort delete encrypted database and sensitive configuration (the attempts counter);
       sidecars and attachment ciphertext are not yet applicable (no WAL sidecars by design, no
       attachment pipeline yet - Phase 4);
9. [x] reach terminal `Destroyed` state - and, once reached, the journal is cleared so the data
       directory is indistinguishable from a fresh install.

The critical security boundary is step 4. Files left behind after that point should be
cryptographically useless to the application if the design is functioning correctly.

**Status:** the sequence is now crash-consistent and resumable across a restart from any stage,
and reachable deliberately rather than only via the wrong-passphrase failsafe. See the three
"Implemented" sections below.

## Implemented: deliberate burn trigger (`burn_identity`)

Until this landed, the *only* way to reach Burn Identity was the wipe-on-three-wrong-passphrases
failsafe below - meaning a user who wanted to destroy their data on purpose had to either
deliberately fail their own passphrase three times or delete files by hand, neither of which runs
the ordered destruction sequence. `burn_identity` is that same sequence, invoked on purpose.

- accepted from `Locked`, `Unlocked` and `Ghost`, matching `AppEvent::BeginIdentityBurn`'s own
  accepted states; idempotent from `Destroyed` (reports success rather than an error, matching
  `lock_application`/`stop_tor`'s existing idempotency); refused from `Onboarding` with an error
  rather than pretending to have destroyed something that never existed;
- **deliberately does not require the passphrase.** Someone who can already operate the running
  application can destroy its data. Demanding the passphrase first would make destruction
  unavailable in precisely the situations a burn feature exists for - including the case where
  the user genuinely no longer knows it;
- optionally takes a replacement passphrase - see "Implemented: replacement identity" below;
- confirmation is the UI's responsibility, not the command's: `apps/desktop/ui` requires typing
  `DESTROY` into a form that is collapsed by default and re-collapsed on every state change, so a
  second stray click cannot trigger an action with no undo. The panel states plainly what the
  burn cannot reach - copies already delivered to contacts, OS swap/hibernation/crash dumps,
  backups and filesystem snapshots, drive firmware - rather than implying the data is gone
  everywhere.

## Implemented: crash-consistent destruction journal (`src/destruction_journal.rs`)

This closes the "Known gap" previously recorded here: identity burn now has the same on-disk,
resumable stage tracking `secure-storage::burn` has for conversations.

- `vault.burn` next to the envelope records the destruction stage. Its **existence** is the
  signal that a burn is pending and must be finished; its contents only refine where to resume.
  Versioned (`SDJ1` magic) per engineering rule 6;
- `AppRuntime::new` checks the journal **before** the vault-exists branch, because the dangerous
  case is the one where both are true: a burn that crashed before deleting the envelope leaves a
  perfectly openable vault on disk, and the application would otherwise come back offering the
  normal unlock prompt for an identity the user had already ordered destroyed. A recovered
  journal instead reconstructs the lifecycle via the new `AppLifecycle::resuming_destruction`
  and drives the remaining stages to `Destroyed`;
- **ordering rule, and why only one direction is safe.** The journal is *armed* (`Armed` written)
  before any work begins - that write is what commits the application to finishing. Each
  individual stage is then recorded only *after* its work has run. A crash in that gap leaves the
  journal understating progress, so recovery re-runs one step; every step is idempotent (stopping
  an already-stopped transport, dropping an already-dropped handle, deleting an already-deleted
  file), so that costs a no-op. Recording a stage *before* its work would produce the opposite
  error - a journal claiming a step ran when the crash prevented it - and recovery would skip it.
  For the stage that deletes the envelope, "skip it" means the envelope survives a burn. The
  first implementation of this had it backwards and the stage-by-stage crash test below caught
  it, which is the argument for having written those tests;
- **a damaged journal fails closed**: unreadable, truncated, wrong magic or an unrecognised stage
  all resolve to the *earliest* stage, so recovery re-runs the whole sequence. Treating a damaged
  journal as absent would hand anyone who can write to the data directory a one-file way to
  cancel a burn already committed to;
- writes are atomic **and durable** - temp file, `fsync`, rename, then `fsync` of the parent
  directory. `write_file_atomically` only guarantees a reader never sees a torn file; a rename
  that is not itself synced can be lost by the filesystem on power loss, which would recreate the
  exact missing-journal case this exists to prevent. (Directory fsync is a Unix idiom and is a
  no-op on Windows, where NTFS metadata journalling covers the same case.)

## Implemented: replacement identity ("a whole new lockbox")

`burn_identity` optionally takes a replacement passphrase. When given, a brand-new vault is
provisioned in place once destruction has fully completed, and the application ends up `Locked`
on that new identity rather than `Destroyed`.

- the replacement shares **nothing** with what it replaces. `provision_new_vault` generates a
  fresh random vault master key - not derived from the old key, from the new passphrase, or from
  anything that survived the burn. Reusing the same file paths is a filesystem detail, not a
  cryptographic relationship: the new database is keyed by a key that did not exist until after
  the old one was destroyed, so access to the new vault reveals nothing about the old;
- **provisioning happens strictly after the destruction journal is cleared**, never as a
  destruction stage. Inside the sequence, a crash between provisioning and clearing the journal
  would make the next launch resume the burn and destroy the brand-new vault. Afterwards, the
  worst case is a crash leaving no replacement - recoverable by onboarding normally;
- a failed replacement never resurrects the destroyed identity: the burn stands, the error says
  so, and the application stays `Destroyed`;
- the replacement passphrase is length-validated **before** anything is destroyed, so a typo in
  an operation with no undo cannot cost the user their data;
- the replacement does not inherit the destroyed identity's failed-attempt counter.

### What this is not

It is a real, usable, cryptographically unrelated identity. It is **not** a deniability
mechanism, and the UI does not describe it as one. A replacement vault is a vault with a recent
creation date and no history; an adversary who knows this software has the feature - it is open
source - learns nothing from its presence except that Secure is installed. Fabricating a
*plausible-looking* history to survive coercion is a materially different and much harder
problem, with a well-documented tendency to leave the user worse off than an obviously-empty
install, and nothing here attempts it. If a decoy-content mode is ever wanted, it needs its own
threat-model section, not a quiet extension of this one.

## Implemented: overwrite-before-unlink with a random cover pattern

`shred_file_best_effort` overwrites a file's bytes in place with **random** data and `fsync`s
that overwrite before unlinking, rather than a bare `fs::remove_file`. Applied to both the
envelope and the database.

Random rather than zeros, deliberately: a zero-filled run is conspicuous - it advertises that
something was deliberately erased at that offset. Random bytes are indistinguishable from the
encrypted content that legitimately occupies these files, so the overwrite is itself the cover,
and it leaves the freed space looking like ordinary ciphertext rather than like a wiped hole.
Fresh randomness per 4 KiB chunk, since a single repeated block would be as recognisable a
pattern as zeros.

Stated honestly, because it is easy to oversell: this raises the bar against trivial undelete and
file-carving, and it does **not** guarantee the previous bytes are unrecoverable. Copy-on-write
and journalling filesystems (btrfs, ZFS, ext4 `data=journal`) may retain the old extent; SSD
wear-levelling and over-provisioning mean the flash translation layer may never reuse the physical
page; snapshots and backups are outside the process's reach entirely. The real guarantee here
remains cryptographic - the key material is gone from the only place the application ever wrote
it - and this is defence in depth on top of that, not a substitute. This does not change the
project's stated position that Secure does not promise forensic invisibility.

## Implemented: wipe-on-repeated-wrong-passphrase failsafe (`apps/desktop/src-tauri/src/main.rs`)

A concrete trigger for Burn Identity: after `MAX_FAILED_UNLOCK_ATTEMPTS` (3) *consecutive*
incorrect passphrase attempts against `unlock_application`, `record_failed_unlock_attempt` drives
`AppLifecycle` through `AppEvent::BeginIdentityBurn` and then `destroy_identity_locked` runs the
sequence above end-to-end: stop Tor, drop the open vault handle (if any), delete the envelope
(the security boundary), then best-effort delete the database and the attempt counter itself.

- the attempt count is persisted to a plain file (`vault.attempts`) next to the envelope, not
  held in memory, specifically so it survives an application restart - the most obvious way an
  attacker would otherwise try to reset it;
- a correct passphrase resets the counter to zero, so only a *consecutive* streak of wrong
  attempts can ever reach the threshold, not a lifetime total across many legitimate sessions;
- only a wrong passphrase against an otherwise-valid, parseable envelope counts toward the
  threshold - a missing or corrupt envelope is a different, already-handled failure class, so an
  attacker cannot force a wipe merely by damaging the envelope file without ever guessing the
  passphrase;
- **honest limit, stated in the code, not hidden**: the attempt counter file itself is a plain,
  unauthenticated integer. Anyone with direct read/write access to the application's data
  directory can reset or edit it to defeat this failsafe. This does not lower the vault's actual
  security boundary, because that same level of filesystem access already lets an attacker copy
  the encrypted database and envelope out for offline attack, or simply delete them - both
  strictly easier than tampering with a counter file. What this failsafe actually defends
  against is repeated passphrase guessing *through the application's own unlock command*, which
  is what "wrong PIN 3 times" means in practice for a desktop application without a secure
  enclave or OS-backed attempt-throttling to lean on;
- restart-time orphan cleanup: `AppRuntime::new` now removes any leftover database/attempts
  file it finds when no envelope exists (e.g. best-effort cleanup partially failed after an
  earlier burn) - the database is already permanently unreadable by that point regardless, so
  this is disk hygiene, not a security boundary, matching the "restart only resumes cleanup"
  test requirement without needing tombstone machinery for a case where there is nothing left to
  protect.

8 tests in `apps/desktop/src-tauri/src/main.rs` (up from 6) cover: exactly 3 consecutive wrong
attempts destroys the envelope, database and attempts file and reaches `AppState::Destroyed`;
2 wrong attempts followed by a correct unlock resets the counter so a further 2 wrong attempts
do not wipe; the counter survives a simulated application restart (a fresh `AppRuntime` against
the same directory); a fresh onboarding does not inherit a stale counter left over in the same
directory; and a destroyed vault can never be unlocked again, even with the original correct
passphrase.

## Tests

38 tests now pass in the desktop host (up from 12), 7 of them in `destruction_journal` itself.
The crash-injection list this section previously described as future work is now exercised.

A real crash cannot be induced from inside a unit test, but what a crash *leaves behind* can be
reproduced exactly: a journal recording some stage plus the on-disk file state that stage
implies. Recovery is then driven by constructing a fresh `AppRuntime` against that directory -
the same code path a real relaunch takes, with no in-memory state carried over.

- `a_burn_interrupted_at_any_stage_resumes_forward_to_destroyed_on_restart` covers **every**
  stage (`Armed` through `Complete`) and asserts, for each: final state is terminal
  (`Destroyed`); the envelope is gone; database and attempts file are gone; the journal cleared
  itself; and the original *correct* passphrase no longer unlocks anything - "old key access
  never reappears";
- `a_burn_interrupted_before_key_destruction_still_destroys_the_key_on_restart` isolates the case
  that matters most, and first proves the envelope really was still openable with the correct
  passphrase at the simulated moment of the crash - so the test demonstrates recovery being
  *taken away*, not an already-dead vault;
- `a_journal_that_understates_progress_re_runs_the_step_harmlessly` covers the other side of the
  ordering rule: journal one step behind reality, so recovery re-runs a completed step
  (shredding an already-deleted envelope) and must still reach the terminal state;
- `a_damaged_journal_cannot_cancel_a_pending_burn`, plus
  `destruction_journal::tests::a_corrupt_journal_still_means_a_burn_is_pending` over eight
  distinct forms of damage, and `..._that_cannot_be_read_at_all_...` for a non-file in its place;
- `a_completed_burn_leaves_a_data_directory_that_looks_like_a_fresh_install` - after the burn and
  one further relaunch the application offers onboarding and none of the four files exist. This
  is the "as if it never existed" property stated as an assertion;
- `recorded_progress_only_ever_moves_forward` pins that a replayed or out-of-order earlier stage
  cannot rewind the record - "restart only resumes cleanup", at the file level;
- `every_stage_name_round_trips` guards against a future stage gaining a serialise arm but no
  deserialise arm, which would silently downgrade a real recorded stage to `Armed`;
- `the_envelope_is_overwritten_before_it_is_unlinked` hard-links a witness to the same inode so
  the data outlives the unlink, then asserts the bytes were actually replaced, cover the whole
  file, and are not an obvious zero fill - pinning that `shred_file_best_effort` neither silently
  degrades to a plain remove nor leaves a conspicuous erased-here pattern;
- replacement identity: `a_replacement_identity_takes_the_destroyed_one_s_place` (ends `Locked`,
  usable, and critically *not* left inside a pending burn that the next launch would resume);
  `the_destroyed_identity_s_passphrase_is_worthless_against_the_replacement` (different envelope
  bytes, and the old passphrase is rejected as simply incorrect - the "unrelated lockbox" claim
  as an assertion); `a_replacement_identity_starts_with_no_history_and_a_clean_attempt_counter`;
  `a_rejected_replacement_passphrase_destroys_nothing` (validation precedes destruction, so a
  typo cannot cost data in an operation with no undo);
  `a_replacement_identity_survives_a_restart_as_a_normal_vault`;
- `burn_identity_destroys_an_unlocked_vault_on_request` also asserts the open vault handle was
  dropped (not merely orphaned), so the SQLCipher connection is closed and the vault master key
  zeroed;
- `burn_identity_destroys_a_locked_vault_without_needing_the_passphrase`,
  `burning_an_already_destroyed_identity_is_idempotent`,
  `burn_identity_is_refused_before_a_vault_exists`;
- in `secure-core`: `a_resumed_destruction_continues_forward_from_its_recovered_stage` (a stage
  completed before the crash is not re-applicable - the sequence is monotonic *across* a restart,
  not merely within one process) and `a_recovered_complete_stage_is_already_terminal`.

"no code path regenerates an envelope for the destroyed identity" holds structurally: the only
writer of the envelope is `complete_onboarding_impl`, which requires `AppState::Onboarding`, and
that state is unreachable from `Destroyed` within a process. After a relaunch onboarding *is*
offered again - correctly, since by then nothing of the destroyed identity remains - and it
writes a fresh randomly-generated vault master key, not the destroyed one, which no longer exists
anywhere to regenerate.

## Remaining work

- the destruction journal is unauthenticated, exactly like the attempts counter and for the same
  reason: authenticating it needs a key that needs the passphrase. This asymmetry is deliberate
  and safe - an attacker can *create* a journal (forcing a burn of data they already had the
  access to delete outright) but cannot *cancel* one, because every form of damage resolves to
  "resume from the earliest stage";
- Windows behaviour of the directory-fsync no-op and of overwrite-before-unlink on NTFS is
  reasoned about but not empirically run here, the same category of gap as Phase 1's Windows
  `mlock` and Phase 2's live Tor bootstrap;
- Ghost mode is an accepted burn state in the lifecycle but there is no Ghost runtime yet
  (Phase 7) for that path to be exercised against.

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
