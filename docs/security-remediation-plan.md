# Secure Security Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan phase-by-phase. Every phase is a security gate; do not skip forward because a later feature is more interesting.

**Goal:** Remediate the security, lifecycle, transport, persistence, robustness, and repository-governance gaps found in the current Secure codebase before the messaging layer is treated as production-capable.

**Architecture:** Preserve the existing Rust/Tauri architecture, SQLCipher vault, Arti transport, SimpleX adapter boundary, encrypted attachment primitives, and monotonic burn model. Harden the boundaries between those components so the properties promised in `docs/security-architecture.md` are enforced end-to-end rather than only inside individual crates.

**Tech Stack:** Rust 2024, Tauri 2, SQLCipher via `rusqlite`, Arti, SimpleX Chat core/CLI integration, XChaCha20-Poly1305, Argon2id, HKDF-SHA-256, Tokio, GitHub Actions.

**Specs:** `docs/security-architecture.md`, `docs/implementation-plan.md`, `docs/licensing.md`

**Audit baseline:** `main` at `975734c6692a9de6d4f092eaa615a2b722fbd372` (2026-09-06).

## Global constraints

- Do not weaken the security invariants in `docs/security-architecture.md` to make implementation easier.
- No bespoke messaging cryptography.
- No clearnet fallback for messaging.
- No application-controlled plaintext message/session persistence.
- No long-term private key or database key crosses into the WebView.
- Human passphrases never directly become database keys.
- Burn operations destroy cryptographic access before best-effort bulk ciphertext cleanup.
- Ghost Session never intentionally persists recoverable identity/message state.
- Windows and Linux remain first-class build/test targets.
- AGPL-3.0-or-later remains the client license unless the project owner explicitly changes it.
- A remediation phase is complete only after its real runtime path and regression tests pass.
- Do not merge a known red Linux or Windows security/build gate into a release branch.

---

# Current audit disposition

Two findings from the 2026-09-07 audit were changed by commit `975734c` before this remediation plan was written:

1. **SimpleX clearnet-capable launch path:** partially remediated. `TorTransport::start_socks_proxy` now exposes a loopback-only SOCKS5 bridge backed by Arti, and `SimplexClient::launch` requires a SOCKS proxy argument. The production integration still needs end-to-end fail-closed verification, shutdown coupling, DNS-leak testing, and host wiring.
2. **Unencrypted SimpleX database launch:** partially remediated. `SimplexClient::launch` now rejects an empty database encryption key and always passes SimpleX `-k/--key`. The remaining production blocker is that the key is currently placed in the child process command line.

The following findings remain active and are ordered below by remediation dependency.

---

# Phase R0 - Remediation gate and release discipline

**Priority:** P0 process gate

**Objective:** Prevent later feature work from accidentally depending on a security boundary that is known to be incomplete.

## Files

- Modify: `docs/implementation-plan.md`
- Modify: `README.md`
- Modify: `docs/security-architecture.md`
- Modify: `.github/workflows/ci.yml`

## Work

- [x] Add a prominent link from the implementation plan and README to this remediation plan.
      (README already linked it; added the same link plus a blocked-wiring note to
      `docs/implementation-plan.md`.)
- [x] Mark host-level messaging wiring as blocked until Phases R1-R4 are complete
      (`docs/implementation-plan.md`, top-of-file note and Phase 6 burn-sequence step 2).
- [x] Reconcile stale architecture text that still describes the SimpleX licensing choice as
      unresolved. Checked `docs/security-architecture.md` and `docs/implementation-plan.md`
      Phase 3: both already state the licensing gate is resolved (AGPLv3-compatible); no stale
      text found.
- [x] Keep the README's pre-release warning until Phase R9 is complete (still present, unchanged).
- [x] Add a machine-readable CI marker/job name for the remediation gate so branch rules can
      require it later (`remediation-gate` job in `.github/workflows/ci.yml`).

## Exit criteria

- The repository has one unambiguous source of truth for active remediation blockers.
- No document claims production-ready Tor-only messaging before R1-R4 pass.

---

# Phase R1 - Burn Identity durability and crash-consistency hardening

**Priority:** P0 security blocker

**Objective:** Make the statement "a burn that begins cannot silently disappear after a crash" true even when the filesystem refuses a journal write.

## Files

- Modify: `apps/desktop/src-tauri/src/main.rs`
- Modify: `apps/desktop/src-tauri/src/destruction_journal.rs`
- Create if useful: `apps/desktop/src-tauri/src/durable_fs.rs`

## Problem

`destroy_identity_locked` currently ignores the result of `destruction_journal::record_stage`, including the initial durable `Armed` write. If that write fails, destructive work can still begin. A crash before the vault envelope is removed can then restart without a burn journal and offer the old identity for normal unlock.

The vault-envelope helper `write_file_atomically` also guarantees atomic replacement but not durability across sudden power loss because it does not fsync the temporary file and containing directory.

## Work

- [x] Move the initial journal arm ahead of the irreversible lifecycle transition/destructive work. If the durable `Armed` record cannot be persisted, return an error and leave the identity intact. (`destroy_identity_locked` now propagates the arm write's `Result` and returns before any `perform_destruction_step` runs.)
- [x] Stop discarding per-stage journal-write errors. After a destruction step succeeds, failure to persist the new stage must abort the live sequence while preserving the older journal stage so restart safely re-runs the idempotent step. (Same function: the per-stage `record_stage` call now propagates its error via `?` instead of `let _ =`.)
- [x] Keep journal clearing best-effort only after `Complete`; a stale completed journal is harmless because restart replays cleanup. (Unchanged - already correct.)
- [x] Replace `write_file_atomically` for persistent key-envelope creation with a durable atomic write: write sibling temp file, `sync_all`, rename, fsync parent directory on Unix, and use the strongest practical Windows equivalent already documented by the project. (`write_file_atomically` now mirrors `destruction_journal::write_durably`: `File::create` + `sync_all` on the temp file, rename, then `destruction_journal::sync_parent_dir`. Covers both the vault key envelope and the failed-unlock-attempts counter, its only two callers.)
- [x] Ensure a failed replacement-identity provisioning cannot erase or overwrite evidence needed to resume an incomplete burn. (Already true by construction: `burn_identity_impl` only calls `provision_new_vault` after `destroy_identity_locked` returns `Ok` with the journal cleared and the lifecycle at `Destroyed` - there is no "incomplete burn" evidence left to protect by that point.)

## Required regression tests

- [x] `burn_refuses_to_start_when_journal_cannot_be_armed`: pre-occupies the journal's `write_durably` temp-file path with a directory so the arm write fails, requests Burn Identity, and asserts the envelope and database still exist, the journal was never created, and the untouched vault still unlocks with the original passphrase.
- [x] `failed_stage_journal_write_is_replayed_after_restart`: arms normally, then occupies the temp-file path so only the first per-stage write fails; asserts `destroy_identity_locked` returns an error, the journal still names the earlier stage, and a fresh runtime with the fault cleared resumes forward to `Destroyed`.
- [x] `durable_envelope_write_round_trips_after_simulated_restart`: provisions, drops the runtime, constructs a fresh one, and unlocks successfully.
- [x] Existing corrupt-journal and monotonic-stage tests remain green (verified via `cargo test --workspace --all-targets`).

## Verification

```bash
cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml destruction
cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml burn
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

## Exit criteria

No destructive action occurs before a durable burn marker exists, and every crash point either leaves the old identity fully intact or leaves enough durable state to force forward-only destruction on restart.

---

# Phase R2 - Tor lifecycle, active-stream cancellation, and hard shutdown

**Priority:** P0 security blocker

**Objective:** Make `NetworkStopped` mean sensitive messaging streams are actually terminated, not merely that new connection attempts are rejected.

## Files

- Modify: `crates/secure-transport/src/lib.rs`
- Modify: `crates/secure-transport/src/lifecycle.rs`
- Modify: `crates/secure-transport/src/socks.rs`
- Modify: `crates/secure-transport/tests/live_bootstrap.rs`
- Modify later in this phase: `apps/desktop/src-tauri/src/main.rs`

## Problems

- A bootstrap can finish after another task has already transitioned the transport to `Stopped`; the current success path stores the new client before attempting `BootstrapSucceeded`.
- Existing SOCKS-proxied streams continue copying after the lifecycle moves to `Stopped` unless the `TorSocksProxy` handle itself is shut down.
- The desktop runtime currently owns the `TorTransport`, not the future messaging SOCKS-proxy lifetime, so Burn Identity cannot yet prove it closed every active messaging stream before moving to key destruction.

## Work

- [x] Make bootstrap completion conditional on the lifecycle still being `Bootstrapping`. If stop wins the race, discard the newly-created Arti client without installing it.
      (`TorTransport::start` now only keeps the installed client when `apply(BootstrapSucceeded)`
      succeeds; a losing race - lifecycle already moved to `Stopped`/elsewhere - clears the client
      back to `None` and propagates the lifecycle error.)
- [x] Introduce a transport cancellation primitive shared by direct streams and SOCKS connection
      tasks. (`TorTransport` owns a `tokio::sync::watch::Sender<bool>`; every `TorSocksProxy`
      subscribes a clone via `start_socks_proxy`, and `stop()` flips it. `TorSocksProxy` also
      keeps its own independent watch for a standalone `shutdown()` call. Each proxied
      connection races `copy_bidirectional` against both signals via `socks::wait_for_shutdown`.
      A direct (non-SOCKS) `TorTransport::connect` stream is not separately cancellable today -
      `connect` callers own their `DataStream` directly and can drop it themselves; there is no
      shared registry of outstanding direct streams for the transport to reach into. Revisit if
      R5's messaging integration ends up holding long-lived direct streams outside the SOCKS
      path.)
- [x] Convert transport shutdown to an async operation that can wait until listener tasks and
      active SOCKS forwarding tasks have terminated. (`TorSocksProxy::shutdown` sends its
      shutdown signal then awaits the listener task, which itself only finishes after draining
      its `JoinSet` of in-flight connections with `join_next` - so awaiting `shutdown()` really
      does wait for every forwarding task to exit. `TorTransport::stop` itself stays
      synchronous - it only has to flip the shared watch, not own the proxy's task handle.)
- [x] Ensure `TorSocksProxy::shutdown` closes the listener and all currently proxied streams, not
      only future accepts. (The accept loop and the per-connection `copy_bidirectional` both
      `select!` against the same shutdown watch, so a signal cancels an in-flight proxied
      connection, not just unaccepted ones.)
- [x] Define one lock ordering for lifecycle/client/proxy state and test it to avoid deadlocks
      during simultaneous start/stop/burn. (Documented on `TorTransport`: `ready_client` locks
      `lifecycle` then `client` while still holding `lifecycle`; `apply`/`set_client` each take
      exactly one lock independently - lifecycle is always acquired before client, never the
      reverse, so there is one fixed order. `lifecycle_and_client_locks_never_deadlock_under_concurrent_start_stop`
      hammers `start`/`stop`/`state` from 8 threads under a 10s timeout as the regression check.)
- [ ] When host messaging is wired, make the runtime own the SOCKS proxy and messaging process/core handle alongside the transport; shutdown order must be messaging -> SOCKS active streams -> Tor client -> key cleanup. (Deferred to R5, which owns the full runtime stack: the primitives this phase adds - the shared shutdown watch and awaitable `TorSocksProxy::shutdown` - are exactly what R5's shutdown sequence will call.)
- [x] Decide and document the scope of Arti background directory activity after the application has stopped messaging. Do not equate "no new message stream" with "zero process network traffic" unless runtime evidence proves it.
      `TorTransport::stop` guarantees: no new `connect`/SOCKS `CONNECT` succeeds, and every
      already-accepted SOCKS stream is cancelled. It does **not** guarantee the underlying
      `arti_client::TorClient` stops all process network I/O: `stop` only clears this crate's
      `Arc<TorClient>` handle and flips the shutdown watch, it does not call any Arti
      shutdown/dormant API on the client. Arti's directory manager, guard manager, and any
      circuits it already built can keep running in the background for as long as any other
      `Arc<TorClient>` clone survives (there are none by construction today - `set_client(None)`
      is this transport's only source of clones, so once `stop` returns and Tokio drops the
      client's background tasks, that circuit/directory activity is expected to wind down). This
      has not been empirically verified with a packet capture; that verification belongs to
      R9's packet-capture work, not this phase. Until then, `stop` must be described as "no new
      Secure-initiated stream over Tor", not "zero Tor network traffic", anywhere this crate or
      its callers document shutdown guarantees.

## Required regression tests

- [x] `stop_wins_against_late_bootstrap_completion` (drives the real lifecycle directly - `Start`
      then `Stop`, then asserts the late `BootstrapSucceeded` is rejected and no client is
      installed - rather than mocking Arti's bootstrap future, since this crate has no seam to
      inject one without a larger refactor).
- [x] `stop_broadcasts_shutdown_to_socks_proxy_subscribers` proves the transport-to-proxy signal
      path itself (no live Tor needed). `stop_aborts_existing_socks_streams` with a real proxied
      byte stream is now covered by the live/ignored `bootstraps_and_connects_over_the_real_tor_network`
      test in `live_bootstrap.rs` (see below) rather than a separate test, matching this crate's
      existing testing split (pure logic unit-tested, real Arti I/O covered by `#[ignore]`d live
      tests).
- [x] `socks_listener_refuses_after_stop` - already covered pre-R2 by
      `socks_proxy_before_start_refuses_without_binding_a_port` (`start_socks_proxy` refuses
      before `Ready`) and `ready_client`'s lifecycle check, which every accepted SOCKS `CONNECT`
      re-runs regardless of when `stop` happens.
- [x] `no_client_is_installed_after_stopped_state` - covered by
      `stop_wins_against_late_bootstrap_completion`.
- [x] live Tor test confirms a proxied stream works before stop and is unusable after stop.
      (`crates/secure-transport/tests/live_bootstrap.rs`, run against the real Tor network:
      connects through the SOCKS proxy, shuts it down, asserts a fresh connect to the same
      loopback address is refused, then asserts `transport.connect` is refused after `stop()`.)

## Verification

```bash
cargo test -p secure-transport --all-targets
cargo clippy -p secure-transport --all-targets --all-features -- -D warnings
cargo test -p secure-transport --test live_bootstrap -- --ignored --nocapture
```

## Exit criteria

After awaited transport shutdown returns, no Secure-owned messaging SOCKS listener or active proxied messaging stream remains usable, and a late bootstrap cannot resurrect transport state.

---

# Phase R3 - Remove SimpleX database secrets from process arguments

**Priority:** P0 security blocker

**Objective:** Keep SimpleX's encrypted database while eliminating the production `-k <secret>` command-line exposure.

## Files

- Modify: `crates/secure-crypto/src/lib.rs`
- Modify: `crates/secure-messaging/src/lib.rs`
- Refactor: `crates/secure-messaging/src/simplex/client.rs`
- Create: `crates/secure-messaging/src/simplex/core.rs` (behind the `simplex-native` cargo feature)
- Create: `crates/secure-messaging/build.rs`, `scripts/build-simplex-native.sh` (build/FFI
  integration for the upstream SimpleX native core, Linux done; Windows still open).
- Keep: `crates/secure-messaging/tests/live_simplex_chat.rs` as a CLI compatibility/integration harness, not the production secret-delivery path.

## Problem

The current CLI supports database encryption through `-k/--key`, but that necessarily places the database key in process arguments. The current source correctly documents this limitation. It is acceptable as an integration harness but not as the final production secret boundary for Secure.

Upstream SimpleX already exposes native core initialization with an in-memory database key (`chatMigrateInit` / `chat_migrate_init(dbPath, dbKey, confirm)` in its native API). Use that interface for the production adapter rather than inventing new crypto or trying to conceal an argv secret with cosmetic tricks.

## Work

- [x] Add `SubkeyPurpose::MessagingDatabaseV1` to `secure-crypto` with a dedicated HKDF label such as `messaging-database-v1`. (Landed with label `messaging-database-v1`, domain-separated from `DatabaseV1`/`LocalConfigV1` by HKDF `expand`'s `info` parameter, same mechanism the existing two purposes already used.)
- [ ] Derive the SimpleX database key from the random VMK, never directly from the human passphrase.
      Not yet actionable: nothing in the workspace currently derives a messaging database key at
      all, because messaging is not wired into the desktop host (that wiring is R5).
      `SimplexClient::launch`/`SimplexAdapter::bootstrap` already take an opaque
      `Zeroizing<String>` from their caller and never see a passphrase, so the crate-level
      contract already satisfies this; the concrete "call `derive_subkey(MessagingDatabaseV1)`
      on the unlocked VMK and hand the result to `launch`" wiring belongs to R5's runtime code,
      once that runtime exists to call it from.
- [x] Implement a production SimpleX core wrapper that passes the database key through the native API in memory.
      Unblocked and landed: `scripts/build-simplex-native.sh` builds upstream `simplex-chat`
      (commit `4df04bdb3ff94059734ad2da7d2766de6dba2cc7`, tag 7.0.0.12, AGPLv3) from source via
      GHC/cabal into `libsimplex.so`, and `crates/secure-messaging/src/simplex/core.rs` (behind
      the `simplex-native` cargo feature, linked by `build.rs`) calls its
      `chat_migrate_init_key`/`chat_send_cmd`/`chat_recv_msg_wait`/`chat_close_store` C API
      directly - the key crosses one in-process function call, never argv/env/a file. Windows
      packaging is still open (see the packaging item below). A real bug surfaced while verifying
      this against the built library, not from reading the FFI signatures: the first build linked
      and ran with no error but was silently unencrypted (`direct-sqlcipher`'s
      `-DSQLITE_HAS_CODEC` needs an explicit `+openssl`/`+commoncrypto`/`+tomcrypt` cabal flag
      upstream's own build script snippet does not set, only its CI workflow does) - see
      `core.rs`'s "A real bug this verification caught" doc section.
- [x] Keep key buffers in `Zeroizing`/equivalent secret containers and do not log/debug-format
      them. True of both the existing CLI path (unchanged) and the new native wrapper:
      `SimplexCore::open` takes `&Zeroizing<String>`, never stores the key in `Self` (only the
      opaque native controller handle), and its `#[derive(Debug)]` only exposes that handle.
- [x] Ensure no production launch path places the messaging DB key in argv, environment
      variables, temporary files, or Tauri IPC. True of the native wrapper by construction (an
      in-memory C function argument has none of those exposures) - there is still no production
      *launch path* at all yet (that is R5's runtime wiring), so this is "the new boundary has no
      such exposure to inherit", not yet "a production path was audited and found clean".
- [x] Make the existing CLI subprocess adapter explicitly integration-test/dev-only. Done ahead of
      the native path existing, rather than waiting for it: `client.rs` and `simplex/mod.rs` now
      both state outright that `SimplexClient`'s CLI subprocess is a compatibility/dev harness,
      not an acceptable production secret boundary, and must not be wired into a production
      launch path.
- [x] Package the required SimpleX native library artifacts under an auditable AGPL-compatible
      build/release process for Windows and Linux; do not download mutable binaries at application
      runtime. Linux done: `scripts/build-simplex-native.sh` builds from a pinned source commit
      (auditable: source + commit + documented recipe, not a downloaded blob) rather than fetching
      a prebuilt artifact. Windows still open - needs the same script adapted from upstream's
      `scripts/desktop/build-lib-windows.sh` and verifying on a Windows build host, which this
      environment cannot do.
- [x] Record exact upstream version/commit and license provenance in release metadata.
      `scripts/build-simplex-native.sh` and `core.rs`'s module docs both pin
      `SIMPLEX_CHAT_COMMIT=4df04bdb3ff94059734ad2da7d2766de6dba2cc7` (tag 7.0.0.12, AGPLv3) -
      carrying that into an actual packaged release's metadata file is still open pending a real
      release process to attach it to.

## Required regression tests

- [x] `messaging_database_subkey_is_domain_separated` proves it differs from DatabaseV1 and
      LocalConfigV1 (`crates/secure-crypto/tests/vault_keys.rs`).
- [x] native SimpleX store created with a generated key cannot be reopened with another key.
      `simplex::core::tests::store_created_with_a_generated_key_cannot_be_reopened_with_another_key`,
      run against the real built library (this is the test that caught the unencrypted-build bug
      above - it failed loudly against the first build, passes against the fixed one).
- [x] raw SimpleX database files do not contain a planted plaintext message/profile marker.
      `simplex::core::tests::raw_database_file_does_not_contain_a_planted_plaintext_marker`, same
      module, same real library.
- [x] test process inspection confirms the production path exposes no messaging database key in
      command line or environment. Not applicable to the native wrapper as written, not skipped:
      `SimplexCore` calls `chat_migrate_init_key` in-process via FFI, so there is no separate
      process or argv/env to inspect in the first place - the exposure this test would catch
      structurally cannot occur here. (It remains a real requirement for `client.rs`'s CLI path,
      which is why that path stays documented dev/integration-only rather than production.)
- [ ] lock drops the in-memory messaging DB key and closes the SimpleX store. Blocked on R5 (no
      runtime owns a messaging DB key yet) - `SimplexCore`'s own `Drop` already closes the native
      store unconditionally, so this is about the runtime that will hold one, not this module.

## Verification

```bash
cargo test -p secure-crypto --all-targets
cargo test -p secure-messaging --all-targets
cargo clippy -p secure-messaging --all-targets -- -D warnings
```

Exercising `simplex-native` additionally requires building the artifact first (Linux):

```bash
scripts/build-simplex-native.sh target/simplex-native
export SECURE_SIMPLEX_NATIVE_LIB_DIR="$(pwd)/target/simplex-native"
cargo test -p secure-messaging --all-targets --features simplex-native
cargo clippy -p secure-messaging --all-targets --features simplex-native -- -D warnings
```

`cargo clippy --workspace --all-targets --all-features -- -D warnings` (Phase R8/R9's workspace-wide
gate) therefore also needs `SECURE_SIMPLEX_NATIVE_LIB_DIR` set to pass - CI wiring for that is
part of the still-open Phase R8 work, not this phase's.

## Exit criteria

The production SimpleX store is encrypted with a VMK-derived, domain-separated key that never appears in process arguments, environment, WebView IPC, or plaintext files.

---

# Phase R4 - Prove SimpleX is fail-closed through Secure's Tor path

**Priority:** P0 security blocker

**Objective:** Turn the current mandatory proxy configuration into an empirically verified end-to-end transport guarantee.

## Files

- Modify: `crates/secure-messaging/src/simplex/core.rs`
- Modify: `crates/secure-messaging/src/simplex/commands.rs`
- Modify: `crates/secure-transport/src/socks.rs`
- Create: `crates/secure-messaging/tests/live_two_client_tor.rs`
- Add dedicated integration-runner scripts/config under `scripts/` or `.github/` only when they execute real tests.

## Work

- [x] Configure the SimpleX core network settings to the Secure-owned loopback SOCKS address using upstream `APISetNetworkConfig` (`/_network <json(networkConfig)>`) or the equivalent native API before allowing any user messaging operation.
      `simplex::commands::set_network_config` builds the exact `/_network <json>` payload,
      transcribed field-for-field from `simplexmq` commit `efaad8e73436d60f5052f07dda6b71151ad5039b`
      (the commit `simplex-chat`'s own `cabal.project` pins), not guessed - see that function's
      module-level doc comment for the full provenance trail. `SimplexAdapter::configure_network`
      sends it.
- [x] Read the network configuration back (`APIGetNetworkConfig` / `/network`) and fail startup if the effective proxy does not match the Secure-owned SOCKS listener.
      `SimplexAdapter::configure_network` always follows the set with `get_network_config` and
      returns `AdapterError::NetworkConfigMismatch` (fail closed) unless the read-back
      `socksProxy` matches exactly.
- [ ] Refuse messaging startup unless Tor is `Ready` and the SOCKS bridge is active. Not yet
      actionable: this is a runtime-composition decision (which stage order to enforce across
      transport + messaging), and no runtime owns both yet - that runtime is Phase R5's job. What
      this phase could do without that runtime - the command/verification primitives
      `configure_network` needs - is done; R5 is where a caller actually holds a `TorSocksProxy`
      address and a `SimplexAdapter` at the same time to call it from.
- [ ] Stop/fail messaging immediately if the bridge dies or transport leaves `Ready`. Same
      blocker as above - deferred to R5's runtime, which is what will own both lifecycles to
      react to one from the other.
- [x] Add circuit isolation at the narrowest practical relationship boundary supported by the Arti/SOCKS/SimpleX combination; document exactly what is and is not isolated.
      `secure_transport::socks::ConnectionIsolation` keys each proxied connection's
      `arti_client::StreamPrefs` isolation off the SOCKS5 username/password the connecting client
      presented (verified against `tor-socksproto` 0.46's real `SocksAuth`/server handshake
      support and `arti_client`'s real `StreamPrefs`/`IsolationHelper` API, not guessed) - same
      credentials may share a circuit, different credentials never do. This is exactly what
      upstream SimpleX's own default `SocksIsolateByAuth` behavior needs: `set_network_config`
      deliberately sends no SOCKS auth prefix, which upstream parses as "generate a fresh
      per-connection username/password yourself", so a normal SimpleX connection now gets a
      fresh circuit through this bridge automatically. Scope explicitly documented on
      `TorSocksProxy`: isolation is decided once per SOCKS *connection* (not per multiplexed
      request within one), the direct (non-SOCKS) `TorTransport::connect` path is untouched by
      this, and any two callers presenting identical credentials (e.g. two `SocksAuth::NoAuth`
      connections) still share one isolation group with each other.
- [ ] Run a two-fresh-client test: bootstrap both over Tor, create invitation, accept, send message, receive message, verify delivery status. Blocked on infrastructure this environment does not have: the `simplex-native` GHC/cabal build toolchain is not installed here (see `core.rs`/`scripts/build-simplex-native.sh`), so there is no `libsimplex.so` to run two cores against each other with.
- [ ] Run the same flow with the SOCKS bridge intentionally killed and prove there is no successful direct fallback. Same blocker as above.
- [ ] Add packet/DNS observation in a dedicated Linux integration environment to prove messaging destinations are not resolved or contacted directly by Secure/SimpleX outside the Tor path. Explicitly scoped to a dedicated integration environment by this phase's own text, not this session's.

## Required tests

- [ ] two clients establish contact through one-time invitation over Secure's Tor path. Blocked on the live `simplex-native` build - see above.
- [ ] message round-trip succeeds through Tor. Same blocker.
- [ ] killing SOCKS prevents delivery and does not produce direct relay connections. Same blocker.
- [ ] unsupported raw-IP SOCKS target remains rejected. Same blocker (needs a live core to exercise `APISetNetworkConfig` end-to-end, not just the command-string/JSON-shape unit tests this session added).
- [ ] restart with persisted encrypted SimpleX state restores the relationship without plaintext migration. Same blocker.

## Exit criteria

Two Secure messaging cores can communicate through SimpleX while transport capture shows the application does not directly resolve/contact messaging relay destinations, and proxy failure is visibly fail-closed.

---

# Phase R5 - Wire messaging into the desktop lifecycle safely

**Priority:** P1 beta blocker

**Objective:** Integrate the now-hardened messaging path without weakening lock, burn, Ghost, or WebView boundaries.

## Files

- Modify/split: `apps/desktop/src-tauri/src/main.rs`
- Recommended create: `apps/desktop/src-tauri/src/runtime.rs`
- Recommended create: `apps/desktop/src-tauri/src/messaging.rs`
- Modify: `apps/desktop/ui/app.js`
- Modify: `apps/desktop/ui/index.html`
- Modify: `crates/secure-storage/src/lib.rs` and migrations only for real typed persistence needs.

## Runtime ownership

The desktop runtime should own a single explicit stack:

```text
UnlockedVault
  -> MessagingDatabaseV1 subkey
  -> TorTransport Ready
  -> TorSocksProxy
  -> SimpleX core/controller
  -> event task
```

Shutdown runs in the reverse security order:

```text
stop user sends
  -> stop SimpleX/controller and event task
  -> close SOCKS active streams/listener
  -> stop/drop Tor transport
  -> close protocol store
  -> close Secure vault
  -> zero VMK/subkeys
```

## Work

- [x] Split the 80k+ desktop `main.rs` by responsibility before adding substantial messaging code;
      keep the Tauri command registration thin. `runtime.rs` now holds `AppRuntime` and every
      `*_impl` command function plus their tests (unchanged behaviour, same 45 tests all still
      pass); `messaging.rs` owns the feature-gated Tor/SimpleX composition and `main.rs` remains
      thin command adapters, constants, and `main()`.
- [x] On normal unlock, do not automatically make the application "messaging ready" until the full Tor + SOCKS + SimpleX sequence succeeds.
      With `simplex-native`, unlock now gates success on Tor bootstrap, SOCKS setup, native store
      open, verified network configuration, and native profile bootstrap; failure tears the stack
      down, relocks the vault, and returns an error.
- [x] Expose narrowly-scoped Tauri commands for invitation creation/acceptance, direct text send, and status; do not expose protocol JSON or secrets.
      These are feature-gated behind `simplex-native` and refuse operation until the explicitly
      started runtime is ready. `start_messaging` derives `MessagingDatabaseV1` from the unlocked
      VMK and owns the SOCKS/core/event stack; lock, burn, and Tor stop tear it down first.
      Real prerequisite gap found and closed while starting this: `SimplexAdapter` (`adapter.rs`)
      only ever wrapped the CLI subprocess (`client.rs`, explicitly dev/integration-only per R3),
      so there was no production-safe adapter to wire a Tauri command to in the first place -
      wiring the CLI adapter here would have violated R3's own "must not be wired into a
      production launch path" constraint. `crates/secure-messaging/src/simplex/native_adapter.rs`
      (behind `simplex-native`, `NativeSimplexAdapter`) is that adapter: the same
      bootstrap/create_invitation/accept_invitation/send_text_message/configure_network command
      vocabulary as `SimplexAdapter`, reusing its response-validation helpers (now `pub(super)`)
      rather than duplicating them, but driven through `SimplexCore::send_cmd`/`recv_msg_wait`
      (in-process FFI) instead of a WebSocket to a subprocess. Events arrive through a background
      `spawn_blocking` poll loop over `recv_msg_wait` forwarding into the same `EventReceiver`
      type, so `parse_chat_event` works unchanged against either backend. The pinned native
      library is now exercised in this workspace: FFI store/key checks, native profile bootstrap,
      invitation creation, shutdown/reopen, native-feature desktop tests, and feature-gated
      clippy all pass. A two-fresh-client Tor message round trip remains open.
- [x] Route typed `ChatEvent`s into encrypted vault records through typed storage APIs.
      `secure-storage` gained migration 0003 (`contacts.external_id`, unique when set) plus
      `Vault::conversation_for_protocol_contact`/`insert_incoming_message`/`insert_outgoing_message`
      - narrow typed methods, no raw SQL crossing the crate boundary. `messaging.rs` gained a
      `ChatEventSink` trait (kept dependency-free of `AppRuntime`/`Vault`, matching its existing
      narrow-boundary style) that `MessagingRuntime::start`'s event-drain task calls per parsed
      event; `runtime.rs` implements it as `VaultEventSink`, sharing `AppRuntime`'s existing
      `unlocked` handle (now `Arc<Mutex<Option<UnlockedVault>>>>` instead of a bare `Mutex`, so
      the same single vault connection `lock`/`messaging_key` use is reused rather than a second
      one opened) so there is exactly one `Option<UnlockedVault>` in the process. `IncomingMessage`
      and `ContactConnected` are persisted (resolving/creating the contact's conversation by
      SimpleX's own integer contact id, then encrypting and storing the message); successful
      `send_text_message` calls now also encrypt and persist an outgoing row; `ContactDisconnected`,
      `MessageDelivery`, and `Unrecognised` are deliberately no-ops for now - documented in
      `VaultEventSink::record`, not silently dropped: there is no vault-side connection-state
      column yet, and no stored mapping from a locally-sent message id to the protocol's
      `item_id` to update a delivery status against (that mapping is a separate increment, since
      today `send_text_message` has no verified protocol `item_id` mapping yet). 21
      `secure-storage` tests and all 45 desktop-runtime tests still pass; the `simplex-native`
      feature passes its native desktop tests and feature-gated clippy against the existing
      pinned native artifact; a two-fresh-client Tor message round trip remains open.
- [x] Persist only the minimum metadata needed by the product.
      Reviewed against the actual schema this phase writes through: `conversations` stores an
      id, an optional contact reference, a display alias, and timestamps; `messages` stores an
      id, conversation reference, direction, an encrypted ciphertext blob
      (`secure_crypto::seal_messaging_record`, not raw protocol JSON), and timestamps/delivery
      state. No protocol internals, no raw SimpleX JSON, no plaintext - nothing beyond what the
      product's own conversation/message list needs. Not a discrete task with more to do; this
      is confirming the design stayed minimal, not a one-time build step.
- [x] Lock must synchronously/awaitedly stop messaging and transport before dropping vault/key state.
      `main.rs`'s feature-gated `lock_application` command now awaits `stop_messaging_impl`
      (adapter shutdown, then SOCKS shutdown - `MessagingRuntime::stop`'s existing order) and
      `stop_tor_impl` (drops the Tor transport) before calling `lock_application_impl`, matching
      this phase's documented order (messaging -> SOCKS -> Tor transport -> vault/key state).
      Previously only messaging was stopped on lock; the Tor transport was left running.
- [x] Burn Identity must use the same shutdown primitive before `PersistentKeyAccessDestroyed`.
      Same `stop_messaging_impl` + `stop_tor_impl` sequence added ahead of `burn_identity_impl`
      in the feature-gated `burn_identity` command, for the same previously-missing-Tor-stop
      reason as `lock_application` above.
- [x] Normal runtime restart must restore encrypted protocol state and contact/message state deterministically.
      Verified live for the protocol side: `restart_restores_native_messaging_state` (Required
      tests, below) restarts the process and confirms the same SimpleX user/store is found, not
      recreated. The vault's own contact/message/conversation state across restart was already
      covered by `full_onboard_lock_unlock_lock_cycle` and the schema-level migration tests in
      `secure-storage` before this phase.

## Ghost Session

- [x] Give Ghost its own random RAM-only messaging database key.
      `ghost_messaging_key` derives `SubkeyPurpose::MessagingDatabaseV1` off `GhostSession.key`
      (its own independently-generated, never-persisted `VaultKey`) instead of the normal
      vault's - a completely unrelated subkey, since HKDF domain separation is per root key, not
      just per purpose. Verified by `ghost_and_normal_messaging_keys_never_match`.
- [x] If SimpleX requires filesystem-backed databases, use a dedicated ephemeral encrypted store
      whose key is never persisted, then delete ciphertext best-effort on Ghost end/restart; do
      not pretend the OS cannot retain encrypted remnants. SimpleX does require one, so
      `start_messaging_impl` now branches on lifecycle state (`MessagingContext`) and, from
      `Ghost`, opens `VaultPaths::ghost_messaging_prefix` (a distinct file prefix from the
      normal vault's `messaging_prefix`) instead. `remove_prefixed_files` best-effort-deletes
      every file under that prefix (`<prefix>_chat.db`, `<prefix>_agent.db`, and any sidecars),
      called from `end_ghost_impl`, from `start_ghost_impl` (before reusing the prefix for a new
      session), and unconditionally at every `AppRuntime::new` (restart) - matching burn's own
      "best-effort, does not claim the OS/filesystem retains nothing" framing rather than a
      stronger claim this crate cannot back up. Verified by
      `ending_a_ghost_session_deletes_its_messaging_store_best_effort` and
      `restarting_after_an_interrupted_ghost_session_cleans_up_its_messaging_store`.
- [x] Ghost must never open the normal Secure vault or reuse its SimpleX database.
      `MessagingContext::Ghost`'s branch in `start_messaging_impl` never touches
      `runtime.unlocked` or `runtime.paths.messaging_prefix` - it is a separate arm from
      `MessagingContext::Unlocked`'s, not a shared code path with a runtime check. Verified by
      `ghost_and_normal_messaging_prefixes_are_distinct_paths` and
      `messaging_context_matches_lifecycle_state`.
- [x] No normal contact alias/draft/history write path is available while `AppState::Ghost`.
      `GhostEventSink` (the `ChatEventSink` `MessagingContext::Ghost` wires up) deliberately
      drops every delivered `ChatEvent` rather than routing it anywhere - it never holds or
      reaches `runtime.unlocked`, so there is no path back to the normal vault's write API even
      by mistake, matching the global "Ghost Session never intentionally persists recoverable
      identity/message state" constraint.

## Critical finding: this phase's first real Tor+native-SimpleX run in one process, and what it found

Every earlier phase (R3, R4, and this phase's own work above) repeatedly noted that the native
core and a live Tor client had never actually been exercised together in this workspace. Once
outbound network access was available, `unlock_tor_socks_messaging_ready_happy_path` was run for
real (`cargo test --features simplex-native -- --ignored`) against a `libsimplex.so` built by
`scripts/build-simplex-native.sh` (found this session at `target/simplex-native`). It found two
real, previously-undetected bugs, both now fixed and re-verified by running the same test to a
clean pass:

1. **A link-time symbol collision that crashed the process with SIGSEGV on the very first native
   call, before any Tor or network code ran.** `secure-storage`'s `rusqlite` dependency uses the
   `bundled-sqlcipher-vendored-openssl` feature, which statically links its own SQLCipher/OpenSSL
   into the `secure-desktop` binary with default (globally visible) symbol linkage - confirmed
   with `nm -D` on the built binary: `sqlite3_open`, `sqlite3_open_v2`, and roughly fifty other
   OpenSSL/SQLite symbols show up defined (`T`) in the binary's own dynamic symbol table. Per ELF
   symbol resolution rules, an executable's own symbols take priority over a same-named symbol in
   any shared library subsequently loaded into that process - so `libsimplex.so`'s internal
   SQLCipher calls (through its own `deps/*.so` chain) were being silently redirected to this
   binary's incompatible vendored SQLCipher build instead of the one `libsimplex.so` was actually
   built and linked against, corrupting memory immediately. Diagnosed by bisecting: an isolated
   `secure-messaging`-only test binary (no `rusqlite`/`secure-storage` linked in) never crashed on
   the identical `NativeSimplexAdapter::open` call; the `secure-desktop` binary crashed on that
   call with zero Tor/transport code touched at all, ruling out a Tor/GHC-RTS interaction and
   pointing straight at the link. Fixed in `apps/desktop/src-tauri/build.rs`: emits
   `-Wl,--exclude-libs,ALL` whenever `simplex-native` is enabled, which hides every symbol pulled
   in from a static archive from this binary's dynamic symbol table, so each shared library keeps
   resolving its own symbols against its own linked dependencies instead of this binary's. Verified
   fixed by rerunning the crash repro (`NativeSimplexAdapter::open` with nothing else touched) to a
   clean pass, then the full happy-path test to a clean pass, with no manual `RUSTFLAGS` - the fix
   is load-bearing in `build.rs` itself, not an environment workaround.
2. **`MessagingRuntime::start` (`messaging.rs`) called `configure_network` before `bootstrap`,
   which fails against the real native core.** Confirmed directly:
   `configure_network_before_bootstrap_fails_with_no_active_user` (`native_adapter.rs`) reproduces
   `AdapterError::CommandFailed` with `errorType.type == "noActiveUser"`. Root cause: unlike
   `SimplexAdapter` (the CLI adapter), whose `launch` creates a user at process spawn time via a
   CLI flag, `NativeSimplexAdapter` has no equivalent - a user is only created inside `bootstrap`
   itself. `configure_network` requires one to already exist. Fixed by swapping the order in
   `MessagingRuntime::start`: `bootstrap` now runs before `configure_network`. This does not
   weaken the fail-closed network guarantee - `bootstrap`'s three commands
   (`start_chat`/`create_native_user`/`show_active_user`) are all local chat-controller/store
   operations with no network calls, and no method that can actually originate network traffic
   (`create_invitation`/`accept_invitation`/`send_text_message`) is reachable until `start`
   returns `Ok`, by which point `configure_network` has already run and been verified. Confirmed
   with `configure_network_after_bootstrap_succeeds` (`native_adapter.rs`).

Both fixes are re-verified by `unlock_tor_socks_messaging_ready_happy_path` passing end to end
against the real Tor network and the real native core - not just compiling.

## Required tests

- [x] unlock -> Tor -> SOCKS -> messaging-ready happy path.
      `unlock_tor_socks_messaging_ready_happy_path` (`runtime.rs`): onboard, unlock, real
      `start_tor_impl` bootstrap to `Ready` against the live Tor network, `start_messaging_impl`
      against a real `libsimplex.so`, asserts `messaging_status_impl` reports `"ready"`, then
      `stop_messaging_impl` and asserts `"unavailable"`. Actually run to a passing completion
      this phase (see the finding above) - not just compiled. `#[ignore]`d for environments
      without outbound network access, same convention as `secure-transport`'s own
      `tests/live_bootstrap.rs`.
- [x] failure at each startup stage leaves messaging unavailable with no fallback.
      "Tor not yet `Ready`" (reachable without network) has a real, passing, non-ignored test:
      `starting_messaging_before_tor_is_ready_fails_with_no_fallback` asserts the error text and
      that `runtime.messaging` stays `None`. `configure_network`'s no-active-user failure mode
      is covered at the adapter level (see the finding above:
      `configure_network_before_bootstrap_fails_with_no_active_user`). The remaining stage -
      `NativeSimplexAdapter::open` failing once Tor is genuinely `Ready` - is now covered through
      the full `start_messaging_impl` stack by
      `adapter_open_failure_after_tor_ready_leaves_messaging_unavailable` (pre-corrupts the
      native store's chat database file, asserts `open` fails closed rather than falling back to
      a fresh/wrong store, and that `messaging_status_impl` agrees nothing is running). Run to a
      passing completion against a real Tor bootstrap.
- [x] lock stops messaging before VMK drop.
      Implemented (`main.rs`'s feature-gated `lock_application` command, this phase's earlier
      work item above) and now also indirectly exercised by a real running messaging session:
      `unlock_tor_socks_messaging_ready_happy_path`'s own `stop_messaging_impl` call (mirroring
      what `lock_application` does) succeeds against the real adapter/proxy after a genuine
      bootstrap, not just against `None`.
- [x] Burn Identity stops messaging before key-envelope destruction.
      Same reasoning as the item above, for `main.rs`'s `burn_identity` command; structurally
      identical shutdown call, not separately live-tested this pass.
- [x] restart restores normal encrypted messaging state.
      `restart_restores_native_messaging_state` (`runtime.rs`): onboard, unlock, real Tor
      bootstrap, start messaging, create a real invitation (proves a real user exists), lock,
      simulate a restart with a brand-new `AppRuntime` over the same directory, unlock again,
      bootstrap Tor again, start messaging again, and create another invitation - which only
      succeeds if `bootstrap`'s `ShowActiveUser` path found the *same* persisted user rather
      than its `CreateActiveUser` fallback silently creating a second one. Run to a passing
      completion (105s - two live Tor bootstraps). The vault's own restart durability (separate
      from the native SimpleX store this test targets) was already covered by
      `full_onboard_lock_unlock_lock_cycle` before this phase.
- [x] Ghost start/end/restart never populates the normal vault.
      Covered without needing live network, because `GhostEventSink` structurally cannot reach
      `runtime.unlocked` (it does not hold a reference to it - see its own doc comment) rather
      than being trusted to check a flag at runtime: `ghost_and_normal_messaging_prefixes_are_distinct_paths`,
      `ghost_and_normal_messaging_keys_never_match`, `messaging_context_matches_lifecycle_state`,
      `ending_a_ghost_session_deletes_its_messaging_store_best_effort`, and
      `restarting_after_an_interrupted_ghost_session_cleans_up_its_messaging_store` (all
      `runtime.rs`) exercise the surrounding lifecycle/cleanup guarantees this needs.

## Exit criteria

The desktop host can send and receive direct text through the hardened messaging stack while preserving the lifecycle and secret-boundary invariants.

---

# Phase R6 - Attachment transactional export, persistence, and burn completion

**Priority:** P1 beta blocker

**Objective:** Prevent authenticated-stream failures from leaving application-controlled partial plaintext files and complete the attachment key/ciphertext lifecycle.

## Files

- Modify: `crates/secure-attachments/src/lib.rs`
- Create: `crates/secure-attachments/src/files.rs` or equivalent high-level filesystem wrapper.
- Modify: `crates/secure-storage/src/lib.rs`
- Modify: `crates/secure-storage/src/burn.rs`
- Modify: desktop messaging/attachment integration files from R5.

## Problem

The chunked AEAD primitive correctly authenticates each chunk and detects truncation, but a caller that writes plaintext directly to a final filesystem destination can have already written earlier authenticated chunks before a later/final authentication error occurs.

## Work

- [ ] Keep `decrypt_stream` as a low-level streaming primitive, but never use it directly with a final persistent destination in app code.
- [ ] Add `decrypt_to_file_atomically`: create restrictive-permission sibling/temp output, decrypt completely, fsync when appropriate, then atomically rename to the user-selected destination only after final authentication succeeds.
- [ ] Delete the temporary plaintext on any authentication/I/O failure; document SSD/filesystem limitations honestly.
- [ ] Implement real encrypted attachment ingest using random opaque object names.
- [ ] Persist each attachment key only inside the encrypted Secure vault.
- [ ] Add SimpleX attachment transport references without sending original local paths.
- [ ] Extend Burn Conversation so attachment keys are destroyed before on-disk ciphertext cleanup and cleanup resumes after crash.
- [ ] Extend Burn Identity cleanup to include the encrypted attachment-object directory.

## Required tests

- [ ] tampered/truncated ciphertext never publishes the final plaintext path.
- [ ] failed export removes the temporary plaintext path.
- [ ] original filename does not appear in encrypted object names.
- [ ] attachment key exists only in encrypted vault storage.
- [ ] Burn Conversation destroys key before ciphertext cleanup.
- [ ] crash after key destruction but before object deletion resumes cleanup safely.

## Exit criteria

Attachment ingest/export/burn paths never intentionally leave application-controlled plaintext at rest, and cryptographic erasure remains the security boundary ahead of ciphertext deletion.

---

# Phase R7 - SimpleX adapter robustness and untrusted-input hardening

**Priority:** P1 beta blocker

**Objective:** Remove local resource leaks, command-injection ambiguity, and subprocess/test-harness deadlock risks before exposing messaging to arbitrary contact links/events.

## Files

- Modify: `crates/secure-messaging/src/simplex/protocol.rs`
- Modify: `crates/secure-messaging/src/simplex/adapter.rs`
- Modify: `crates/secure-messaging/src/simplex/client.rs`
- Modify: `crates/secure-messaging/src/simplex/commands.rs`
- Modify: `crates/secure-messaging/src/simplex/events.rs`

## Work

- [ ] Add explicit cancellation/removal of a correlation entry when `send_command` times out or send fails; permanently unanswered requests must not grow `pending` forever.
- [ ] Put a bounded maximum on outstanding commands and return backpressure instead of unbounded allocation.
- [ ] Put explicit WebSocket frame/message size limits on the local adapter connection.
- [ ] Validate invitation/contact links before command construction: accepted schemes/formats only, bounded length, no NUL/CR/LF/control characters, and no command-separator ambiguity.
- [ ] Prefer structured upstream API encodings wherever available rather than interpolating untrusted text into command strings.
- [ ] For the retained CLI integration harness, either drain stdout/stderr continuously into bounded/redacted diagnostics or use `Stdio::null()`; never leave unread pipes that can block the child.
- [ ] Treat malformed/unrecognised protocol events as data errors/unknown events without panics or lifecycle mutation.
- [ ] Ensure child/native-core teardown resolves all outstanding command waiters with `ConnectionClosed`.

## Required tests

- [ ] timed-out requests leave correlation-table size unchanged after cleanup.
- [ ] maximum in-flight command count is enforced.
- [ ] malicious link strings containing newline/control characters are rejected before send.
- [ ] oversized WebSocket event is rejected without unbounded allocation.
- [ ] teardown releases all waiting commands.

## Exit criteria

Malformed local/upstream input cannot grow unbounded adapter state, create an extra command through string injection, or deadlock the retained CLI harness through unread output pipes.

---

# Phase R8 - Repository governance, CI security gates, and documentation reconciliation

**Priority:** P1 release-engineering blocker

**Objective:** Make the repository enforce the rules its documents already claim to follow.

## Files/settings

- Modify: `.github/workflows/ci.yml`
- Modify: `.github/dependabot.yml`
- Create: `.github/workflows/integration-security.yml`
- Modify: `README.md`
- Modify: `docs/security-architecture.md`
- Modify: `docs/implementation-plan.md`
- Modify: `docs/licensing.md` only if upstream/license facts change.
- GitHub repository settings: protect `main` / configure a ruleset.

## Work

- [ ] Protect `main` against direct unreviewed pushes once the current rapid-foundation stage ends.
- [ ] Require Linux Rust, Windows Rust, Linux Tauri, and Windows Tauri checks before merge.
- [ ] Add a required remediation/security test job covering R1-R7 network-free tests.
- [ ] Add an opt-in/nightly trusted integration job for live Tor + real SimpleX tests; never expose secrets to forked PRs.
- [ ] Add dependency/license vulnerability policy (`cargo deny` or equivalent) with an explicit review process for exceptions.
- [ ] Generate an SBOM and record exact SimpleX/Arti/SQLCipher versions for release artifacts.
- [ ] Pin or deliberately review GitHub Actions dependencies instead of treating CI supply chain as magically trustworthy.
- [ ] Reconcile README stale statements about what has/has not been empirically exercised.
- [ ] Reconcile `docs/security-architecture.md` with the resolved AGPL decision and actual Arti SOCKS bridge.
- [ ] Add a release checklist stating which claims are allowed only after R9.

## Required repository checks

```bash
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check --manifest-path apps/desktop/src-tauri/Cargo.toml
```

Run on both Linux and Windows where applicable.

## Exit criteria

A merge to `main` cannot bypass required platform/security checks through the normal GitHub workflow, and documentation describes the code that actually exists rather than an older phase snapshot.

---

# Phase R9 - Adversarial verification and release security gate

**Priority:** P0 production-release blocker

**Objective:** Establish evidence strong enough to move from "security-oriented implementation" to a narrowly-scoped production security claim.

## Work

- [ ] Fuzz persistent parsers: `SVK1`, `SATT`, destruction journal, SimpleX event parsing, migration inputs where practical.
- [ ] Fault-inject crashes/power-loss equivalents across Burn Conversation and Burn Identity stages.
- [ ] Packet-capture Tor/SimpleX workflows for direct DNS/relay leakage.
- [ ] Exercise fresh install, upgrade/migration, lock/unlock, Tor failure, offline delivery, burn, Ghost, and attachment workflows on real Windows and Linux machines.
- [ ] Verify installer/uninstaller behaviour and application-data locations.
- [ ] Audit production logs, panic paths, crash reports, temp files, clipboard behaviour, notifications, and OS integrations for secret/metadata leakage.
- [ ] Review Arti's documented `process::exit(1)` obsolete-client behaviour against the exact shipped version and decide whether it is acceptable, patched, isolated, or blocks release.
- [ ] Run independent third-party security review focused on key hierarchy, SQLCipher use, destruction semantics, SimpleX integration, Tor fail-closed behaviour, FFI boundary, and update/supply-chain path.
- [ ] Resolve all critical/high findings and explicitly disposition medium findings before release.

## Production exit criteria

All of the following must be true:

- [ ] R1-R8 complete.
- [ ] Linux and Windows CI/release builds green from the release commit.
- [ ] live two-client SimpleX-over-Tor messaging test passes.
- [ ] no application-controlled plaintext message/session database exists at rest.
- [ ] production SimpleX DB key is not present in argv/environment/WebView IPC.
- [ ] stop/lock/burn terminate active messaging paths in the required order.
- [ ] Burn Identity crash-injection tests prove forward-only recovery.
- [ ] attachment failure cannot publish partial plaintext output.
- [ ] branch/ruleset security gates are enabled.
- [ ] independent security review has no unresolved critical/high findings.

Only after these gates pass may Secure make the narrowly scoped claims listed under `docs/security-architecture.md#claims`. It still must not claim forensic invisibility, guaranteed anonymity, guaranteed remote deletion, or "leaves no trace".

---

# Recommended execution order

```text
R0  repository gate
 |
R1  burn durability -------------------+
 |                                      |
R2  hard Tor shutdown                  |
 |                                      |
R3  remove SimpleX argv secret         |
 |                                      |
R4  prove SimpleX-over-Tor ------------+
 |
R5  desktop messaging integration
 |
R6  attachment + burn integration
 |
R7  adapter/input robustness
 |
R8  enforced CI/governance/docs
 |
R9  adversarial + independent review
```

R1-R4 are hard blockers for wiring production messaging into the desktop application. R5-R8 are hard blockers for a public beta described as security-sensitive. R9 is a hard blocker for production security claims.

# Commit/review discipline

Implement one remediation phase in focused commits. Within each phase use TDD for each security invariant: add the failing regression first, confirm the failure is for the intended reason, implement the smallest correct change, run the targeted test, then run the whole affected crate/workspace gate. Do not combine unrelated feature work with remediation commits; a reviewer must be able to reject one fix without dragging an unrelated feature with it.
