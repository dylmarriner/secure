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

- [ ] Make bootstrap completion conditional on the lifecycle still being `Bootstrapping`. If stop wins the race, discard the newly-created Arti client without installing it.
- [ ] Introduce a transport cancellation primitive shared by direct streams and SOCKS connection tasks.
- [ ] Convert transport shutdown to an async operation that can wait until listener tasks and active SOCKS forwarding tasks have terminated.
- [ ] Ensure `TorSocksProxy::shutdown` closes the listener and all currently proxied streams, not only future accepts.
- [ ] Define one lock ordering for lifecycle/client/proxy state and test it to avoid deadlocks during simultaneous start/stop/burn.
- [ ] When host messaging is wired, make the runtime own the SOCKS proxy and messaging process/core handle alongside the transport; shutdown order must be messaging -> SOCKS active streams -> Tor client -> key cleanup.
- [ ] Decide and document the scope of Arti background directory activity after the application has stopped messaging. Do not equate "no new message stream" with "zero process network traffic" unless runtime evidence proves it.

## Required regression tests

- [ ] `stop_wins_against_late_bootstrap_completion` using an injected/fake bootstrap future.
- [ ] `stop_aborts_existing_socks_streams` with a controlled local upstream fixture.
- [ ] `socks_listener_refuses_after_stop`.
- [ ] `no_client_is_installed_after_stopped_state`.
- [ ] live Tor test confirms a proxied stream works before stop and is unusable after stop.

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
- Create: `crates/secure-messaging/src/simplex/core.rs`
- Add build/FFI integration files required by the upstream SimpleX native core for Windows/Linux.
- Keep: `crates/secure-messaging/tests/live_simplex_chat.rs` as a CLI compatibility/integration harness, not the production secret-delivery path.

## Problem

The current CLI supports database encryption through `-k/--key`, but that necessarily places the database key in process arguments. The current source correctly documents this limitation. It is acceptable as an integration harness but not as the final production secret boundary for Secure.

Upstream SimpleX already exposes native core initialization with an in-memory database key (`chatMigrateInit` / `chat_migrate_init(dbPath, dbKey, confirm)` in its native API). Use that interface for the production adapter rather than inventing new crypto or trying to conceal an argv secret with cosmetic tricks.

## Work

- [ ] Add `SubkeyPurpose::MessagingDatabaseV1` to `secure-crypto` with a dedicated HKDF label such as `messaging-database-v1`.
- [ ] Derive the SimpleX database key from the random VMK, never directly from the human passphrase.
- [ ] Implement a production SimpleX core wrapper that passes the database key through the native API in memory.
- [ ] Keep key buffers in `Zeroizing`/equivalent secret containers and do not log/debug-format them.
- [ ] Ensure no production launch path places the messaging DB key in argv, environment variables, temporary files, or Tauri IPC.
- [ ] Make the existing CLI subprocess adapter explicitly integration-test/dev-only once the native path is usable.
- [ ] Package the required SimpleX native library artifacts under an auditable AGPL-compatible build/release process for Windows and Linux; do not download mutable binaries at application runtime.
- [ ] Record exact upstream version/commit and license provenance in release metadata.

## Required regression tests

- [ ] `messaging_database_subkey_is_domain_separated` proves it differs from DatabaseV1 and LocalConfigV1.
- [ ] native SimpleX store created with a generated key cannot be reopened with another key.
- [ ] raw SimpleX database files do not contain a planted plaintext message/profile marker.
- [ ] test process inspection confirms the production path exposes no messaging database key in command line or environment.
- [ ] lock drops the in-memory messaging DB key and closes the SimpleX store.

## Verification

```bash
cargo test -p secure-crypto --all-targets
cargo test -p secure-messaging --all-targets
cargo clippy -p secure-messaging --all-targets --all-features -- -D warnings
```

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

- [ ] Configure the SimpleX core network settings to the Secure-owned loopback SOCKS address using upstream `APISetNetworkConfig` (`/_network <json(networkConfig)>`) or the equivalent native API before allowing any user messaging operation.
- [ ] Read the network configuration back (`APIGetNetworkConfig` / `/network`) and fail startup if the effective proxy does not match the Secure-owned SOCKS listener.
- [ ] Refuse messaging startup unless Tor is `Ready` and the SOCKS bridge is active.
- [ ] Stop/fail messaging immediately if the bridge dies or transport leaves `Ready`.
- [ ] Add circuit isolation at the narrowest practical relationship boundary supported by the Arti/SOCKS/SimpleX combination; document exactly what is and is not isolated.
- [ ] Run a two-fresh-client test: bootstrap both over Tor, create invitation, accept, send message, receive message, verify delivery status.
- [ ] Run the same flow with the SOCKS bridge intentionally killed and prove there is no successful direct fallback.
- [ ] Add packet/DNS observation in a dedicated Linux integration environment to prove messaging destinations are not resolved or contacted directly by Secure/SimpleX outside the Tor path.

## Required tests

- [ ] two clients establish contact through one-time invitation over Secure's Tor path.
- [ ] message round-trip succeeds through Tor.
- [ ] killing SOCKS prevents delivery and does not produce direct relay connections.
- [ ] unsupported raw-IP SOCKS target remains rejected.
- [ ] restart with persisted encrypted SimpleX state restores the relationship without plaintext migration.

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

- [ ] Split the 80k+ desktop `main.rs` by responsibility before adding substantial messaging code; keep the Tauri command registration thin.
- [ ] On normal unlock, do not automatically make the application "messaging ready" until the full Tor + SOCKS + SimpleX sequence succeeds.
- [ ] Expose narrowly-scoped Tauri commands for invitation creation/acceptance, direct text send, and status; do not expose protocol JSON or secrets.
- [ ] Route typed `ChatEvent`s into encrypted vault records through typed storage APIs.
- [ ] Persist only the minimum metadata needed by the product.
- [ ] Lock must synchronously/awaitedly stop messaging and transport before dropping vault/key state.
- [ ] Burn Identity must use the same shutdown primitive before `PersistentKeyAccessDestroyed`.
- [ ] Normal runtime restart must restore encrypted protocol state and contact/message state deterministically.

## Ghost Session

- [ ] Give Ghost its own random RAM-only messaging database key.
- [ ] If SimpleX requires filesystem-backed databases, use a dedicated ephemeral encrypted store whose key is never persisted, then delete ciphertext best-effort on Ghost end/restart; do not pretend the OS cannot retain encrypted remnants.
- [ ] Ghost must never open the normal Secure vault or reuse its SimpleX database.
- [ ] No normal contact alias/draft/history write path is available while `AppState::Ghost`.

## Required tests

- [ ] unlock -> Tor -> SOCKS -> messaging-ready happy path.
- [ ] failure at each startup stage leaves messaging unavailable with no fallback.
- [ ] lock stops messaging before VMK drop.
- [ ] Burn Identity stops messaging before key-envelope destruction.
- [ ] restart restores normal encrypted messaging state.
- [ ] Ghost start/end/restart never populates the normal vault.

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
