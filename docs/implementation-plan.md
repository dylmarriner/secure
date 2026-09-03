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

- finish Linux Tauri compile gate;
- add Windows Tauri compile gate;
- add required application icons/bundle resources;
- ensure all current CI gates pass on the PR head;
- close any review findings before merge.

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

## Tests

- wrong passphrase cannot produce a usable vault key;
- tampered key envelope fails authentication;
- wrong database key cannot open the vault;
- plaintext message content cannot be found in application-controlled storage after close;
- migrations preserve encrypted state;
- interrupted migrations either roll back safely or resume from a documented state;
- app cannot accidentally create a new plaintext database when encrypted open fails.

## Exit criteria

A clean install can create, lock, unlock, close and reopen an encrypted vault on Windows and Linux with no application-controlled plaintext message persistence.

---

# Phase 2 - Managed Tor transport

## Objective

Make network access security-enforcing rather than advisory.

## Work

- choose supported Tor integration strategy: managed bundled Tor process, Arti, or another mature implementation after platform review;
- start and supervise Tor from Rust;
- expose only narrowly scoped local proxy access to the messaging layer;
- prohibit WebView direct networking;
- prohibit direct DNS resolution for messaging destinations;
- implement bootstrap state, failure state and retry policy;
- implement strict-mode network state machine;
- ensure transport errors never fall back to clearnet;
- isolate unrelated circuits/transports where useful and supported;
- implement shutdown sequencing so sensitive network activity stops before lock/burn cleanup.

## Tests

- strict mode refuses messaging before Tor readiness;
- Tor process death immediately disables messaging transport;
- DNS leakage tests for supported network paths;
- explicit tests proving no clearnet fallback;
- restart recovery tests;
- firewall/proxy integration tests where practical in CI or dedicated integration runners.

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
