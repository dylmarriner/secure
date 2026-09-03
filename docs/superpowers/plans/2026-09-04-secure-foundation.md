# Secure Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first testable security foundation for the Secure Windows/Linux messenger.

**Architecture:** Keep the frontend unprivileged and put lifecycle, destruction ordering and local cryptographic key handling in isolated Rust crates. Introduce Tauri only after the core APIs are tested, and do not add messaging/Tor/storage adapters until they have real implementations.

**Tech Stack:** Rust 2024, Tauri 2, Argon2id, XChaCha20-Poly1305, HKDF-SHA-256, `zeroize`, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-09-04-secure-messenger-design.md`

## Global Constraints

- No bespoke messaging cryptographic protocol.
- No plaintext persistent message storage.
- No clearnet fallback when strict Tor transport is implemented.
- Passphrases wrap a random vault master key; they are not direct database keys.
- Burn Identity invalidates persistent key access before encrypted-data cleanup.
- No production secret logging.
- Do not claim forensic invisibility or guaranteed remote deletion.

---

### Task 1: Repository and CI baseline

**Files:** `Cargo.toml`, `rust-toolchain.toml`, `.github/workflows/ci.yml`, crate manifests, docs.

- [x] Create the Rust workspace and CI workflow.
- [x] Record the threat/security architecture and licensing gate.
- [x] Add failing lifecycle and vault-key tests before production implementation.

### Task 2: Lifecycle and destruction state machine

**Files:**
- Modify: `crates/secure-core/src/lib.rs`
- Test: `crates/secure-core/tests/lifecycle.rs`

**Produces:** `AppState`, `AppEvent`, `AppLifecycle`, `DestructionStage`, `DestructionEvent`.

- [ ] Run the tests and confirm they fail because the API does not exist.
- [ ] Implement explicit allowed state transitions.
- [ ] Reject destruction cleanup before `PersistentKeyAccessDestroyed`.
- [ ] Keep `Destroyed` terminal.
- [ ] Run tests, formatting and clippy.

### Task 3: Vault key envelope

**Files:**
- Modify: `crates/secure-crypto/src/lib.rs`
- Test: `crates/secure-crypto/tests/vault_keys.rs`

**Produces:** `VaultKey`, `Argon2Profile`, `VaultKeyEnvelope`, `SubkeyPurpose`.

- [ ] Run tests and confirm they fail because the API does not exist.
- [ ] Generate a 256-bit vault key with OS randomness.
- [ ] Derive a 256-bit wrapping key with Argon2id and per-envelope random salt.
- [ ] Encrypt the vault key with XChaCha20-Poly1305 and authenticate the envelope header as AAD.
- [ ] Implement explicit `SVK1` binary encoding/decoding.
- [ ] Derive database/config subkeys with HKDF-SHA-256 domain separation.
- [ ] Zero temporary wrapping and derived-key buffers where feasible.
- [ ] Run tests, formatting and clippy.

### Task 4: Minimal Tauri desktop shell

**Files:** `apps/desktop/ui/*`, `apps/desktop/src-tauri/*`, workspace CI additions.

**Consumes:** `secure-core::AppLifecycle`.

- [x] Add a static local-only frontend with no remote resources.
- [x] Add a Tauri host exposing only status and lock commands.
- [x] Keep all state mutation behind Rust IPC commands.
- [x] Add a restrictive Tauri capability configuration.
- [x] Add a desktop compile-check CI job with Linux Tauri prerequisites.
- [x] Add real application icons so the Tauri build actually produces a bundle (previously missing, blocking `tauri::generate_context!()`).
- [x] Add a matching desktop compile-check CI job for Windows.

### Task 5: Verification and review

- [x] Run workspace tests and clippy in CI.
- [x] Run the desktop compile check in CI (Linux and Windows).
- [ ] Inspect the branch diff for secrets, placeholders and accidental network functionality.
- [ ] Open a PR to `main` with security scope and known-next-slice items documented.
