# secure

Security-first private messenger for Windows and Linux.

Secure is being built around a narrow Tauri 2 UI boundary, a Rust security core, Tor-only networking, identifier-minimising messaging, encrypted local state, cryptographic destruction, and an ephemeral Ghost Session mode.

## Security posture

This project does **not** claim to be untraceable, forensically invisible, or capable of guaranteed remote deletion. Its security goals are scoped to end-to-end encrypted communication, minimised identifiers, fail-closed Tor transport, encrypted application-controlled storage, and destruction of application-controlled cryptographic key material.

The repository is pre-release. Do not rely on it for high-risk communication until the relevant release has completed independent security review.

## Current foundation

Implemented in the first slice:

- explicit application lifecycle and destruction-order state machine;
- terminal destroyed state;
- random 256-bit vault master key generation;
- Argon2id passphrase-derived wrapping key;
- versioned authenticated `SVK1` vault-key envelope;
- XChaCha20-Poly1305 local key wrapping;
- HKDF-SHA-256 domain-separated database/config subkeys;
- zeroising wrappers around local key buffers;
- minimal Tauri 2 desktop host with local-only static frontend;
- restrictive CSP and no direct frontend network functionality;
- CI format/test/clippy gates.

Not yet implemented:

- SimpleX-compatible messaging integration;
- managed Tor transport;
- SQLCipher vault persistence;
- attachment encryption/storage pipeline;
- actual Burn Conversation / Burn Identity I/O orchestration;
- Ghost Session storage runtime.

Those components will be added only as real tested slices rather than decorative placeholders.

## Repository map

```text
apps/desktop/                  Tauri desktop shell
crates/secure-core/            lifecycle + destruction invariants
crates/secure-crypto/          local key hierarchy
docs/security-architecture.md  security baseline
docs/licensing.md              messaging licensing gate
```

## Core checks

```bash
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Desktop host compile check on Linux:

```bash
cargo check --manifest-path apps/desktop/src-tauri/Cargo.toml
```

See `docs/security-architecture.md` for the threat model and security invariants.
