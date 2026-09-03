# secure

Security-first private messenger for Windows and Linux.

Secure is being built around a narrow Tauri 2 UI boundary, a Rust security core, Tor-only networking, identifier-minimising messaging, encrypted local state, cryptographic destruction, and an ephemeral Ghost Session mode.

## License

Secure is free and open source under the [GNU Affero General Public License v3.0 or later](LICENSE) (AGPL-3.0-or-later). Secure is monetized through optional hosted services (managed relays, premium capacity, business/enterprise deployments, support) rather than through the client - self-hosting is fully supported, and there is no advertising or user-data monetization. See [`docs/licensing.md`](docs/licensing.md) for how this decision governs messaging-substrate integration.

## Security posture

This project does **not** claim to be untraceable, forensically invisible, or capable of guaranteed remote deletion. Its security goals are scoped to end-to-end encrypted communication, minimised identifiers, fail-closed Tor transport, encrypted application-controlled storage, and destruction of application-controlled cryptographic key material.

The repository is pre-release. Do not rely on it for high-risk communication until the relevant release has completed independent security review.

## Current foundation

Implemented so far (Phases 0-2 of the roadmap; see `docs/implementation-plan.md` for the
authoritative, continuously-updated status of each phase):

- explicit application lifecycle and destruction-order state machine (`secure-core`);
- random 256-bit vault master key generation, Argon2id passphrase-derived wrapping key,
  versioned authenticated `SVK1` vault-key envelope, XChaCha20-Poly1305 local key wrapping,
  HKDF-SHA-256 domain-separated database/config subkeys, zeroising and (for the vault master
  key specifically) memory-locked key buffers (`secure-crypto`);
- SQLCipher-backed encrypted vault persistence with versioned schema migrations
  (`secure-storage`);
- managed Tor transport embedding Arti, with a fail-closed, network-free-testable state machine
  (`secure-transport`);
- a Tauri 2 desktop host wiring the above into real onboarding/unlock/lock and Tor start/stop
  flows, with a local-only static frontend, restrictive CSP, and no direct frontend network
  functionality;
- CI format/test/clippy gates on Linux and Windows.

Not yet implemented:

- SimpleX-derived messaging integration behind the `secure-messaging` adapter boundary;
- attachment encryption/storage pipeline;
- actual Burn Conversation / Burn Identity I/O orchestration;
- Ghost Session storage runtime.

Those components will be added only as real tested slices rather than decorative placeholders.

## Implementation roadmap

The versioned engineering roadmap is in [`docs/implementation-plan.md`](docs/implementation-plan.md). It defines the implementation order, dependencies, security gates, tests and production-readiness criteria from the current foundation through encrypted storage, Tor, messaging, attachments, burn operations, Ghost Session, platform hardening and independent review.

The security model in [`docs/security-architecture.md`](docs/security-architecture.md) remains authoritative. If the roadmap and security architecture ever conflict, they must be deliberately reconciled rather than silently implementing whichever document is more convenient.

## Repository map

```text
apps/desktop/                  Tauri desktop shell
crates/secure-core/            lifecycle + destruction invariants
crates/secure-crypto/          local key hierarchy
crates/secure-storage/         encrypted vault persistence (SQLCipher)
crates/secure-transport/       managed Tor transport (Arti)
docs/security-architecture.md  security baseline
docs/implementation-plan.md    phased implementation roadmap
docs/licensing.md              messaging licensing decision (AGPLv3 client)
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

See `docs/security-architecture.md` for the threat model and security invariants, and `docs/implementation-plan.md` for the execution sequence and release gates.
