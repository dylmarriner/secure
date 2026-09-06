# secure

Security-first private messenger for Windows and Linux.

Secure is being built around a narrow Tauri 2 UI boundary, a Rust security core, Tor-only networking, identifier-minimising messaging, encrypted local state, cryptographic destruction, automatic fresh-identity replacement after Self-Destruct, and an ephemeral Ghost Session mode.

## License

Secure is free and open source under the [GNU Affero General Public License v3.0 or later](LICENSE) (AGPL-3.0-or-later). Secure is monetized through optional hosted services (managed relays, premium capacity, business/enterprise deployments, support) rather than through the client - self-hosting is fully supported, and there is no advertising or user-data monetization. See [`docs/licensing.md`](docs/licensing.md) for how this decision governs messaging-substrate integration.

## Security posture

This project does **not** claim to be untraceable, forensically invisible, or capable of guaranteed remote deletion. Its security goals are scoped to end-to-end encrypted communication, minimised identifiers, fail-closed Tor transport, encrypted application-controlled storage, and destruction of application-controlled cryptographic key material.

For Secure's canonical Burn / Self-Destruct operation, replacement is **not optional**: once the current identity crosses the irreversible cryptographic-destruction boundary, Secure must automatically create a completely fresh, unrelated identity. Old contacts, conversations, messages, protocol sessions, attachment keys, identifiers and identity generations must not carry forward. See [`docs/self-destruct-semantics.md`](docs/self-destruct-semantics.md).

Secure's production destruction model also requires rollback resistance: restoring a pre-burn copy of Secure's application-controlled data must not restore a burned identity, even with the old correct passphrase. This is enforced through device-bound destruction/anti-rollback state rather than pretending privileged software cannot copy bytes. See [`docs/backup-snapshot-hardening.md`](docs/backup-snapshot-hardening.md).

The repository is pre-release. Do not rely on it for high-risk communication until the relevant release has completed independent security review and the mandatory destruction/rollback release gates pass.

## Current foundation

Implemented so far (Phases 0-7 of the roadmap are in progress; see `docs/implementation-plan.md`
for the authoritative, continuously-updated per-phase status - most phases below are real but
partial, not finished):

- explicit application lifecycle and destruction-order state machine (`secure-core`);
- random 256-bit vault master key generation, Argon2id passphrase-derived wrapping key,
  versioned authenticated `SVK1` vault-key envelope, XChaCha20-Poly1305 local key wrapping,
  HKDF-SHA-256 domain-separated database/config subkeys, zeroising and (for the vault master
  key specifically) memory-locked key buffers (`secure-crypto`);
- SQLCipher-backed encrypted vault persistence with versioned schema migrations and
  crash-consistent Burn Conversation (`secure-storage`);
- managed Tor transport embedding Arti, with a fail-closed, network-free-testable state machine
  (`secure-transport`);
- a first-slice SimpleX messaging adapter behind a protocol-neutral boundary - bootstrap,
  invitations, plain-text messages, typed chat events - not yet wired into the desktop host
  (`secure-messaging`);
- independent per-attachment encryption keys and bounded-memory authenticated streaming
  encryption, not yet wired into a real ingest path (`secure-attachments`);
- a Tauri 2 desktop host wiring the above into real onboarding/unlock/lock, Tor start/stop,
  crash-consistent Burn Identity, brute-force lockout, replacement-identity primitives, and
  Ghost Session flows, with a local-only static frontend, restrictive CSP, and no direct
  frontend network functionality;
- CI format/test/clippy gates on Linux and Windows.

The current replacement-identity implementation is transitional: the product requirement is now the mandatory automatic flow defined in `docs/self-destruct-semantics.md`, and the implementation must be brought into exact alignment before production release.

Not yet implemented/completed:

- full mandatory automatic post-Burn replacement semantics and device-bound anti-rollback enforcement defined in `docs/self-destruct-semantics.md` and `docs/backup-snapshot-hardening.md`;
- `secure-messaging` wired into the desktop host through the fully verified fail-closed Tor path;
- `secure-attachments` wired into a real ingest path, and on-disk ciphertext cleanup integrated
  with burn (attachment *key* destruction at the database level is already part of Burn
  Conversation);
- Ghost Session's messaging-layer scope (memory-backed protocol state, disabling durable
  drafts/contact aliases) - not yet applicable until messaging is wired into the host.

Those components will be added only as real tested slices rather than decorative placeholders.

## Implementation roadmap

The versioned engineering roadmap is in [`docs/implementation-plan.md`](docs/implementation-plan.md). It defines the implementation order, dependencies, security gates, tests and production-readiness criteria from the current foundation through encrypted storage, Tor, messaging, attachments, burn operations, Ghost Session, platform hardening and independent review.

The active remediation roadmap is in [`docs/security-remediation-plan.md`](docs/security-remediation-plan.md).

Mandatory destruction and rollback semantics are defined in:

- [`docs/self-destruct-semantics.md`](docs/self-destruct-semantics.md)
- [`docs/backup-snapshot-hardening.md`](docs/backup-snapshot-hardening.md)

The security model in [`docs/security-architecture.md`](docs/security-architecture.md) remains authoritative except where newer mandatory product invariants in the two documents above deliberately tighten an older requirement. Any conflicting older text must be reconciled rather than treated as an alternative mode.

## Repository map

```text
apps/desktop/                        Tauri desktop shell
crates/secure-core/                  lifecycle + destruction invariants
crates/secure-crypto/                local key hierarchy
crates/secure-storage/               encrypted vault persistence (SQLCipher) + Burn Conversation
crates/secure-transport/             managed Tor transport (Arti)
crates/secure-messaging/             SimpleX messaging adapter
crates/secure-attachments/           encrypted attachment streaming primitives
docs/security-architecture.md        security baseline
docs/implementation-plan.md          phased implementation roadmap
docs/security-remediation-plan.md    active remediation roadmap
docs/self-destruct-semantics.md      mandatory Burn / automatic replacement semantics
docs/backup-snapshot-hardening.md    mandatory snapshot/rollback resistance requirements
docs/licensing.md                    messaging licensing decision (AGPLv3 client)
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

See `docs/security-architecture.md` for the threat model, `docs/implementation-plan.md` for the execution sequence, and the mandatory destruction documents above for the release-blocking Self-Destruct invariants.