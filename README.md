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

Implemented so far (see `docs/security-remediation-plan.md` for the authoritative per-item status;
CI's `remediation-gate` fails if a checked item there cites code that does not exist):

- explicit application lifecycle and destruction-order state machine (`secure-core`);
- random 256-bit vault master key generation, Argon2id passphrase-derived wrapping key,
  versioned authenticated `SVK1` vault-key envelope, XChaCha20-Poly1305 local key wrapping,
  HKDF-SHA-256 domain-separated database/config/messaging subkeys, zeroising and (for the vault
  master key specifically) memory-locked key buffers (`secure-crypto`);
- SQLCipher-backed encrypted vault persistence with versioned schema migrations and
  crash-consistent Burn Conversation, including a durable queue of attachment ciphertext to
  delete after their keys are destroyed (`secure-storage`);
- managed Tor transport embedding Arti, with a fail-closed lifecycle and a loopback SOCKS5
  bridge that isolates circuits per SOCKS credential and whose shutdown cannot be stalled by a
  silent client (`secure-transport`);
- a SimpleX messaging adapter behind a protocol-neutral boundary: a production native-core path
  (`simplex-native` feature, key passed in memory, network configured and verified *before* the
  chat starts, per-connection circuit isolation) and a dev-only CLI harness; bounded command
  correlation, WebSocket size limits and validated contact links (`secure-messaging`);
- per-attachment random keys, bounded-memory authenticated streaming encryption, an opaque
  on-disk object store and transactional (authenticate-then-publish) plaintext export
  (`secure-attachments`);
- a Tauri 2 desktop host wiring the above into onboarding/unlock/lock, Tor start/stop,
  messaging start behind the native feature, crash-consistent Burn Identity that fails closed if
  its journal cannot be written, brute-force lockout, replacement-identity primitives, Ghost
  Session, and post-burn cleanup of the SimpleX store and attachment objects; a local-only static
  frontend with a restrictive CSP and no direct frontend network functionality;
- device-bound anti-rollback (`secure-device`): each identity's vault-key envelope is also bound
  to a random secret held in a TPM 2.0 NV index outside the data directory, and Burn destroys it,
  so a restored pre-burn copy of the data directory cannot be reopened even with the old
  passphrase. Linux only so far; see "Platform requirements" below;
- CI on Linux and Windows: format, tests (core and desktop), clippy in both feature modes,
  cargo-deny, a CycloneDX SBOM and release metadata, with every action pinned to a commit SHA.

Not yet implemented/completed (all release blockers - see `docs/release-checklist.md`):

- a Windows device-bound backend (TPM via TBS/NCrypt). Until it exists, Windows builds refuse to
  create or open an identity rather than fall back to passphrase-only protection;
- independent review of the device-binding construction (`docs/backup-snapshot-hardening.md`);
- live two-client SimpleX-over-Tor verification, kill-the-bridge and packet-capture evidence
  (these need the native core built from source and dedicated hosts);
- SimpleX attachment transport and any UI for conversations or attachments;
- real-hardware Windows/Linux validation and an independent security review.

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
crates/secure-device/                device-bound (TPM 2.0) destruction secrets
docs/security-architecture.md        security baseline
docs/implementation-plan.md          phased implementation roadmap
docs/security-remediation-plan.md    active remediation roadmap
docs/self-destruct-semantics.md      mandatory Burn / automatic replacement semantics
docs/backup-snapshot-hardening.md    mandatory snapshot/rollback resistance requirements
docs/release-checklist.md            what must be true before any release or security claim
docs/licensing.md                    messaging licensing decision (AGPLv3 client)
```

## Platform requirements

Secure refuses to create an identity unless it can bind it to device storage outside its data
directory (`docs/self-destruct-semantics.md` invariant 6 - no silent downgrade):

- **Linux:** a TPM 2.0 reachable at `/dev/tpmrm0` (usually: be a member of the `tss` group) with
  the default empty owner authorization, and the `tpm2-tss` runtime libraries
  (`libtss2-esys`, `libtss2-tctildr`). Building needs `libtss2-dev`.
  `SECURE_TPM_TCTI` overrides the TPM connection (e.g. `swtpm:host=127.0.0.1,port=2321`).
- **Windows:** not supported yet - identity creation fails closed until a Windows TPM backend
  lands.

## Core checks

These are what CI runs; run them before pushing.

```bash
cargo fmt --all -- --check
cargo test --locked --workspace --all-targets
# --all-features includes `simplex-native`; check-only mode lints it without the native library.
SECURE_SIMPLEX_NATIVE_CHECK_ONLY=1 cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
python3 scripts/check-plan-claims.py
```

TPM backend against a software TPM (`swtpm`):

```bash
swtpm socket --tpm2 --tpmstate dir=/tmp/tpm --server type=tcp,port=2321 \
  --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --daemon
SECURE_TPM_TCTI=swtpm:host=127.0.0.1,port=2321 \
  cargo test --locked -p secure-device --features tpm -- --include-ignored
```

Desktop host (Linux needs the Tauri system packages and `libtss2-dev` listed in `.github/workflows/ci.yml`):

```bash
cargo test --locked --manifest-path apps/desktop/src-tauri/Cargo.toml
cargo clippy --locked --manifest-path apps/desktop/src-tauri/Cargo.toml --all-targets -- -D warnings
```

Supply chain (with `cargo-deny` installed):

```bash
cargo deny --manifest-path Cargo.toml --config deny.toml check
cargo deny --manifest-path apps/desktop/src-tauri/Cargo.toml --config deny.toml check
```

See `docs/security-architecture.md` for the threat model, `docs/implementation-plan.md` for the execution sequence, and the mandatory destruction documents above for the release-blocking Self-Destruct invariants.