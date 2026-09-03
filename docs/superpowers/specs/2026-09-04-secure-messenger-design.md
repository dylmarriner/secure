# Secure Messenger Foundation Design

## Goal

Create the auditable foundation for a Windows/Linux private messenger with a narrow Tauri UI boundary, Rust-owned security state, Tor-only networking, encrypted local storage, pairwise identities, cryptographic destruction and Ghost Session support.

## First implementation slice

The first slice deliberately implements only security primitives we can test in isolation:

- application lifecycle/destruction ordering;
- random vault master key generation;
- Argon2id passphrase wrapping;
- authenticated versioned vault-key envelope;
- domain-separated local subkeys;
- minimal Tauri shell consuming the core API;
- CI gates for formatting, tests and clippy.

Messaging, Tor process management and SQLCipher integration remain subsequent implementation slices behind explicit interfaces. No fake protocol, fake Tor layer or pretend self-destruct implementation will be committed merely to make the tree look busy.

## Core invariants

- persistent key access must be invalidated before Burn Identity performs best-effort data cleanup;
- destroyed application state is terminal;
- the passphrase is not the vault master key;
- cryptographic envelopes are versioned and authenticated;
- purpose-specific keys are domain separated;
- no frontend-owned long-term keys;
- no claims of forensic invisibility or guaranteed remote deletion.

## Repository boundaries

- `secure-core`: state machines and security invariants;
- `secure-crypto`: local vault-key hierarchy only;
- `apps/desktop`: Tauri host and presentation layer;
- future `secure-vault`, `secure-transport`, `secure-messaging`, `secure-attachments` crates are added only when their first real behavior is implemented and tested.
