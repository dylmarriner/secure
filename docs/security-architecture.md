# Secure Messenger Security Architecture

## Verdict

Secure is a Windows/Linux private messenger designed around end-to-end encrypted communication, identifier minimisation, Tor-only transport, encrypted application-controlled storage and cryptographic destruction.

It does **not** claim to leave no forensic trace. The application can destroy application-controlled secrets, cryptographically erase access to encrypted state and remove its own encrypted files. It cannot reliably erase remnants created by SSD wear-levelling, swap/pagefile, hibernation, crash dumps, filesystem journals, backups, antivirus/EDR, search indexing, RAM acquisition or another person's device.

## Threat model

| Threat | Design position |
| --- | --- |
| Stolen disk / offline acquisition | Address strongly with encrypted vault + independently protected vault master key |
| Compromised relay | Content remains E2E encrypted; minimise relay-visible metadata |
| Passive network observer | Mitigate with mandatory Tor; traffic correlation remains possible |
| Contact/social-graph leakage | Pairwise relationships and no global account identifier |
| Logs / telemetry | No analytics; production secret logging prohibited |
| Forensics after burn | Cryptographic erasure of app-controlled keys first, file cleanup second |
| Malware / compromised endpoint | Out of scope; plaintext and keys can be captured while unlocked |
| RAM acquisition | Partially mitigate with short lifetimes, zeroisation and memory locking where practical |
| Screenshots / recipient copies | Cannot solve |
| Backups, swap, hibernation, dumps, journals, EDR, SSD remapping | Partially mitigate or document as outside app control |

## Security invariants

1. No persistent application-controlled plaintext message history.
2. Human passphrases do not directly become vault/database keys.
3. A random vault master key is protected by an Argon2id-derived wrapping key.
4. Database/config subkeys are domain-separated from the vault master key.
5. Attachment keys are independent and persist only inside the encrypted vault.
6. Strict mode never falls back from Tor to clearnet.
7. The WebView never receives long-term private cryptographic keys.
8. Successful Burn Identity invalidates persistent key access before bulk encrypted-data cleanup.
9. Remote deletion is never represented as enforceable.
10. No security claim depends on repeated overwriting of SSD blocks.
11. Persistent cryptographic formats are explicitly versioned.

## Layers

```text
Minimal desktop UI
        |
Tauri 2 capability + IPC boundary
        |
Rust security core
   |        |         |
identity  messaging  panic controller
   |        |         |
encrypted vault   Tor-only transport
   |
independently encrypted attachments
```

## Identity

No phone number, email, global username or searchable public directory. Local identities are cryptographically generated and contacts are established through one-time invitations/QR codes with out-of-band safety-code verification. Contact aliases are local encrypted metadata only.

## Messaging

The preferred v1 substrate is a SimpleX-style asynchronous relay architecture, integrated behind an adapter boundary. The project must resolve AGPL/commercial licensing before binding itself to upstream implementation code. No bespoke messaging cryptographic protocol will be created.

## Transport

Strict networking requirements:

- Tor required and fail-closed;
- no clearnet fallback;
- no local DNS leakage from messaging paths;
- no remote fonts, CDNs, analytics or telemetry;
- no automatic third-party image/media fetching;
- no automatic crash upload;
- no embedded third-party web resources;
- isolate unrelated transports where useful and supported.

Tor does not protect a compromised endpoint, recipient copies, identifying message content or all forms of global traffic correlation.

## Key hierarchy

```text
passphrase
   |
Argon2id
   |
passphrase wrapping key
   |
authenticated key envelope
   |
random 256-bit vault master key
   |--------------------|
HKDF database-v1   HKDF local-config-v1

Encrypted vault contains protocol identity/session secrets and per-attachment keys.
```

The vault master key is generated from operating-system CSPRNG output. Persistent key envelopes are versioned. Secret buffers are zeroised where feasible and memory locking is used where practical without pretending this defeats a hostile OS.

## Local storage

SQLCipher or an equivalently mature encrypted SQLite implementation is the target. Contacts, messages, drafts, ratchet/session state, aliases and attachment-key records live only in the encrypted vault. Attachment ciphertext uses random on-disk object names. Thumbnails are encrypted or generated transiently. Plaintext temporary files and application caches are prohibited by design.

External viewers are an explicit trust-boundary escape because they may create plaintext caches, recent-file entries or backups.

## Destruction semantics

### Lock

Obscure UI, stop sensitive networking, close vault access, drop plaintext caches and zero runtime key material where feasible. Persistent encrypted state remains recoverable by unlock.

### Burn Conversation

Destroy targeted pairwise/session secrets and attachment keys, remove targeted encrypted records and files, stop the connection, and treat local recovery as impossible by design. Remote deletion remains cooperative only.

### Burn Identity

Stop networking, revoke runtime access, atomically invalidate the vault-master-key envelope, persist destruction state, zero runtime keys, then best-effort remove encrypted database/sidecars/attachments/configuration. Key invalidation precedes cosmetic cleanup.

### Crash consistency

Destruction is a monotonic state machine. Once persistent key access is destroyed, restart may continue cleanup but must never recreate the old key envelope.

## Ghost Session

Ghost Session uses session-only identity and cryptographic material, no persistent contact state and no persistent history. Where a protocol implementation requires storage, use memory-only storage or an ephemeral encrypted store whose random key is never persisted. OS swap/pagefile, hibernation, dumps, EDR and screen capture remain outside guaranteed control.

## Claims

### We may make after implementation and audit

- end-to-end encrypted communication under the selected protocol;
- encrypted application-controlled local storage;
- application-controlled cryptographic key destruction;
- minimised account identifiers;
- Tor-only/fail-closed messaging transport in strict configuration;
- no application analytics telemetry.

### We must not make

- untraceable;
- forensically invisible;
- leaves no trace;
- guaranteed anonymous;
- guaranteed remote deletion;
- impossible to recover without a carefully scoped application-key statement.
