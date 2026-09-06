# Secure Messenger Security Architecture

## Verdict

Secure is a Windows/Linux private messenger designed around end-to-end encrypted communication, identifier minimisation, Tor-only transport, encrypted application-controlled storage, mandatory rollback-resistant cryptographic destruction, automatic fresh-identity replacement after Self-Destruct, and an ephemeral Ghost Session mode.

Secure does **not** claim that privileged software is physically incapable of copying bytes or that another participant's copy can be forcibly erased. Instead, Secure's production security model requires that restoring pre-burn application-controlled state cannot resurrect a destroyed identity.

The canonical Self-Destruct semantics are defined in `docs/self-destruct-semantics.md`. Mandatory backup/snapshot rollback requirements are defined in `docs/backup-snapshot-hardening.md`. These requirements are release gates, not optional hardening tiers.

## Threat model

| Threat | Design position |
| --- | --- |
| Stolen disk / offline acquisition | Address strongly with encrypted vault, VMK, and device-bound destruction/anti-rollback state |
| Restored pre-burn application-data copy | Must not recover a burned identity, even with the old correct passphrase |
| Compromised relay | Content remains E2E encrypted; minimise relay-visible metadata |
| Passive network observer | Mitigate with mandatory Tor; traffic correlation remains possible |
| Contact/social-graph leakage | Pairwise relationships and no global account identifier |
| Logs / telemetry | No analytics; production secret logging prohibited |
| Forensics after burn | Cryptographic erasure of app-controlled keys and device-bound rollback state first, file cleanup second |
| Malware / compromised endpoint | Out of scope; plaintext and keys can be captured while unlocked |
| RAM acquisition | Partially mitigate with short lifetimes, zeroisation and memory locking where practical |
| Screenshots / recipient copies | Cannot solve locally |
| Backups / filesystem snapshots | Bytes may be copied, but copied application state must not resurrect a burned identity |
| VM snapshot containing RAM/vTPM state | Outside the disk-only rollback guarantee unless the deployment proves the required secret state remains outside the VM snapshot boundary |

## Security invariants

1. No persistent application-controlled plaintext message history.
2. Human passphrases do not directly become vault/database keys.
3. A random vault master key is protected through a reviewed passphrase + device-bound key hierarchy.
4. Database/config/messaging subkeys are domain-separated from the vault master key.
5. Attachment keys are independent and persist only inside protected encrypted state.
6. Strict mode never falls back from Tor to clearnet.
7. The WebView never receives long-term private cryptographic keys.
8. Burn / Self-Destruct is irreversible once durably committed.
9. Burn invalidates device-bound anti-rollback/destruction state and old VMK access before bulk encrypted-data cleanup.
10. After Burn, restoring a pre-burn copy of Secure's application-controlled persistent state cannot recover the destroyed identity on supported production platforms.
11. Burn automatically provisions a completely fresh and unrelated identity after old destruction reaches its terminal boundary.
12. Replacement identities never inherit old contacts, conversations, messages, drafts, invitations, protocol sessions, attachment keys, verification state, or identity epoch.
13. Remote deletion is never represented as enforceable.
14. No security claim depends on repeated overwriting of SSD blocks.
15. Persistent cryptographic formats are explicitly versioned.
16. Requested production security invariants do not silently downgrade to weaker fallback modes.

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
   |
device-bound destruction / anti-rollback boundary
```

## Identity

No phone number, email, global username or searchable public directory. Local identities are cryptographically generated and contacts are established through one-time invitations/QR codes with out-of-band safety-code verification. Contact aliases are local encrypted metadata only.

Each production identity also has device-bound destruction/anti-rollback state that is not recoverable solely from the normal application-data directory. This state prevents an old disk/application snapshot from rolling Secure backward to a burned identity.

## Messaging

The v1 substrate is SimpleX, integrated behind a protocol-neutral adapter boundary. Secure itself ships under AGPL-3.0-or-later; the SimpleX licensing gate is resolved in `docs/licensing.md`.

No bespoke messaging cryptographic protocol will be created.

The production messaging path must use encrypted protocol state and mandatory Secure-controlled Tor routing. A development/integration path that exposes secrets or clearnet capability cannot be treated as the production path.

## Transport

Strict networking requirements:

- Tor required and fail-closed;
- no clearnet fallback;
- no local DNS leakage from messaging paths;
- no remote fonts, CDNs, analytics or telemetry;
- no automatic third-party image/media fetching;
- no automatic crash upload;
- no embedded third-party web resources;
- isolate unrelated transports where practical without weakening correctness;
- Burn must terminate Secure-owned active messaging transport before old identity key destruction proceeds.

Tor does not protect a compromised endpoint, recipient copies, identifying message content or all forms of global traffic correlation.

## Key hierarchy

Target production hierarchy:

```text
human passphrase
      |
   Argon2id
      |
passphrase-derived wrapping input
      |
      +------------------------+
                               |
                  device-bound destruction secret
                  non-exportable / platform protected
                               |
                     reviewed key wrapping / KDF
                               |
                     random vault master key
                               |
        +----------------------+------------------+
        |                      |                  |
 HKDF database-v1   HKDF messaging-db-v1  HKDF local-config-v1
        |
 encrypted vault contains protected identity metadata,
 contact state, attachment keys and other local secrets
```

The exact passphrase/device-secret composition must use a reviewed standard construction with explicit domain separation. Secure must not invent an ad-hoc cryptographic combiner.

The vault master key is generated from operating-system CSPRNG output. Secret buffers are zeroised where feasible and memory locking is used where practical without pretending this defeats a hostile OS.

## Local storage

SQLCipher or an equivalently mature encrypted SQLite implementation protects Secure vault state. SimpleX protocol databases must also be encrypted under VMK-derived, domain-separated key material.

Contacts, messages, drafts, aliases, protocol state and attachment-key records live only in encrypted stores. Attachment ciphertext uses random on-disk object names. Thumbnails are encrypted or generated transiently. Plaintext temporary files and application caches are prohibited by design.

External viewers are an explicit trust-boundary escape because they may create plaintext caches, recent-file entries or backups.

## Backup and rollback resistance

Secure must exclude sensitive application state from ordinary backup/roaming paths using the strongest documented platform mechanism available, but the security guarantee cannot depend on those exclusions being obeyed.

A privileged copy of the application-data directory is assumed possible.

Therefore production identity recovery must require device-bound state that Burn invalidates and that is not restored merely by copying old application files back into place.

If a supported production platform cannot provide the required destruction/anti-rollback primitive, Secure must fail closed for production identity provisioning rather than silently degrading the requested invariant.

## Destruction semantics

### Lock

Obscure UI, stop sensitive networking, close vault access, drop plaintext caches and zero runtime key material where feasible. Persistent encrypted state remains recoverable by normal unlock.

### Burn Conversation

Destroy targeted local relationship/session secrets where the protocol exposes them, destroy attachment keys, remove targeted encrypted records/files, stop the relationship, and treat local recovery as impossible by design. Remote deletion remains cooperative only.

### Burn / Self-Destruct

Burn is application-wide irreversible identity destruction followed by mandatory automatic creation of a fresh unrelated identity.

Required high-level order:

```text
1. durably commit burn intent
2. seal UI / block new sensitive work
3. terminate SimpleX/controller and active messaging streams
4. terminate Secure-owned SOCKS/Tor messaging path
5. revoke runtime secret handles
6. permanently invalidate old device-bound identity generation/destruction state
7. destroy old messaging database key access
8. destroy old VMK / envelope access
9. close old encrypted stores
10. best-effort remove old encrypted files/caches/sidecars
11. complete and clear old destruction journal
12. generate new device-bound identity generation
13. generate fresh VMK, messaging identity and all new subkeys
14. return to a clean replacement identity
```

Replacement is not optional in the canonical Self-Destruct flow.

The replacement identity must share no cryptographic identity state or messaging relationships with the destroyed identity.

### Crash consistency

Destruction is a monotonic state machine.

If durable burn intent cannot be written, destruction must not begin.

Once durable burn intent exists, restart only moves forward. A crash may delay cleanup or replacement provisioning, but must never restore the old identity.

After the old cryptographic boundary is crossed, failure to create the replacement identity leaves the old identity destroyed and restart may only create/resume a fresh identity.

## Ghost Session

Ghost Session uses session-only identity and cryptographic material, no persistent contact state and no persistent history. Where a protocol implementation requires storage, use memory-only storage or an ephemeral encrypted store whose random key is never persisted. OS swap/pagefile, hibernation, dumps, EDR and screen capture remain outside guaranteed control.

## Mandatory release validation

A production release must include tests proving:

- the old correct passphrase cannot recover a burned identity;
- automatic replacement uses fresh cryptographic roots and fresh identity generation;
- no old contacts/history/protocol state appear in the replacement identity;
- restoring a pre-burn application-data copy cannot recover or roll back to the burned identity;
- crash/restart after durable burn intent never returns to the old identity;
- messaging remains fail-closed through Tor;
- no application-controlled plaintext message/session state is persisted;
- all Linux and Windows release/security gates pass.

## Claims

### Permitted after implementation and independent review

- end-to-end encrypted communication under the selected protocol;
- encrypted application-controlled local storage;
- mandatory Tor-only/fail-closed messaging transport;
- application-controlled cryptographic key destruction;
- automatic fresh unrelated identity creation after Self-Destruct;
- on supported Secure production platforms, restoring old application-controlled state does not restore a burned identity;
- minimised account identifiers;
- no application analytics telemetry.

### Not permitted

- untraceable;
- forensically invisible;
- leaves no trace;
- guaranteed anonymous;
- guaranteed deletion of another participant's copies;
- physically impossible for privileged software to snapshot/copy bytes;
- impossible to recover from a live-memory/vTPM snapshot that already captured the active secrets.