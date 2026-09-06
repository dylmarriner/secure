# Secure Backup and Snapshot Hardening

## Purpose

Secure must be designed so that ordinary backup, sync, filesystem-snapshot, and disk-image mechanisms do not create a second recoverable copy of sensitive application state that survives Burn Identity.

This is a security objective, not a claim that an unprivileged application can prevent the operating system, an administrator, a hypervisor, storage firmware, or a forensic acquisition tool from copying bytes. Secure must not claim that it is impossible to snapshot, image, clone, or back up the host.

The stronger and defensible requirement is:

> After the cryptographic-destruction boundary completes, a previously captured copy of Secure's application-controlled encrypted state must not be sufficient by itself to recover the destroyed identity. Secure must minimize participation in ordinary backup/sync systems, persist no plaintext message/session state, and make recovery of old ciphertext depend on secret material that is intentionally destroyed during Burn Identity.

Residual ciphertext may still exist in filesystem snapshots, volume images, cloud/device backups, storage-controller remapping, or other layers outside Secure's control. Those copies are treated as hostile archival copies and must remain useless without the destroyed key hierarchy.

---

# Security model

## Threats in scope

Secure must account for:

- ordinary file backup tools copying the application data directory;
- cloud/roaming profile backup of application data;
- filesystem snapshots such as copy-on-write snapshots;
- full-volume or full-disk images;
- backup software that captures files while Secure is locked or unlocked;
- stale copies of `vault.key`, `vault.db`, SimpleX databases, encrypted attachments, migration files, caches, temporary files, and configuration;
- a snapshot taken before Burn Identity and inspected after Burn Identity;
- an attacker obtaining the user's passphrase after Burn Identity;
- restoration of an old application-data directory onto the same machine after Burn Identity.

## Threats outside an application-only guarantee

Secure cannot guarantee protection when an attacker captured enough live system state to include the active decryption secrets, for example:

- RAM or process-memory capture while Secure was unlocked;
- a VM snapshot that includes guest RAM and virtual TPM/secure-hardware state;
- kernel, debugger, EDR, or administrator access capable of reading active process secrets;
- a backup/export explicitly created by the user that intentionally includes independent recovery key material;
- compromise of hardware or firmware that exposes a supposedly non-exportable device secret.

These limits must remain explicit in product and security documentation.

---

# Required architecture

## 1. Backups must never be the recovery mechanism

Secure must not silently use system/cloud backup as identity recovery.

- No automatic cloud backup of identities, message databases, attachment keys, or recovery secrets.
- No roaming-profile sync of security-critical state where the platform provides a non-roaming/local storage location.
- No application-managed remote backup by default.
- Any future explicit user export must be a separate, deliberately encrypted recovery artifact with its own threat model and must never be created automatically.

## 2. Best-effort platform backup exclusion

For every supported platform, Secure must use the strongest supported, documented mechanism to mark or place application-controlled sensitive data outside ordinary backup/sync scope where such a mechanism exists.

This is defence in depth only. A privileged backup product, administrator, filesystem snapshot, disk image, or hypervisor can ignore application preferences.

Release documentation must record, per platform:

- the application data directory used;
- whether it is local/non-roaming;
- which backup-exclusion mechanism is applied;
- which backup/snapshot mechanisms can ignore that exclusion;
- the test used to prove the normal backup path does not collect Secure data.

Secure must not disable operating-system backup services, tamper with unrelated snapshots, wipe system restore data, or attempt to evade forensic/EDR tooling. The security boundary is cryptographic, not hostile modification of the host.

## 3. Snapshot-resistant key hierarchy

A filesystem snapshot can preserve an old copy of the vault envelope. Therefore deleting only the current `vault.key` file is insufficient to make a *pre-burn snapshot* useless if that snapshot contains everything needed to unwrap the VMK.

Where supported, Secure must add a device-bound destruction secret that is not stored as recoverable plaintext inside the application data directory.

Target hierarchy:

```text
human passphrase
      |
   Argon2id
      |
passphrase wrapping key
      |
      +---------------------+
                            |
                device-bound destruction secret
                (prefer non-exportable hardware-backed key)
                            |
                  vault-unwrapping construction
                            |
                  random vault master key
                            |
        +-------------------+-------------------+
        |                   |                   |
 SQLCipher vault     SimpleX DB key      local config key
                                                |
                                      independent attachment keys
```

The exact composition must be cryptographically reviewed before implementation. Do not invent an ad-hoc combining primitive. Use a standard KDF/wrapping construction with explicit domain separation.

### Desired property

A copied `vault.key`/`vault.db` pair plus the human passphrase must not be sufficient to recover the vault after the device-bound destruction secret has been destroyed.

This is the main mechanism that makes old ordinary disk/file snapshots materially less useful after Burn Identity.

## 4. Hardware-backed secret where available

Prefer a non-exportable, machine-bound key held by supported platform security hardware/services.

Requirements:

- private key/secret material must not be exportable through Secure's normal API;
- application storage may contain only the public metadata/wrapped blob needed to ask the device security boundary to unwrap;
- Burn Identity destroys or invalidates the device-bound key before ordinary ciphertext cleanup is considered complete;
- restoring an old application-data snapshot after burn must fail because the old wrapped state still depends on the destroyed device key;
- Secure must detect and report when hardware-backed protection is unavailable rather than silently claiming the same snapshot-resistance level.

A software-only fallback may still provide strong encrypted-at-rest protection, but it must be labelled as a weaker snapshot-resistance tier.

Virtual machines require separate treatment because a VM snapshot can include virtual-TPM state. Secure must not claim hardware-backed snapshot resistance inside a VM unless the deployment architecture proves that the relevant hardware/secret state is outside the snapshot boundary.

## 5. Key epochs and anti-rollback state

Old snapshots must not be accepted merely because their files are internally valid.

Introduce a monotonic identity/key epoch tied to the device-bound security boundary where technically feasible:

```text
identity generation 41 -> active
Burn Identity
identity generation 41 -> permanently invalid
replacement identity -> generation 42
```

On startup, restoring an older application-data snapshot must fail closed if its cryptographic epoch is older than the device-bound current/invalidated state.

The anti-rollback marker must not live only inside the same snapshot-able directory it is intended to defeat. If the platform cannot provide a trustworthy monotonic/device-bound state source, document that rollback resistance is unavailable rather than pretending a local counter solves it.

## 6. No plaintext persistence

Snapshot resistance is impossible if plaintext was written before the snapshot was taken.

Secure must continue enforcing:

- SQLCipher for the Secure vault;
- encrypted SimpleX protocol databases;
- independent encrypted attachment objects;
- no plaintext drafts/history/contact secrets outside encrypted stores;
- no plaintext thumbnails or previews persisted by default;
- transactional attachment export, with temporary plaintext never becoming a durable application-cache artifact;
- no secrets in argv, environment variables, logs, crash reports, WebView state, or analytics;
- key material in zeroizing/locked memory where practical and destroyed on lock/burn.

## 7. Backup-safe update and migration behavior

Migrations and upgrades frequently create backup copies, which would defeat the entire policy with impressive efficiency.

Every migration path must be audited for:

- `.bak` or old-database copies;
- SQLite/SQLCipher journals, WAL/SHM files, migration sidecars, and temporary databases;
- SimpleX migration backups;
- installer/updater rollback copies containing application data;
- crash recovery files;
- attachment conversion temporary files.

If a migration backup is required, it must remain encrypted under the same destruction hierarchy and be removed best-effort after successful migration. A migration must never create a plaintext safety copy.

## 8. Burn Identity ordering

The burn sequence must treat snapshot-resistance keys as first-class destruction targets.

Target sequence:

```text
1. durably arm Burn Identity
2. seal UI and block all new sensitive operations
3. terminate SimpleX/controller and active messaging streams
4. terminate Secure-owned Tor/SOCKS paths
5. revoke runtime attachment/session/database subkeys
6. destroy/invalidate device-bound destruction secret and anti-rollback generation
7. destroy current VMK wrapping/envelope access
8. close encrypted stores
9. best-effort remove encrypted databases, sidecars, attachments and caches
10. reach terminal Destroyed state
```

The exact ordering between steps 6 and 7 must be chosen so a crash at either boundary can only resume forward and can never make an old snapshot valid again.

No cleanup failure after the cryptographic boundary may restore key access.

## 9. Burn Conversation

Where protocol semantics permit, per-conversation destruction should follow the same philosophy:

- freeze the relationship;
- destroy conversation/session-specific local secret material where available;
- destroy attachment keys;
- remove encrypted records;
- request cooperative remote deletion only as an optional best-effort action;
- never claim the recipient's copy can be forcibly erased.

If the messaging substrate does not expose a separately destroyable conversation key hierarchy, document that limitation rather than inventing one above the protocol.

---

# Verification requirements

## Backup exclusion tests

On Windows and Linux release candidates:

- run the normal supported OS/desktop backup path against a test profile and confirm Secure's sensitive data directory is excluded wherever the platform supports exclusion;
- verify a generic privileged file copy can still copy ciphertext, proving the design does not depend on magical file invisibility;
- document the exact observed behavior.

## Pre-burn snapshot recovery test

This is the critical test.

1. Create an identity and seed known messages/attachments.
2. Lock Secure.
3. Copy the entire application-controlled data directory as a simulated pre-burn snapshot.
4. Burn Identity completely.
5. Restore the copied directory.
6. Attempt unlock with the original correct passphrase.
7. Assert recovery fails because required device-bound destruction/epoch state no longer exists or is invalid.
8. Verify no supported Secure code path can recreate the destroyed key material from the restored files.

Run the same test with a replacement identity created after burn and confirm restoring the old snapshot cannot roll the replacement identity backward.

## Live-memory boundary test

Document separately that a snapshot containing live RAM or hardware/vTPM secret state is outside the disk-only guarantee. Do not let a passing disk-snapshot test become a broader claim than it proves.

## Migration test

Plant unique plaintext markers in test messages/attachment metadata, perform every supported database/application migration, and search all application-controlled files for those markers. None may appear outside encrypted stores.

---

# Release tiers

Secure should report the achieved local protection tier rather than pretending every machine provides identical guarantees.

### Tier A - hardware-backed snapshot resistance

- device-bound non-exportable destruction secret available;
- anti-rollback/epoch mechanism available;
- ordinary backups excluded where supported;
- old disk/file snapshots fail after burn even with the correct former passphrase;
- no plaintext persistence detected by release tests.

### Tier B - software-only cryptographic erasure

- encrypted stores and VMK destruction remain active;
- ordinary backups excluded where supported;
- no plaintext persistence detected;
- an old snapshot containing the wrapped VMK may remain recoverable if an attacker later obtains all wrapping material, so the UI/docs must not claim Tier A snapshot resistance.

---

# Product wording

Permitted wording after the relevant release tests pass:

> Secure minimizes participation in ordinary backup and sync systems and uses cryptographic key destruction so residual encrypted application data is not relied on being physically erased. On supported hardware, destroyed identities additionally depend on device-bound key material so restoring an old application-data snapshot does not restore access to the destroyed identity.

Do not use:

- "cannot be snapshotted";
- "cannot be backed up";
- "leaves no trace";
- "forensically unrecoverable under all circumstances";
- "guaranteed impossible to recover".

Those claims exceed what an application can prove on a general-purpose Windows or Linux host.
