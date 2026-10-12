# Secure Backup and Snapshot Hardening

## Status

This document defines mandatory security requirements for Secure. Snapshot/backup resistance requested by the product owner is not an optional tier, convenience feature, or best-effort substitute for the real destruction invariant.

Secure MUST NOT ship a supported production identity mode that allows a pre-burn copy of Secure's application-controlled data to resurrect a destroyed identity.

See `docs/self-destruct-semantics.md` for the canonical Burn / Self-Destruct behavior.

## Required security property

> After Burn / Self-Destruct completes, restoring any pre-burn copy of Secure's application-controlled persistent state MUST NOT restore the destroyed identity, even when the attacker knows the old correct passphrase.

Secure may be copied, imaged, snapshotted, or backed up by privileged software. The application cannot stop an administrator, hypervisor, kernel, filesystem, storage controller, or forensic tool from copying bytes. Secure therefore treats every such copy as a hostile archival copy and makes the copied bytes insufficient to recover a destroyed identity.

Residual ciphertext may remain in snapshots, disk images, cloud/device backups, filesystem history, storage-controller remapping, or other layers outside Secure's control. Those copies MUST remain useless without key material that Burn permanently invalidates.

---

# Threats in scope

Secure MUST account for:

- ordinary file backup tools copying the application data directory;
- cloud or roaming-profile backup of application data;
- copy-on-write filesystem snapshots;
- full-volume and full-disk images that do not include live RAM/device-secret state;
- backup software capturing files while Secure is locked or unlocked;
- stale copies of `vault.key`, `vault.db`, SimpleX databases, encrypted attachments, migrations, caches, temporary files, and configuration;
- a snapshot taken before Burn and inspected after Burn;
- an attacker learning the old passphrase after Burn;
- restoring an old application-data directory onto the same machine after Burn;
- attempting to roll the automatic replacement identity backward to the destroyed generation.

## Boundary outside an application-only guarantee

Secure cannot retroactively destroy an independent copy of an active secret that an attacker already captured outside Secure's persistent storage boundary, for example:

- RAM/process-memory capture while Secure is unlocked;
- VM snapshot containing guest RAM and the complete virtual-TPM/security-device state;
- kernel/debugger/EDR/administrator capture of active secret material;
- compromise of security hardware/firmware that exposes a supposedly non-exportable secret.

These limits MUST remain explicit. They do not weaken the mandatory disk/application-state rollback requirement above.

---

# Mandatory architecture

## 1. Backups are never identity recovery

Secure MUST NOT silently use system/cloud backup as identity recovery.

- No automatic cloud backup of identities, message databases, attachment keys, or recovery secrets.
- No roaming-profile sync of security-critical state.
- No application-managed remote backup by default.
- Any future explicit export MUST be a separate intentionally encrypted artifact with a separately approved threat model. It MUST NOT weaken Burn semantics.

## 2. Exclude Secure from ordinary backup/sync paths

For every supported production platform, Secure MUST use the strongest documented mechanism available to place or mark sensitive application state outside normal backup and roaming-sync scope.

This is defence in depth, not the core guarantee. A privileged backup product may ignore the exclusion, and the cryptographic design MUST remain secure when it does.

Release documentation MUST record:

- the sensitive application-data directory;
- the local/non-roaming placement used;
- backup-exclusion mechanisms applied;
- known mechanisms capable of ignoring the exclusion;
- release tests proving normal backup paths do not collect Secure state.

Secure MUST NOT disable unrelated OS backups, delete unrelated snapshots, tamper with restore points, or interfere with forensic/EDR systems.

## 3. Device-bound destruction secret is mandatory

The human passphrase and files inside Secure's application-data directory MUST NOT be sufficient to recover an identity after Burn.

Secure's production key hierarchy MUST include a device-bound destruction secret or equivalent non-exportable platform security primitive whose valid state is outside the normal snapshot-able application-data set.

Target construction:

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
                     reviewed key-wrapping/KDF design
                               |
                     random vault master key
                               |
        +----------------------+------------------+
        |                      |                  |
 Secure SQLCipher key   SimpleX DB key    local-config key
                                                   |
                                         attachment/session keys
```

The exact combining construction MUST use a reviewed standard KDF/wrapping design with explicit domain separation. Secure MUST NOT invent an ad-hoc cryptographic combiner.

## 4. No silent software-only downgrade

If Secure cannot establish the required device-bound destruction/anti-rollback primitive on a machine, it MUST fail closed for supported production identity provisioning.

It MUST NOT silently fall back to a mode where an old application-data snapshot plus the old passphrase can restore a burned identity.

Unsupported/development configurations may exist only if they are unmistakably non-production and cannot be mistaken for satisfying the Secure destruction guarantee.

## 5. Anti-rollback identity generation is mandatory

Each identity MUST have a device-bound generation/epoch that cannot be rolled backward merely by replacing the application-data directory.

```text
identity generation 41 -> active
Burn 41
41 -> permanently invalid
fresh replacement -> generation 42
```

On startup, application state whose generation is older than the device-bound valid generation MUST fail closed.

The anti-rollback marker MUST NOT live solely inside the same snapshot-able directory it protects.

## 6. No plaintext persistence

Secure MUST continue enforcing:

- SQLCipher for Secure vault state;
- encrypted SimpleX protocol databases;
- independently encrypted attachment objects;
- no plaintext drafts/history/contact/session secrets outside encrypted stores;
- no persistent plaintext thumbnails/previews by default;
- transactional attachment export;
- no long-term secret in argv, environment variables, logs, crash reports, WebView state, or analytics;
- zeroizing/locked secret memory where practical;
- destruction of runtime key material on lock and Burn.

If plaintext was persistently written before a snapshot, later key destruction cannot make that plaintext encrypted retroactively. Therefore plaintext-at-rest regressions are release blockers.

## 7. Migration/update copies remain under the destruction hierarchy

Every migration/update path MUST audit and control:

- `.bak`/old-database copies;
- SQLite/SQLCipher journals and sidecars;
- SimpleX migration backups;
- installer/updater rollback copies containing user data;
- crash-recovery files;
- temporary attachment conversions.

Any required migration backup MUST stay encrypted under key material revoked by Burn and MUST be removed after successful migration. A plaintext safety copy is forbidden.

## 8. Burn ordering includes rollback revocation

Required sequence:

```text
1. durably arm Burn / Self-Destruct
2. seal UI and block new sensitive operations
3. terminate SimpleX/controller and active messaging streams
4. terminate Secure-owned SOCKS/Tor messaging paths
5. revoke runtime attachment/session/database subkeys
6. permanently invalidate the old device-bound identity generation/destruction secret
7. destroy old messaging database key access
8. destroy old VMK / vault-envelope access
9. close encrypted stores
10. best-effort remove old encrypted databases, sidecars, attachments and caches
11. complete/clear old burn journal
12. generate a fresh device-bound identity generation
13. generate fresh VMK and protocol identity
14. return as the automatic clean replacement identity
```

The crash-recovery design MUST guarantee that once step 1 is durable, restart only moves forward. Once step 6 completes, no pre-burn application-data copy may become valid again.

## 9. Automatic replacement identity is part of the rollback model

Burn MUST automatically create a fresh unrelated identity after old destruction completes.

The replacement MUST have a newer valid device-bound generation. Restoring old files MUST NOT roll the replacement identity back to the destroyed generation.

Replacement is not optional in the canonical Self-Destruct flow.

---

# Mandatory verification

## Backup exclusion test

For each supported release platform:

1. create a populated Secure test identity;
2. run the normal supported desktop/OS backup path;
3. confirm Secure sensitive application state is excluded by the configured platform mechanism;
4. separately prove a privileged file copy can still copy encrypted bytes;
5. confirm the cryptographic rollback test below still succeeds when those bytes are restored.

## Pre-burn rollback test

This is a release-blocking test.

1. Create identity A and seed known messages/attachments.
2. Lock Secure.
3. Copy the entire application-controlled data directory.
4. Burn A completely.
5. Allow Secure to automatically create fresh identity B.
6. Restore A's copied application-data directory.
7. Launch Secure.
8. Enter A's original correct passphrase.
9. Assert A cannot be recovered.
10. Assert Secure cannot roll device-bound generation B back to A.
11. Assert no supported code path can recreate A's destroyed device-bound/VMK/protocol secrets from the restored files.

The same test MUST run after each material key-hierarchy, storage, installer, migration, or platform-security change.

## Crash/fault test

Crash or inject failure at every Burn boundary, especially immediately before/after device-bound generation invalidation and VMK destruction.

After durable Burn intent, no restart state may restore the old identity.

## Migration plaintext test

Plant unique known plaintext markers, perform every supported migration/update, then inspect all application-controlled files. The markers MUST NOT appear outside deliberately encrypted stores.

---

# Release gate

Secure is production-eligible on a platform only when that platform passes all of the following:

- device-bound non-exportable destruction/rollback primitive is available and used;
- identity generation cannot be rolled backward using only restored application data;
- ordinary backup/sync exclusion is configured and tested;
- pre-burn application-state restoration cannot recover a burned identity with the old correct passphrase;
- automatic fresh identity creation after Burn passes crash/fault tests;
- no plaintext persistence is detected;
- all relevant storage/migration copies remain under the destroyed key hierarchy.

Failure of any item blocks the supported production security mode. There is no weaker production tier presented as equivalent.

---

# Product wording

After the required release tests pass, Secure may state narrowly:

> Burn permanently revokes the local cryptographic identity and automatically creates a fresh unrelated identity. Restoring an old copy of Secure's application-controlled data does not restore a burned identity on supported Secure production platforms, because the old state also depends on device-bound anti-rollback key material invalidated by Burn.

Secure MUST NOT claim that privileged software is physically incapable of copying bytes, that live RAM compromise is impossible, or that another participant's independent copy can be forcibly erased.
## Implementation status (2026-10-12)

Implemented on Linux, pending independent review:

- `crates/secure-device`: each identity has a random 32-byte secret in a TPM 2.0 NV index (owner
  hierarchy, random handle in the owner range). The data directory stores only its locator
  (`vault.device`), never the secret.
- `crates/secure-crypto`: vault-key envelope format 2 wraps the vault key under
  `HKDF-SHA-256(salt = device secret, ikm = Argon2id(passphrase), info =
  "secure/vault-wrapping-key/v2")`. The format byte is authenticated, so a format-2 envelope
  cannot be relabelled to the passphrase-only format 1.
- Burn destroys the device secret (overwrite, then undefine) before shredding the envelope. If the
  TPM cannot be reached, the burn pauses before that stage is journalled and resumes on the next
  launch.
- Identity creation, and the upgrade of a legacy format-1 vault, fail closed without a usable TPM.
- Evidence: `restoring_a_pre_burn_copy_cannot_resurrect_the_burned_identity` and the other desktop
  tests use a simulated TPM held outside the data directory; `crates/secure-device/tests/tpm_nv.rs`
  exercises the real TPM code path against swtpm in CI.

Not covered (as stated above, and in `crates/secure-device/src/tpm.rs`): VM snapshots that include
virtual-TPM state, live compromise while unlocked, a physical TPM-bus interposer (the NV read uses
an unsalted session), and Windows, which has no backend yet and therefore refuses to provision.
