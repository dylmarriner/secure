# Secure Self-Destruct Semantics

## Status

This document defines mandatory product and security invariants for Secure. These requirements are not optional features, fallback modes, preferences, or future enhancements.

If another document conflicts with this one, the conflicting text must be corrected before implementation or release work proceeds.

## Canonical behavior

A successful **Burn / Self-Destruct** operation MUST permanently destroy the current Secure identity and all application-controlled cryptographic access to its protected local state, then MUST automatically provision a completely new and unrelated Secure identity in the same application installation.

The replacement identity MUST be created only after the old identity has crossed the irreversible cryptographic-destruction boundary.

```text
current identity
      |
      v
Burn / Self-Destruct requested
      |
      v
durably commit irreversible burn intent
      |
      v
seal UI and block new sensitive operations
      |
      v
terminate SimpleX/controller and active messaging streams
      |
      v
terminate Secure-owned SOCKS/Tor messaging paths
      |
      v
revoke runtime keys and secret handles
      |
      v
invalidate device-bound destruction / anti-rollback state
      |
      v
destroy old messaging-database key access
      |
      v
destroy old VMK / vault-envelope access
      |
      v
OLD IDENTITY IS CRYPTOGRAPHICALLY DEAD
      |
      v
mandatory best-effort cleanup of old encrypted state
      |
      v
complete and clear old burn journal
      |
      v
generate a new identity generation
      |
      v
fresh device-bound state + fresh VMK + fresh protocol identity
      |
      v
fresh empty Secure identity
```

## Mandatory invariants

### 1. Destruction completes before replacement begins

Secure MUST NOT generate or activate replacement identity state while any step capable of restoring the old identity remains incomplete.

A crash after Burn has been durably committed MUST never return Secure to the old identity's normal unlock flow.

### 2. Every cryptographic root is fresh

The replacement identity MUST receive newly generated cryptographic roots, including:

- fresh random vault master key;
- fresh device-bound destruction / anti-rollback state;
- fresh SimpleX/protocol identity;
- fresh messaging database key hierarchy;
- fresh contact/session state;
- fresh local-config subkeys;
- fresh future attachment keys;
- fresh identity generation/epoch.

No replacement key may be derived from an old identity key.

### 3. No identity-state inheritance

The replacement identity MUST NOT inherit:

- contacts;
- conversations;
- messages;
- drafts;
- invitations;
- protocol sessions;
- attachment keys;
- attachment metadata belonging to the old identity;
- contact aliases;
- safety-code/fingerprint verification state;
- failed-unlock counters;
- old identity generation/epoch;
- identifiers that allow a remote party to silently recognise the replacement as the destroyed identity.

Only explicitly classified installation-level, non-sensitive preferences may survive, and they MUST NOT permit recovery or correlation of the destroyed identity.

### 4. Old credentials become useless

After the destruction boundary, the old correct passphrase MUST NOT recover the destroyed identity.

If the same textual passphrase is chosen for the replacement identity, it MUST wrap completely fresh cryptographic material and MUST provide no path to the old identity.

### 5. Pre-burn application-state copies cannot resurrect the identity

Secure MUST be designed so that restoring a pre-burn copy of Secure's application-controlled data cannot restore the destroyed identity, even when the old correct passphrase is known.

Required test:

```text
1. create identity A and seed known data
2. copy the complete Secure application-data directory
3. Burn A
4. allow Secure to automatically create identity B
5. replace current application data with A's pre-burn copy
6. launch Secure
7. enter A's old correct passphrase
8. recovery of A MUST fail
9. rollback from B to A MUST fail
```

The anti-rollback/destruction secret needed to enforce this property MUST NOT exist solely inside the snapshot-able application-data directory.

### 6. Required security capability cannot silently downgrade

Secure MUST NOT silently fall back to a weaker mode that allows a requested destruction or anti-rollback invariant to become false.

If the supported platform cannot provide the device-bound / anti-rollback primitive required by Secure's production security model, Secure MUST fail closed for identity provisioning or clearly refuse the affected production mode. It MUST NOT present a weaker mode as equivalent security.

### 7. Burn intent is durable before irreversible work

Before any destructive step begins, Secure MUST durably record that Burn has been committed.

If the burn-intent record cannot be persisted durably, Burn MUST fail without beginning destruction.

Once that record exists, every restart MUST continue forward toward destruction. No restart may cancel or roll back the burn.

### 8. Replacement provisioning occurs after old burn completion

Replacement provisioning MUST occur only after the old burn has reached terminal completion and its destruction journal is safely completed/cleared.

If Secure crashes after the old identity is destroyed but before the replacement is fully provisioned, the old identity remains destroyed. On restart Secure MUST create a new fresh identity or resume fresh provisioning. It MUST NOT recover the old identity.

### 9. Failure after destruction never resurrects old state

If fresh-identity provisioning fails because of randomness, storage, hardware-key, process, or other failure:

- the old identity remains destroyed;
- no old envelope/session/database key is restored;
- restart resumes from a fresh-identity state;
- Secure never falls back to the old identity.

### 10. Cleanup is mandatory defence in depth

After destroying the relevant cryptographic keys, Secure MUST make a best-effort cleanup attempt over all old application-controlled encrypted state, including databases, attachments, caches, sidecars, migration files, protocol stores and destruction bookkeeping that no longer needs to persist.

A cleanup failure MUST NOT restore key access or make Burn reversible. Physical deletion is defence in depth; the security boundary remains destruction or invalidation of the key hierarchy required to interpret residual encrypted bytes.

### 11. Recipient copies are outside the local guarantee

Burn MUST destroy Secure-controlled local identity state. It cannot force deletion of data already copied by another participant or captured from live system memory outside Secure's control.

Any cooperative remote-delete request MUST be best-effort only and MUST never delay, cancel, or roll back local destruction.

## Automatic replacement is mandatory

For the normal Secure product flow, automatic replacement after Burn is mandatory.

There is no "replacement identity optional" interpretation of Self-Destruct.

After the old identity is irreversibly destroyed, Secure MUST immediately provision a fresh unrelated identity and return to a clean usable state.

A separate future operation with different semantics would require a separately named feature, threat model, implementation plan, and tests. It must not alter the definition of Self-Destruct above.

## UI requirements

Before Burn begins, the UI MUST state that:

- the current identity will be permanently destroyed;
- the operation cannot be undone;
- old contacts/history/session state will not survive;
- Secure will automatically create a fresh unrelated identity afterwards;
- the new identity will not restore the old identity's contacts/history;
- copies already held by other parties cannot be forcibly erased by the local application.

After replacement succeeds, the UI MUST present a clean new identity and MUST NOT surface old conversation tombstones or imply continuity with the destroyed identity.

## Mandatory verification

Release tests MUST include:

- old and new vault envelopes differ;
- replacement VMK differs from old VMK using test-only instrumentation;
- old correct passphrase cannot recover the destroyed identity;
- replacement contains no old contacts/messages/drafts/invitations/protocol state;
- replacement has a new identity epoch/generation;
- replacement has fresh SimpleX/protocol identity state;
- crash/restart at every Burn stage never restores the old identity after durable burn intent;
- crash after destruction but before replacement leaves the old identity destroyed and resumes only fresh provisioning;
- restoring a pre-burn application-data copy after replacement cannot recover or roll back to the old identity;
- mandatory best-effort cleanup is attempted over every registered old application-controlled persistence location;
- no supported production code path can recreate destroyed device-bound, VMK, messaging-database, attachment, or protocol secrets from residual application files.

## Relationship to other documents

This document is mandatory input to:

- `docs/security-architecture.md`
- `docs/implementation-plan.md`
- `docs/security-remediation-plan.md`
- `docs/backup-snapshot-hardening.md`

Any older text describing replacement identity as optional must be treated as stale and removed.