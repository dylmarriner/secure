# Release checklist

A Secure build may be published as a release - and may make any of the claims listed under
`docs/security-architecture.md#claims` - only when every box below is checked for the exact
release commit. Unchecked boxes are release blockers, not follow-ups. This list is the
operational form of `docs/security-remediation-plan.md` Phase R9's production exit criteria.

## 1. Automated gates (must be green on the release commit)

- [ ] `CI` workflow: `Rust core (ubuntu-latest)`, `Rust core (windows-latest)`,
      `Tauri desktop tests (Linux)`, `Tauri desktop tests (Windows)`,
      `TPM 2.0 device-secret backend (swtpm)`,
      `Supply chain (cargo-deny, SBOM, release metadata)`, and
      `Security remediation gate (docs/security-remediation-plan.md)`.
- [ ] `Integration security (live Tor)` workflow run on the release commit (manual dispatch).
- [ ] `release-evidence` artifact from the release commit's CI run attached to the release:
      the CycloneDX SBOM of the desktop host and `release-metadata.json` (Arti, bundled
      SQLCipher/SQLite, pinned SimpleX commit/version/GHC).
- [ ] Every `deny.toml` advisory exception re-reviewed; each still has a written reason that
      holds for the shipped versions.

## 2. Repository protection (GitHub settings, done once and kept on)

- [ ] `main` protected by a ruleset: no direct pushes, no force pushes, pull request required,
      at least one approving review.
- [ ] All seven `CI` checks in section 1 marked as **required** status checks.
- [ ] GitHub Actions billing/spending limit healthy - CI that cannot start is treated as red.

## 3. Evidence that needs real infrastructure (cannot be produced by unit tests)

- [ ] Two fresh clients over Tor using the release's `simplex-native` build: invitation,
      accept, message round trip, delivery status (R4).
- [ ] Same flow with the SOCKS bridge killed: no delivery and no direct relay connection (R4).
- [ ] Packet/DNS capture on a dedicated Linux host: no messaging destination resolved or
      contacted outside Tor, including on relaunch with existing contacts (R4/R9).
- [ ] Fresh install, upgrade/migration, lock/unlock (twice, without restarting), Tor failure,
      offline delivery, Burn Conversation, Burn Identity with replacement, Ghost start/end, and
      attachment export exercised on real Windows and Linux machines (R9).
- [ ] Crash/power-loss injection across every Burn Conversation and Burn Identity stage on real
      hardware (R9).
- [ ] Installer/uninstaller behaviour and application-data locations verified (R9).
- [ ] Production logs, panic paths, crash reports, temp files, clipboard, notifications and OS
      integrations audited for secret/metadata leakage (R9).
- [ ] Arti's documented `process::exit(1)` obsolete-client behaviour reviewed for the shipped
      Arti version and dispositioned (R9).

## 4. Device-bound anti-rollback and Burn replacement

- [x] Device-bound destruction secret (`docs/backup-snapshot-hardening.md`) on Linux: TPM 2.0 NV
      index, destroyed by Burn; `restoring_a_pre_burn_copy_cannot_resurrect_the_burned_identity`
      passes and the TPM path is tested against swtpm in CI.
- [ ] The same on Windows (TPM via TBS/NCrypt). Until then Windows builds fail closed and must not
      be released as supported.
- [ ] Verified on real TPM hardware (not only swtpm) on each supported Linux target, including
      `/dev/tpmrm0` permissions and a TPM whose owner authorization is set (must fail closed).
- [x] After Burn, Secure returns to fresh provisioning, or straight to the replacement identity
      when one was supplied (`docs/self-destruct-semantics.md`).

## 5. Independent review

- [ ] Third-party security review of the key hierarchy, SQLCipher use, destruction semantics,
      SimpleX integration, Tor fail-closed behaviour, the FFI boundary, and the update/supply
      chain path.
- [ ] All critical/high findings resolved; every medium finding explicitly dispositioned in
      writing.

## Claims

Only after sections 1-5 are complete may a release use the "Permitted after implementation and
independent review" claims in `docs/security-architecture.md`. The "Not permitted" claims are
never permitted. The README's pre-release warning stays until then.
