#!/usr/bin/env python3
"""Print release provenance for the desktop build as JSON (docs/security-remediation-plan.md R8).

Records the exact versions of the security-critical third-party components that ship inside a
Secure release: Arti (Tor), rusqlite/libsqlite3-sys with the SQLCipher and SQLite versions it
bundles, and the pinned SimpleX Chat core (commit, version, GHC) built by
scripts/build-simplex-native.sh. The full dependency inventory is the CycloneDX SBOM; this file
is the short list a reviewer checks first.
"""
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "apps" / "desktop" / "src-tauri" / "Cargo.toml"
TRACKED = ("arti-client", "tor-proto", "rusqlite", "libsqlite3-sys", "rustls", "tauri", "chacha20poly1305", "argon2")


def cargo_metadata():
    out = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked", "--manifest-path", str(MANIFEST)],
        check=True, capture_output=True, text=True,
    ).stdout
    return json.loads(out)


def define(text, name):
    match = re.search(rf"#define {name}\s+\"?([^\"\s]+)\"?", text)
    return match.group(1) if match else None


def main():
    metadata = cargo_metadata()
    packages = {p["name"]: p for p in metadata["packages"]}
    crates = {name: packages[name]["version"] for name in TRACKED if name in packages}

    sqlcipher = {}
    sys_pkg = packages.get("libsqlite3-sys")
    if sys_pkg:
        amalgamation = pathlib.Path(sys_pkg["manifest_path"]).parent / "sqlcipher" / "sqlite3.c"
        if amalgamation.is_file():
            text = amalgamation.read_text(encoding="utf-8", errors="replace")
            sqlcipher = {
                "sqlcipher": define(text, "CIPHER_VERSION_NUMBER"),
                "sqlite": define(text, "SQLITE_VERSION"),
            }

    script = (ROOT / "scripts" / "build-simplex-native.sh").read_text(encoding="utf-8")
    simplex = {
        key.lower(): re.search(rf"^{key}=(\S+)", script, re.M).group(1)
        for key in ("SIMPLEX_CHAT_COMMIT", "SIMPLEX_CHAT_VERSION", "GHC_VERSION")
    }

    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True
    ).stdout.strip()

    json.dump(
        {"source_commit": commit, "crates": crates, "bundled_sqlcipher": sqlcipher, "simplex_native": simplex},
        sys.stdout,
        indent=2,
    )
    print()


if __name__ == "__main__":
    main()
