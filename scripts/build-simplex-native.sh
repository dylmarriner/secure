#!/usr/bin/env bash
# Reproducibly builds upstream simplex-chat's native core as a shared library, from source, for
# linking into secure-messaging's `simplex-native` feature (see
# crates/secure-messaging/src/simplex/core.rs and docs/security-remediation-plan.md Phase R3).
#
# This deliberately builds from a pinned upstream git commit rather than downloading a prebuilt
# binary artifact: the remediation plan requires an auditable build process, and a downloaded
# `.so`/`.dll` cannot be audited the way source + a pinned commit + a documented build recipe can.
#
# Requires: GHC 9.6.3 and cabal (matching upstream's own scripts/desktop/build-lib-linux.sh -
# install via https://www.haskell.org/ghcup/), git, and the system libraries simplex-chat's cabal
# packages link against: libsodium-dev, libsqlcipher-dev, libgmp-dev, libncurses-dev, zlib1g-dev,
# libffi-dev, pkg-config, patchelf.
#
# Usage: scripts/build-simplex-native.sh [output_dir]
# Output: <output_dir>/libsimplex.so plus <output_dir>/deps/*.so (its GHC-runtime dependencies).
# Point crates/secure-messaging's build at it with:
#   SECURE_SIMPLEX_NATIVE_LIB_DIR=<output_dir> cargo build -p secure-messaging --features simplex-native

set -euo pipefail

# Exact upstream commit this script and crates/secure-messaging/src/simplex/core.rs were verified
# against - tagged version 7.0.0.12, AGPLv3. Update all three together; core.rs's FFI signatures
# are hand-written against this commit's src/Simplex/Chat/Mobile.hs, not machine-generated, so an
# upstream API change here needs a matching review of core.rs, not just a tag bump.
SIMPLEX_CHAT_COMMIT=4df04bdb3ff94059734ad2da7d2766de6dba2cc7
SIMPLEX_CHAT_VERSION=7.0.0.12
GHC_VERSION=9.6.3

output_dir="$(cd "$(dirname "${1:-./target/simplex-native}")" 2>/dev/null && pwd || mkdir -p "${1:-./target/simplex-native}" && cd "${1:-./target/simplex-native}" && pwd)"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

echo "Cloning simplex-chat @ $SIMPLEX_CHAT_COMMIT into $work_dir"
git clone --quiet https://github.com/simplex-chat/simplex-chat.git "$work_dir/simplex-chat"
git -C "$work_dir/simplex-chat" checkout --quiet "$SIMPLEX_CHAT_COMMIT"

actual_version="$(grep -m1 '^version:' "$work_dir/simplex-chat/simplex-chat.cabal" | awk '{print $2}')"
if [ "$actual_version" != "$SIMPLEX_CHAT_VERSION" ]; then
  echo "error: checked-out commit is version $actual_version, expected $SIMPLEX_CHAT_VERSION" >&2
  exit 1
fi

cd "$work_dir/simplex-chat"

# `direct-sqlcipher`'s own `-DSQLITE_HAS_CODEC` (the #define that turns encryption on at all in
# its bundled sqlite3 amalgamation) is gated behind its `commoncrypto`/`openssl`/`tomcrypt` cabal
# flags, all `default: False` - so without this, the build below silently succeeds and produces
# a fully functional but *entirely unencrypted* SQLite library: `chat_migrate_init_key` accepts
# any key (including the wrong one for an existing store) and the `.db` files on disk are plain
# SQLite, not SQLCipher, with no error anywhere to say so. Found by actually running the
# regression tests in crates/secure-messaging/src/simplex/core.rs against a first build of this
# script that omitted this - not documented anywhere in upstream's own build script snippet,
# only in its CI workflow (`.github/workflows/build.yml`, "Build library" step). `openssl` here
# matches that CI job and this repo's own OpenSSL-backed crypto elsewhere (see
# `crates/secure-transport`'s "ring vs aws-lc-rs" note for why OpenSSL over the platform-specific
# alternatives is already this project's default assumption).
echo "ignore-project: False" >> cabal.project.local
echo "package direct-sqlcipher" >> cabal.project.local
echo "    flags: +openssl" >> cabal.project.local

echo "Building lib:simplex-chat (sqlite/sqlcipher backend, +client_library) - this takes a while"
cabal build lib:simplex-chat \
  --ghc-options='-optl-Wl,-soname,libsimplex.so -flink-rts -threaded' \
  --constraint 'simplexmq +client_library' \
  --constraint 'simplex-chat +client_library'

build_dir="$(find dist-newstyle/build/*/ghc-${GHC_VERSION}/simplex-chat-* -maxdepth 0 -type d)/build"
cd "$build_dir"
cp "libHSsimplex-chat-${SIMPLEX_CHAT_VERSION}-inplace-ghc${GHC_VERSION}.so" libsimplex.so

# GitHub's Ubuntu 20.04 CI runner ships libffi.so.7 while most current systems (and this one) only
# have libffi.so.8; both are ABI-compatible for the symbols GHC's RTS uses. Matches upstream's own
# scripts/desktop/build-lib-linux.sh.
patchelf --replace-needed "libffi.so.7" "libffi.so.8" libsimplex.so || true

mkdir -p deps
ldd libsimplex.so | grep "ghc" | awk '{print $3}' | xargs -I{} cp {} ./deps/

cp libsimplex.so "$output_dir/"
rm -rf "$output_dir/deps"
cp -r deps "$output_dir/"

echo "Built $output_dir/libsimplex.so ($(du -h libsimplex.so | cut -f1)) plus $(ls deps | wc -l) runtime dependencies"
