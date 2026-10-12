//! Links `src/simplex/core.rs` against upstream simplex-chat's native core when the
//! `simplex-native` feature is enabled. See `scripts/build-simplex-native.sh` for how to produce
//! the artifact this expects, and that module's docs for what it is.

fn main() {
    if std::env::var_os("CARGO_FEATURE_SIMPLEX_NATIVE").is_none() {
        return;
    }

    println!("cargo::rerun-if-env-changed=SECURE_SIMPLEX_NATIVE_CHECK_ONLY");
    // Lint/type-check-only mode for CI (`cargo clippy --all-features`): `cargo check` and clippy
    // never link, so the native core's FFI declarations can be checked without the 233MB
    // artifact. Anything that does link (`cargo build`/`cargo test`) with this set fails at link
    // time on the unresolved `hs_init`/`chat_*` symbols rather than silently producing a binary,
    // so this cannot be used to ship a build without the real core. It must be opted into
    // explicitly; the default remains the loud panic below.
    if std::env::var_os("SECURE_SIMPLEX_NATIVE_CHECK_ONLY").is_some_and(|value| value == "1") {
        println!(
            "cargo::warning=SECURE_SIMPLEX_NATIVE_CHECK_ONLY=1: simplex-native is type-checked \
             only and will not link"
        );
        return;
    }

    let lib_dir = std::env::var("SECURE_SIMPLEX_NATIVE_LIB_DIR").unwrap_or_else(|_| {
        panic!(
            "the `simplex-native` feature requires SECURE_SIMPLEX_NATIVE_LIB_DIR to point at a \
             directory built by scripts/build-simplex-native.sh (containing libsimplex.so and a \
             deps/ subdirectory of its GHC-runtime dependencies)"
        )
    });
    let deps_dir = format!("{lib_dir}/deps");

    println!("cargo::rustc-link-search=native={lib_dir}");
    println!("cargo::rustc-link-search=native={deps_dir}");
    println!("cargo::rustc-link-lib=dylib=simplex");
    // `libsimplex.so` itself calls into the GHC RTS (`hs_init` et al, see `src/simplex/core.rs`)
    // rather than defining those symbols - it only *depends on* the RTS shared library, it does
    // not re-export its symbols. The linker does not follow that dependency chain to resolve our
    // own direct `hs_init` reference, so it has to be named explicitly too.
    println!("cargo::rustc-link-lib=dylib={}", rts_link_name(&deps_dir));
    // The built binary needs to find libsimplex.so and its ~150 GHC-runtime dependency `.so`
    // files at *run* time too, not just link time; baking their location into the binary's rpath
    // means a test/dev run doesn't also need LD_LIBRARY_PATH set correctly by hand.
    println!("cargo::rustc-link-arg=-Wl,-rpath,{lib_dir}");
    println!("cargo::rustc-link-arg=-Wl,-rpath,{deps_dir}");

    println!("cargo::rerun-if-env-changed=SECURE_SIMPLEX_NATIVE_LIB_DIR");
}

/// The GHC RTS `.so` filename in `deps/` is version-qualified (e.g.
/// `libHSrts-1.0.2_thr-ghc9.6.3.so`) by both the RTS package version and the GHC version used to
/// build it, neither of which this crate should hardcode - `scripts/build-simplex-native.sh`
/// copies whatever `ldd libsimplex.so` reports, so finding it by pattern here stays correct
/// across a GHC/RTS bump without this file needing to track that version too.
fn rts_link_name(deps_dir: &str) -> String {
    let entries = std::fs::read_dir(deps_dir).unwrap_or_else(|error| {
        panic!("failed to read SECURE_SIMPLEX_NATIVE_LIB_DIR/deps ({deps_dir}): {error}")
    });
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("libHSrts-") && name.ends_with(".so") {
            return name
                .strip_prefix("lib")
                .and_then(|rest| rest.strip_suffix(".so"))
                .expect("checked prefix/suffix above")
                .to_string();
        }
    }
    panic!(
        "no libHSrts-*.so found under {deps_dir} - expected one of libsimplex.so's own \
         dependencies copied there by scripts/build-simplex-native.sh"
    );
}
