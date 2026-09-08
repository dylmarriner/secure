fn main() {
    if std::env::var_os("CARGO_FEATURE_SIMPLEX_NATIVE").is_some() {
        // `rusqlite`'s `bundled-sqlcipher-vendored-openssl` feature (`secure-storage`) statically
        // links its own SQLCipher/OpenSSL into this binary with default (global) symbol
        // visibility - confirmed with `nm -D` (`sqlite3_open`, `sqlite3_open_v2`, and ~50 other
        // OpenSSL/SQLite symbols show up `T` in this binary's dynamic symbol table). ELF gives an
        // executable's own symbols priority over a same-named symbol in any shared library loaded
        // into it, so without this flag `libsimplex.so`'s internal SQLCipher calls (through its
        // own `deps/*.so`) get silently redirected to this binary's incompatible vendored
        // SQLCipher build instead of its own - reproduced as an immediate SIGSEGV on the very
        // first `NativeSimplexAdapter::open` call, before any Tor/network code ever runs
        // (`cargo test --features simplex-native -- --ignored diag_native_open_no_tor_touched_at_all`
        // before this flag was added). `--exclude-libs,ALL` hides every symbol pulled in from a
        // static archive from this binary's dynamic symbol table, so each shared library keeps
        // resolving its own symbols against its own linked dependencies instead of this binary's.
        println!("cargo::rustc-link-arg=-Wl,--exclude-libs,ALL");
    }

    if std::env::var_os("CARGO_FEATURE_SIMPLEX_NATIVE").is_some()
        && let Ok(lib_dir) = std::env::var("SECURE_SIMPLEX_NATIVE_LIB_DIR")
    {
        // Link arguments emitted by a dependency build script are not propagated to this final
        // desktop executable. Carry the native core's runtime search paths onto the Tauri binary
        // as well, so an installed build does not require LD_LIBRARY_PATH just to start.
        let deps_dir = format!("{lib_dir}/deps");
        println!("cargo::rustc-link-arg=-Wl,-rpath,{lib_dir}");
        println!("cargo::rustc-link-arg=-Wl,-rpath,{deps_dir}");
        println!("cargo::rerun-if-env-changed=SECURE_SIMPLEX_NATIVE_LIB_DIR");
    }
    tauri_build::build();
}
