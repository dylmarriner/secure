//! SimpleX Chat integration.
//!
//! This is the only module in `secure-messaging` - and `secure-messaging` is the only crate in
//! the workspace - permitted to know that the messaging substrate is SimpleX. See
//! `docs/licensing.md`: being licensed (AGPLv3 client, AGPLv3-compatible upstream) to link
//! SimpleX code directly does not change that boundary decision. Everything outside this crate
//! talks to [`crate::SimplexAdapter`]'s narrow public surface, never to a SimpleX-specific type.
//!
//! SimpleX Chat's implementation is Haskell, not Rust: there is no Rust library to link.
//! Integration is via `simplex-chat`'s own documented interface for non-Haskell clients -
//! running the `simplex-chat` CLI as a local subprocess with `-p <port>`, which then serves a
//! JSON-over-WebSocket API (`bots/README.md` in `simplex-chat/simplex-chat`, `stable` branch).
//! That is "linking SimpleX's implementation" in the sense the licensing decision covers (this
//! crate's own release still needs to ship or depend on that AGPLv3 binary), just not in the
//! sense of `cargo` dependency linking.
//!
//! See `docs/security-remediation-plan.md` Phase R3: this CLI subprocess path is an
//! integration-test/dev-only adapter, not the production secret-delivery boundary, because it
//! necessarily places the database encryption key in this process's argv (`client.rs` module
//! docs explain why there is no better flag). Production requires linking upstream's native core
//! and its in-memory key API instead - see [`core`] (behind the `simplex-native` feature), which
//! does exactly that, built from source by `scripts/build-simplex-native.sh`.

pub(crate) mod adapter;
#[cfg(any(test, feature = "simplex-native"))]
pub(crate) mod bootstrap;
pub(crate) mod client;
pub(crate) mod commands;
#[cfg(feature = "simplex-native")]
pub(crate) mod core;
pub(crate) mod events;
#[cfg(feature = "simplex-native")]
pub(crate) mod native_adapter;
#[cfg(test)]
mod properties;
pub(crate) mod protocol;
