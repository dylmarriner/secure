//! Managed, fail-closed Tor transport for Secure.
//!
//! This crate embeds [Arti](https://arti.torproject.org), the Tor Project's own pure-Rust Tor
//! implementation, rather than bundling and supervising the reference C `tor` daemon as a
//! subprocess. There is no local SOCKS proxy port and no subprocess to launch, sandbox, or
//! watch for crashes: [`TorTransport::connect`] is the *only* network entry point this crate
//! exposes. That is a deliberate structural choice, not an oversight - "no clearnet fallback"
//! is enforced by there being no other function anywhere in this crate that performs network
//! I/O, rather than by a runtime check that could be bypassed or forgotten elsewhere.
//!
//! # What has and has not been exercised
//!
//! The [`lifecycle`] state machine (strict-mode enforcement, retry-after-failure, shutdown
//! semantics) is pure and unit-tested with no network dependency. The real Arti integration has
//! now been run against the live Tor network (`tests/live_bootstrap.rs`, `#[ignore]`d by
//! default since it needs real network access - run explicitly with `cargo test -p
//! secure-transport --test live_bootstrap -- --ignored`): bootstrap completed in about 30
//! seconds and a real stream opened to `check.torproject.org:443` over Tor. That run caught a
//! real bug the first time - see [`ensure_crypto_provider_installed`] - that no amount of
//! type-checking or network-free unit testing could have found, which is exactly why this
//! verification mattered rather than being a formality. See `docs/implementation-plan.md`
//! Phase 2 for when this was actually run and on what.
//!
//! # A known upstream risk
//!
//! `arti-client`'s own documentation for `TorClient::create_bootstrapped` warns that Arti can
//! call `process::exit(1)` and terminate the whole process if the Tor network consensus marks
//! the running Arti version as obsolete. That is a "fail catastrophic", not a "fail closed":
//! this crate cannot intercept or downgrade that behaviour from the outside. It is documented
//! here, in `docs/implementation-plan.md`, and must be re-checked against upstream's own
//! plans to change it before Secure is described as production-ready.

mod lifecycle;

use std::path::Path;
use std::sync::{Arc, Mutex, Once};

use arti_client::config::TorClientConfigBuilder;
use arti_client::{TorClient, TorClientConfig};
use thiserror::Error;
use tor_rtcompat::PreferredRuntime;

pub use arti_client::DataStream;
pub use lifecycle::{TransportEvent, TransportLifecycleError, TransportState};

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("failed to build Tor client configuration: {0}")]
    Configuration(String),
    #[error("transport is not ready for connections (state: {state:?})")]
    NotReady { state: TransportState },
    #[error("Tor bootstrap failed: {0}")]
    BootstrapFailed(String),
    #[error("failed to establish a connection over Tor: {0}")]
    ConnectFailed(String),
    #[error("internal transport lifecycle error: {0}")]
    Lifecycle(#[from] TransportLifecycleError),
    #[error("transport state lock poisoned")]
    LockPoisoned,
}

/// A managed, fail-closed Tor transport.
///
/// One `TorTransport` owns one Arti client and one [`lifecycle::TransportLifecycle`]. All
/// state transitions go through the lifecycle, so `connect` refusing to run before `Ready` (or
/// after `Stopped`) is enforced in one place regardless of how many callers hold a reference to
/// this transport.
pub struct TorTransport {
    lifecycle: Mutex<lifecycle::TransportLifecycle>,
    client: Mutex<Option<Arc<TorClient<PreferredRuntime>>>>,
    config: TorClientConfig,
}

/// `rustls` 0.23+ requires a process-wide `CryptoProvider` to be installed before any TLS
/// connection is attempted; it does not pick one automatically once more than zero backends are
/// reachable in the dependency graph (see the comment on the `rustls` dependency in
/// `Cargo.toml`) - `arti-client`'s directory client uses TLS to fetch consensus documents from
/// directory caches, so this has to be installed before `start` ever runs, not just before
/// `connect`. This was found by actually running a bootstrap against the live Tor network - it
/// compiled and type-checked without it, and panicked on first real use.
///
/// "ring" over "aws-lc-rs": `aws-lc-rs`'s optimised build path additionally wants NASM on
/// Windows and a C toolchain generally; `ring` avoids adding that requirement on top of what
/// `secure-storage`'s vendored SQLCipher/OpenSSL build already needs. Both are widely used,
/// audited TLS crypto backends; this is a build-footprint choice, not a security one.
static CRYPTO_PROVIDER_INSTALLED: Once = Once::new();

fn ensure_crypto_provider_installed() {
    CRYPTO_PROVIDER_INSTALLED.call_once(|| {
        // `install_default` returns `Err` only if a provider was already installed (e.g. by
        // another crate in the same process, or a previous `TorTransport`); either way there is
        // nothing left to do, so the result is intentionally ignored.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

impl TorTransport {
    /// Build a transport that will persist Arti's directory cache and persistent state under
    /// `state_dir`/`cache_dir`. Does not start bootstrapping - call [`Self::start`] for that.
    pub fn new(state_dir: &Path, cache_dir: &Path) -> Result<Self, TransportError> {
        ensure_crypto_provider_installed();

        let config = TorClientConfigBuilder::from_directories(state_dir, cache_dir)
            .build()
            .map_err(|error| TransportError::Configuration(error.to_string()))?;

        Ok(Self {
            lifecycle: Mutex::new(lifecycle::TransportLifecycle::new()),
            client: Mutex::new(None),
            config,
        })
    }

    #[must_use]
    pub fn state(&self) -> TransportState {
        // A poisoned lock here would mean a panic happened while holding it, which this crate
        // never does deliberately; falling back to NotStarted (the most restrictive state)
        // keeps this accessor infallible without ever reporting a falsely-ready state.
        self.lifecycle
            .lock()
            .map(|lifecycle| lifecycle.state())
            .unwrap_or(TransportState::NotStarted)
    }

    /// Bootstrap a connection to the Tor network. Must be awaited from within a running Tokio
    /// runtime (Arti's `PreferredRuntime` requires one) - see `arti_client::TorClient::create_bootstrapped`.
    ///
    /// On success, transitions to `Ready` and connections may be established. On failure,
    /// transitions to `Failed`; calling `start` again from `Failed` retries.
    pub async fn start(&self) -> Result<(), TransportError> {
        self.apply(TransportEvent::Start)?;

        match TorClient::create_bootstrapped(self.config.clone()).await {
            Ok(client) => {
                self.set_client(Some(client));
                self.apply(TransportEvent::BootstrapSucceeded)?;
                Ok(())
            }
            Err(error) => {
                self.set_client(None);
                // Best-effort: BootstrapFailed is always a valid transition out of
                // Bootstrapping, so this should never itself fail, but the original bootstrap
                // error is what the caller needs regardless.
                let _ = self.apply(TransportEvent::BootstrapFailed);
                Err(TransportError::BootstrapFailed(error.to_string()))
            }
        }
    }

    /// The only network entry point this crate exposes. Refuses to run - with no network I/O
    /// attempted at all - unless the transport is `Ready`. `target` is host/port, never a raw
    /// IP: `arti_client::IntoTorAddr` is implemented for `(&str, u16)`/`String` pairs, and
    /// deliberately not used here with `DangerouslyIntoTorAddr`, so callers cannot accidentally
    /// bypass Tor-side name resolution by connecting straight to an IP address.
    pub async fn connect(&self, host: &str, port: u16) -> Result<DataStream, TransportError> {
        let client = {
            let lifecycle = self
                .lifecycle
                .lock()
                .map_err(|_| TransportError::LockPoisoned)?;
            if !lifecycle.can_connect() {
                return Err(TransportError::NotReady {
                    state: lifecycle.state(),
                });
            }
            self.client
                .lock()
                .map_err(|_| TransportError::LockPoisoned)?
                .clone()
                .ok_or(TransportError::NotReady {
                    state: lifecycle.state(),
                })?
        };

        client
            .connect((host, port))
            .await
            .map_err(|error| TransportError::ConnectFailed(error.to_string()))
    }

    /// The current bootstrap progress, if a bootstrap has ever been attempted: `0.0` (just
    /// started) to `1.0` (ready). Purely informational, e.g. for a status indicator; nothing
    /// in this crate uses it to make a connect/refuse decision - that is [`lifecycle::TransportLifecycle::can_connect`]'s job alone.
    #[must_use]
    pub fn bootstrap_fraction(&self) -> Option<f32> {
        let client = self.client.lock().ok()?.clone()?;
        Some(client.bootstrap_status().as_frac())
    }

    /// Stop the transport. Immediately after this returns, every current and future call to
    /// [`Self::connect`] refuses with `NotReady { state: Stopped }` - that refusal happens
    /// synchronously inside the lifecycle's `Mutex`, before this function returns, regardless
    /// of what Arti's own background tasks are still doing. This is the property that matters
    /// for shutdown sequencing ahead of lock/burn cleanup: no *new* network activity can start
    /// once `stop` has returned. `Stopped` is terminal; a new `TorTransport` must be
    /// constructed to use Tor again.
    pub fn stop(&self) -> Result<(), TransportError> {
        self.apply(TransportEvent::Stop)?;
        self.set_client(None);
        Ok(())
    }

    fn apply(&self, event: TransportEvent) -> Result<(), TransportError> {
        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| TransportError::LockPoisoned)?;
        lifecycle.apply(event).map_err(TransportError::from)
    }

    fn set_client(&self, client: Option<Arc<TorClient<PreferredRuntime>>>) {
        if let Ok(mut guard) = self.client.lock() {
            *guard = client;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_transport_starts_not_started_and_refuses_bootstrap_fraction() {
        let dir = tempfile::tempdir().expect("tempdir");
        let transport = TorTransport::new(&dir.path().join("state"), &dir.path().join("cache"))
            .expect("build transport config");

        assert_eq!(transport.state(), TransportState::NotStarted);
        assert_eq!(transport.bootstrap_fraction(), None);
    }

    #[tokio::test]
    async fn connect_before_start_refuses_without_a_client() {
        let dir = tempfile::tempdir().expect("tempdir");
        let transport = TorTransport::new(&dir.path().join("state"), &dir.path().join("cache"))
            .expect("build transport config");

        let error = transport
            .connect("example.com", 80)
            .await
            .expect_err("must refuse before start");
        assert!(matches!(
            error,
            TransportError::NotReady {
                state: TransportState::NotStarted
            }
        ));
    }

    #[tokio::test]
    async fn stop_before_start_transitions_to_stopped_and_refuses_connect() {
        let dir = tempfile::tempdir().expect("tempdir");
        let transport = TorTransport::new(&dir.path().join("state"), &dir.path().join("cache"))
            .expect("build transport config");

        transport.stop().expect("stop from NotStarted");
        assert_eq!(transport.state(), TransportState::Stopped);

        let error = transport
            .connect("example.com", 80)
            .await
            .expect_err("must refuse after stop");
        assert!(matches!(
            error,
            TransportError::NotReady {
                state: TransportState::Stopped
            }
        ));
    }
}
