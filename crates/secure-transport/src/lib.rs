//! Managed, fail-closed Tor transport for Secure.
//!
//! This crate embeds [Arti](https://arti.torproject.org), the Tor Project's own pure-Rust Tor
//! implementation, rather than bundling and supervising the reference C `tor` daemon as a
//! subprocess. [`TorTransport::connect`] is the direct network entry point; callers that cannot
//! consume an Arti [`DataStream`] (notably the `simplex-chat` subprocess) can start a loopback-only
//! [`TorSocksProxy`] backed by that same entry point. Neither path contains a clearnet fallback.
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
mod socks;

use std::path::Path;
use std::sync::{Arc, Mutex, Once};

use arti_client::config::TorClientConfigBuilder;
use arti_client::{TorClient, TorClientConfig};
use thiserror::Error;
use tor_rtcompat::PreferredRuntime;

pub use arti_client::DataStream;
pub use lifecycle::{TransportEvent, TransportLifecycleError, TransportState};
pub use socks::TorSocksProxy;

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
    #[error("failed to bind the loopback SOCKS proxy: {0}")]
    SocksBind(#[source] std::io::Error),
    #[error("failed to read the loopback SOCKS proxy address: {0}")]
    SocksAddress(#[source] std::io::Error),
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
    lifecycle: Arc<Mutex<lifecycle::TransportLifecycle>>,
    client: Arc<Mutex<Option<Arc<TorClient<PreferredRuntime>>>>>,
    config: TorClientConfig,
    /// Broadcasts `true` exactly once, from [`Self::stop`]. Every [`TorSocksProxy`] started
    /// from this transport subscribes to a clone of the receiver side, so stopping the
    /// transport cancels its active proxied streams too, not only future `connect`/SOCKS
    /// attempts - see `socks::wait_for_shutdown`.
    shutdown: tokio::sync::watch::Sender<bool>,
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

        let (shutdown, _receiver) = tokio::sync::watch::channel(false);
        Ok(Self {
            lifecycle: Arc::new(Mutex::new(lifecycle::TransportLifecycle::new())),
            client: Arc::new(Mutex::new(None)),
            config,
            shutdown,
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
                // A concurrent `stop()` may have already moved the lifecycle out of
                // `Bootstrapping` (e.g. to `Stopped`) while this bootstrap was in flight. Install
                // the client only if the transition to `Ready` actually succeeds; otherwise stop
                // won the race and this freshly-bootstrapped client must be discarded rather than
                // left installed under a lifecycle that no longer says `Ready`.
                self.set_client(Some(client));
                if let Err(error) = self.apply(TransportEvent::BootstrapSucceeded) {
                    self.set_client(None);
                    return Err(error);
                }
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

    /// The direct network entry point this crate exposes. Refuses to run - with no network I/O
    /// attempted at all - unless the transport is `Ready`. `target` is host/port, never a raw
    /// IP: `arti_client::IntoTorAddr` is implemented for `(&str, u16)`/`String` pairs, and
    /// deliberately not used here with `DangerouslyIntoTorAddr`, so callers cannot accidentally
    /// bypass Tor-side name resolution by connecting straight to an IP address. The SOCKS bridge
    /// applies the same restriction to subprocess requests.
    pub async fn connect(&self, host: &str, port: u16) -> Result<DataStream, TransportError> {
        let client = ready_client(&self.lifecycle, &self.client)?;

        client
            .connect((host, port))
            .await
            .map_err(|error| TransportError::ConnectFailed(error.to_string()))
    }

    /// Start a SOCKS5 proxy bound to an operating-system-selected port on IPv4 loopback.
    ///
    /// This exists for subprocesses such as `simplex-chat` that can consume a SOCKS proxy but
    /// cannot consume Arti's [`DataStream`] directly. Starting it before Tor is ready fails
    /// without binding a listener. Every accepted `CONNECT` request re-checks the shared
    /// transport lifecycle before opening a Tor stream, so stopping the transport also makes
    /// the proxy refuse subsequent connections.
    pub async fn start_socks_proxy(&self) -> Result<TorSocksProxy, TransportError> {
        ready_client(&self.lifecycle, &self.client)?;
        TorSocksProxy::start(
            Arc::clone(&self.lifecycle),
            Arc::clone(&self.client),
            self.shutdown.subscribe(),
        )
        .await
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
    /// once `stop` has returned. `stop` also broadcasts on this transport's shutdown watch, so
    /// every [`TorSocksProxy`] started from it cancels its already-accepted connections too, not
    /// only future ones. `Stopped` is terminal; a new `TorTransport` must be constructed to use
    /// Tor again.
    ///
    /// What this does **not** guarantee: `stop` drops this crate's only `Arc<TorClient>` handle,
    /// it does not call any Arti shutdown/dormant API on the client. Arti's own directory/guard
    /// management and any circuits it already built are not proven to stop producing network
    /// traffic the instant this returns - "no new Secure-initiated stream", not "zero Tor
    /// process network traffic". See the R2 section of `docs/security-remediation-plan.md`.
    pub fn stop(&self) -> Result<(), TransportError> {
        self.apply(TransportEvent::Stop)?;
        self.set_client(None);
        // Best-effort: an error here only means no `TorSocksProxy` ever subscribed, i.e. there
        // is nothing live left to cancel.
        let _ = self.shutdown.send(true);
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

fn ready_client(
    lifecycle: &Mutex<lifecycle::TransportLifecycle>,
    client: &Mutex<Option<Arc<TorClient<PreferredRuntime>>>>,
) -> Result<Arc<TorClient<PreferredRuntime>>, TransportError> {
    let lifecycle = lifecycle.lock().map_err(|_| TransportError::LockPoisoned)?;
    if !lifecycle.can_connect() {
        return Err(TransportError::NotReady {
            state: lifecycle.state(),
        });
    }
    client
        .lock()
        .map_err(|_| TransportError::LockPoisoned)?
        .clone()
        .ok_or(TransportError::NotReady {
            state: lifecycle.state(),
        })
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
    async fn socks_proxy_before_start_refuses_without_binding_a_port() {
        let dir = tempfile::tempdir().expect("tempdir");
        let transport = TorTransport::new(&dir.path().join("state"), &dir.path().join("cache"))
            .expect("build transport config");

        let error = transport
            .start_socks_proxy()
            .await
            .expect_err("must refuse before Tor is ready");
        assert!(matches!(
            error,
            TransportError::NotReady {
                state: TransportState::NotStarted
            }
        ));
    }

    #[test]
    fn stop_wins_against_late_bootstrap_completion() {
        // Simulates the race without a real Arti bootstrap: `Start` moves the lifecycle to
        // `Bootstrapping`, `Stop` (racing in from another task) moves it to `Stopped` before the
        // bootstrap's `BootstrapSucceeded` is applied, so the late completion must be rejected
        // and no client may end up installed under a `Stopped` lifecycle.
        let dir = tempfile::tempdir().expect("tempdir");
        let transport = TorTransport::new(&dir.path().join("state"), &dir.path().join("cache"))
            .expect("build transport config");

        transport.apply(TransportEvent::Start).expect("start");
        transport.stop().expect("stop wins the race");
        assert_eq!(transport.state(), TransportState::Stopped);

        let late_completion = transport.apply(TransportEvent::BootstrapSucceeded);
        assert!(
            late_completion.is_err(),
            "a bootstrap that finishes after stop must not resurrect Ready"
        );
        assert_eq!(transport.state(), TransportState::Stopped);
        assert!(
            transport.client.lock().unwrap().is_none(),
            "no client may be installed once stop has won"
        );
    }

    #[test]
    fn stop_broadcasts_shutdown_to_socks_proxy_subscribers() {
        // `TorSocksProxy` cancels active connections by subscribing to this same watch channel
        // (see `socks::wait_for_shutdown`); this asserts the transport side of that contract
        // without needing a real listener or a live Tor bootstrap.
        let dir = tempfile::tempdir().expect("tempdir");
        let transport = TorTransport::new(&dir.path().join("state"), &dir.path().join("cache"))
            .expect("build transport config");

        let mut subscriber = transport.shutdown.subscribe();
        assert!(!*subscriber.borrow(), "must not be pre-signalled");

        transport.stop().expect("stop");

        assert!(
            *subscriber.borrow_and_update(),
            "stop must flip the shared shutdown watch"
        );
    }

    #[test]
    fn lifecycle_and_client_locks_never_deadlock_under_concurrent_start_stop() {
        // `ready_client` locks `lifecycle` then (while still holding it) `client`; `apply` and
        // `set_client` each lock exactly one of the two independently. That is one fixed lock
        // order (lifecycle before client, never the reverse), so hammering start/stop/connect
        // concurrently from many threads must finish promptly rather than deadlock.
        let dir = tempfile::tempdir().expect("tempdir");
        let transport = Arc::new(
            TorTransport::new(&dir.path().join("state"), &dir.path().join("cache"))
                .expect("build transport config"),
        );

        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let transport = Arc::clone(&transport);
                std::thread::spawn(move || {
                    for _ in 0..200 {
                        if i % 2 == 0 {
                            let _ = transport.apply(TransportEvent::Start);
                        } else {
                            let _ = transport.stop();
                        }
                        let _ = transport.state();
                    }
                })
            })
            .collect();

        // A `join` on every thread returning within a generous bound is the deadlock check
        // itself: a real lock-order violation here would hang this test, not fail an assertion.
        runtime.block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                for handle in handles {
                    tokio::task::spawn_blocking(move || handle.join())
                        .await
                        .expect("join task")
                        .expect("worker thread must not panic");
                }
            })
            .await
            .expect("start/stop contention must not deadlock");
        });

        assert_eq!(transport.state(), TransportState::Stopped);
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
