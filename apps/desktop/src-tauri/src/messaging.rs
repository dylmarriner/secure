//! Desktop messaging runtime wiring (Phase R5, `docs/security-remediation-plan.md`).
//!
//! Owns the composed stack this phase's plan specifies:
//!
//! ```text
//! UnlockedVault -> MessagingDatabaseV1 subkey -> TorTransport Ready -> TorSocksProxy
//!   -> SimpleX core/controller -> event task
//! ```
//!
//! [`MessagingRuntime`] is that composition from `TorSocksProxy` down. It requires the
//! `simplex-native` feature: the CLI-backed `secure_messaging::SimplexAdapter` is documented
//! dev/integration-only (`docs/security-remediation-plan.md` Phase R3) and must not be wired
//! into a production launch path, so there is nothing safe to compose here without the native
//! core. Building/testing this feature requires `libsimplex.so`
//! (`scripts/build-simplex-native.sh`) and `SECURE_SIMPLEX_NATIVE_LIB_DIR`.
//!
//! The feature-enabled unlock command owns startup of this stack and fails closed if Tor,
//! network configuration, or native bootstrap fails. Delivered `ChatEvent`s are routed into
//! encrypted vault storage through [`ChatEventSink`] - this module never holds a `Vault` or a
//! `VaultKey` itself (only `main.rs`'s runtime layer is allowed to), so the sink is a trait the
//! caller implements against whatever holds the unlocked vault.

#![cfg(feature = "simplex-native")]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use secure_messaging::{AdapterError, ChatEvent, NativeSimplexAdapter};
use secure_transport::TorSocksProxy;
use serde::Serialize;
use zeroize::Zeroizing;

/// Where delivered chat events go once parsed. Implemented by the runtime layer, which owns the
/// unlocked vault; kept as a trait so this module never has to depend on `AppRuntime`/`Vault`
/// types, matching the rest of this file's narrow-boundary style.
pub(crate) trait ChatEventSink: Send + Sync + 'static {
    fn record(&self, event: ChatEvent);
}

/// The composed messaging stack for one unlocked session: a Tor SOCKS bridge plus a SimpleX
/// core configured to route through it exclusively.
pub(crate) struct MessagingRuntime {
    proxy: TorSocksProxy,
    adapter: NativeSimplexAdapter,
    /// Drains the adapter's event channel until [`Self::stop`] closes it, parsing each raw
    /// value into zero or more [`ChatEvent`]s and handing them to the [`ChatEventSink`] passed
    /// to [`Self::start`].
    event_drain: tokio::task::JoinHandle<()>,
}

#[derive(Debug, Serialize)]
pub(crate) struct MessagingStatus {
    pub(crate) state: &'static str,
}

/// Failure during [`MessagingRuntime::start`]. Carries the `TorSocksProxy` back so the caller -
/// which owns the `TorTransport` the proxy borrowed from - can shut it down; `start` never
/// leaves a proxy running unowned on a failure path.
pub(crate) struct MessagingStartError {
    pub(crate) proxy: TorSocksProxy,
    pub(crate) error: AdapterError,
}

impl MessagingRuntime {
    /// Bring up the messaging stack behind an already-`Ready` Tor transport's SOCKS proxy:
    /// open the native SimpleX store at `db_file_prefix` under `db_key` (a
    /// `SubkeyPurpose::MessagingDatabaseV1` subkey, never the raw passphrase - see
    /// `NativeSimplexAdapter::open`), bootstrap (creates the local user - the native store has
    /// no equivalent of the CLI adapter's launch-time `--user` creation, so unlike
    /// `SimplexAdapter::configure_network`, `NativeSimplexAdapter::configure_network` errors
    /// with `noActiveUser` if called before a user exists - confirmed against the real native
    /// core, not assumed), then point it at `proxy`'s loopback address and verify the read-back
    /// matches (`docs/security-remediation-plan.md` Phase R4).
    ///
    /// `bootstrap` itself makes no network calls (`start_chat`/`create_native_user`/
    /// `show_active_user` are all local chat-controller/store operations), so running it before
    /// `configure_network` does not weaken the fail-closed guarantee: no method that can
    /// actually originate network traffic (`create_invitation`/`accept_invitation`/
    /// `send_text_message`) is reachable until `start` returns `Ok`, and `configure_network`
    /// still runs - and is still verified - before that happens.
    ///
    /// Fails closed at every step: a `bootstrap`/`configure_network` failure shuts the
    /// half-open adapter down before returning, so a caller never observes a partially-started
    /// `MessagingRuntime` and never needs to guess whether cleanup already happened.
    pub(crate) async fn start(
        proxy: TorSocksProxy,
        db_file_prefix: PathBuf,
        db_key: Zeroizing<String>,
        sink: Arc<dyn ChatEventSink>,
    ) -> Result<Self, MessagingStartError> {
        let socks_address = match proxy.address() {
            SocketAddr::V4(address) => address,
            // `TorSocksProxy` binds `(Ipv4Addr::LOCALHOST, 0)` unconditionally
            // (`secure_transport::socks::TorSocksProxy::start`) - there is no code path that
            // produces a v6 address today.
            SocketAddr::V6(_) => {
                unreachable!("TorSocksProxy always binds an IPv4 loopback address")
            }
        };

        let (adapter, mut events) = match NativeSimplexAdapter::open(db_file_prefix, db_key).await {
            Ok(opened) => opened,
            Err(error) => return Err(MessagingStartError { proxy, error }),
        };

        if let Err(error) = adapter.bootstrap().await {
            adapter.shutdown().await;
            return Err(MessagingStartError { proxy, error });
        }

        if let Err(error) = adapter.configure_network(socks_address).await {
            adapter.shutdown().await;
            return Err(MessagingStartError { proxy, error });
        }

        let event_drain = tokio::spawn(async move {
            while let Some(value) = events.recv().await {
                for event in secure_messaging::parse_chat_event(value) {
                    sink.record(event);
                }
            }
        });

        Ok(Self {
            proxy,
            adapter,
            event_drain,
        })
    }

    /// Shut down in the order this phase's plan requires: SimpleX/controller and its event task
    /// first, then the SOCKS bridge's active streams and listener. The caller is responsible for
    /// the remaining steps (stop/drop the Tor transport, close the vault, zero the VMK/subkeys)
    /// since this type does not own any of that state.
    pub(crate) async fn stop(self) {
        self.adapter.shutdown().await;
        // `adapter.shutdown()` drops the native core, which drops the event channel's sender,
        // so `event_drain`'s loop exits on its own; `abort` is a safety net in case that ever
        // stops being true rather than the primary shutdown mechanism.
        self.event_drain.abort();
        self.proxy.shutdown().await;
    }

    pub(crate) async fn create_invitation(&self) -> Result<String, AdapterError> {
        Ok(self.adapter.create_invitation().await?.link)
    }

    pub(crate) async fn accept_invitation(&self, link: &str) -> Result<(), AdapterError> {
        self.adapter.accept_invitation(link).await
    }

    pub(crate) async fn send_text_message(
        &self,
        chat_id: i64,
        message: &str,
    ) -> Result<(), AdapterError> {
        self.adapter.send_text_message(chat_id, message).await
    }
}
