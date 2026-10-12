//! Production chat-command layer over [`super::core::SimplexCore`] (`simplex-native` feature).
//!
//! [`super::adapter::SimplexAdapter`] is explicitly dev/integration-only (see `client.rs`'s
//! module docs): it spawns the `simplex-chat` CLI subprocess, which necessarily puts the database
//! key in argv. `SimplexCore` closes that gap at the FFI boundary (Phase R3), but on its own is
//! only "open a store and send/receive raw JSON" - it has no bootstrap, invitation, or
//! network-config command vocabulary of its own. [`NativeSimplexAdapter`] is that vocabulary,
//! mirroring [`super::adapter::SimplexAdapter`]'s method surface exactly (same command strings
//! from [`super::commands`], same response-shape validation via
//! [`super::adapter::is_error_response`]/`extract_*`) so a caller can be written once against
//! either backend. It does not reimplement that validation logic - see the `pub(super)` helpers
//! in `adapter.rs`.
//!
//! # Async over a blocking FFI boundary
//!
//! `SimplexCore::send_cmd`/`recv_msg_wait` are synchronous, blocking C calls (documented on
//! `SimplexCore` itself: no concurrent calls, `Send` but not `Sync`). Every call here goes through
//! `tokio::task::spawn_blocking` so it cannot stall the async runtime's worker threads, matching
//! how upstream's own mobile/desktop bindings drive this same FFI surface from a dedicated thread.
//!
//! # Event delivery
//!
//! Unlike the CLI's WebSocket transport (which pushes correlated responses and uncorrelated
//! events over one multiplexed stream via [`super::protocol::CorrelationTable`]), the native
//! core's `chat_send_cmd` already returns *that command's own* response directly - no correlation
//! table is needed here at all. Out-of-band events (a contact connecting, an incoming message)
//! only ever arrive through a separate polling call, `chat_recv_msg_wait`, so [`Self::open`] spawns
//! one background task that loops on it and forwards whatever arrives to an
//! [`super::client::EventReceiver`] - the same channel type [`super::adapter::SimplexAdapter`]'s
//! callers already consume, so [`crate::parse_chat_event`] works unchanged against either backend.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::{Mutex as AsyncMutex, mpsc};
use zeroize::Zeroizing;

use super::adapter::{AdapterError, Invitation, extract_invitation_link, is_error_response};
use super::bootstrap;
use super::client::{EVENT_CHANNEL_CAPACITY, EventReceiver};
use super::commands::{self, ChatKind};
use super::core::SimplexCore;

/// How long each `chat_recv_msg_wait` poll blocks before returning empty. Bounds both how
/// promptly a real event is forwarded and how long [`NativeSimplexAdapter::shutdown`] can take to
/// observe its stop signal and let the background event task exit - a smaller value tightens
/// shutdown latency at the cost of more idle FFI calls per second of quiet.
///
/// ponytail: fixed poll interval rather than a wake-on-event native callback (upstream's FFI
/// surface offers only blocking `recv_msg_wait`, not a callback registration); revisit if a
/// future upstream version exposes one and 1s shutdown/delivery latency stops being acceptable.
const EVENT_POLL_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug)]
pub struct NativeSimplexAdapter {
    /// `SimplexCore` is `Send` but deliberately not `Sync` (see its own docs: "never concurrent
    /// direct calls"), so `Arc<SimplexCore>` alone is not `Send` either - `Arc<T>` requires
    /// `T: Send + Sync`. The background event poller (below) and every `run`/`send_cmd` caller
    /// need to share one core across tasks, so this `std::sync::Mutex` is what actually
    /// enforces "only ever one call into the FFI boundary at a time" rather than merely
    /// asserting it in a comment; locking happens inside `spawn_blocking` closures only, never
    /// held across an `.await`, so it cannot block the async runtime.
    core: Arc<std::sync::Mutex<SimplexCore>>,
    user_id: AsyncMutex<Option<i64>>,
    stop_events: Arc<AtomicBool>,
    event_task: tokio::task::JoinHandle<()>,
}

impl NativeSimplexAdapter {
    /// Open the native SimpleX store at `db_file_prefix` under `key` (a
    /// `SubkeyPurpose::MessagingDatabaseV1`-derived subkey - see [`SimplexCore::open`]'s own
    /// docs for why it must not be the raw passphrase) and start the background event poller.
    pub async fn open(
        db_file_prefix: PathBuf,
        key: Zeroizing<String>,
    ) -> Result<(Self, EventReceiver), AdapterError> {
        let core = tokio::task::spawn_blocking(move || SimplexCore::open(&db_file_prefix, &key))
            .await
            .expect("spawn_blocking task panicked")?;
        let core = Arc::new(std::sync::Mutex::new(core));

        let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let stop_events = Arc::new(AtomicBool::new(false));

        let poll_core = Arc::clone(&core);
        let poll_stop = Arc::clone(&stop_events);
        let event_task = tokio::spawn(async move {
            loop {
                if poll_stop.load(Ordering::Relaxed) {
                    break;
                }
                let poll_core = Arc::clone(&poll_core);
                let received = tokio::task::spawn_blocking(move || {
                    poll_core
                        .lock()
                        .expect("SimplexCore mutex poisoned")
                        .recv_msg_wait(EVENT_POLL_TIMEOUT)
                })
                .await;
                match received {
                    Ok(Ok(serde_json::Value::Null)) => continue, // poll timeout, no event
                    Ok(Ok(value)) => {
                        // The only failure mode is "no receiver left", meaning the adapter has
                        // already been dropped without going through `shutdown` - nothing to do
                        // but stop polling, matching `client.rs`'s reader task.
                        if event_tx.send(value).await.is_err() {
                            break;
                        }
                    }
                    // A core-level error or a panicked/aborted blocking task both mean this
                    // store can no longer be trusted to keep answering - stop rather than spin.
                    Ok(Err(_)) | Err(_) => break,
                }
            }
        });

        Ok((
            Self {
                core,
                user_id: AsyncMutex::new(None),
                stop_events,
                event_task,
            },
            event_rx,
        ))
    }

    /// Bring the core up over Secure's Tor path: ensure the local user exists, point the network
    /// config at `socks_address` and verify it, and only then start the chat controller. See
    /// [`super::bootstrap`] for why that order is a security property - `/_start` before a
    /// verified `/_network` connects to relays directly. Idempotent: a second call re-verifies
    /// the network config and `/_start` answers `chatRunning`.
    pub async fn bootstrap(
        &self,
        socks_address: std::net::SocketAddrV4,
    ) -> Result<(), AdapterError> {
        let user_id = bootstrap::bootstrap(socks_address, |cmd| self.run(cmd)).await?;
        *self.user_id.lock().await = Some(user_id);
        Ok(())
    }

    #[cfg(test)]
    async fn configure_network(
        &self,
        socks_address: std::net::SocketAddrV4,
    ) -> Result<(), AdapterError> {
        bootstrap::configure_network(socks_address, &mut |cmd| self.run(cmd)).await
    }

    /// Create a one-time invitation link for a new contact to connect with.
    pub async fn create_invitation(&self) -> Result<Invitation, AdapterError> {
        let user_id = self.require_user_id().await?;
        let response = self.run(commands::create_invitation(user_id)).await?;
        extract_invitation_link(&response).map(|link| Invitation { link })
    }

    /// Accept an invitation (or connect to a contact address / group link).
    pub async fn accept_invitation(&self, link: &str) -> Result<(), AdapterError> {
        let user_id = self.require_user_id().await?;
        self.run(commands::connect_via_link(user_id, link)?).await?;
        Ok(())
    }

    /// Send a plain-text message to a direct chat.
    pub async fn send_text_message(&self, chat_id: i64, text: &str) -> Result<(), AdapterError> {
        self.run(commands::send_text_message(ChatKind::Direct, chat_id, text))
            .await?;
        Ok(())
    }

    /// Stop the background event poller and close the native store. Bounded by
    /// [`EVENT_POLL_TIMEOUT`]: the in-flight `recv_msg_wait` call cannot be interrupted (it is
    /// synchronous FFI, not cancellable async code), so this waits for it to return on its own
    /// before the poller observes the stop flag and exits - after which dropping `self.core`
    /// (now the only remaining reference) runs `SimplexCore`'s `Drop` and calls
    /// `chat_close_store`.
    pub async fn shutdown(self) {
        self.stop_events.store(true, Ordering::Relaxed);
        let _ = self.event_task.await;
        drop(self.core);
    }

    async fn require_user_id(&self) -> Result<i64, AdapterError> {
        self.user_id
            .lock()
            .await
            .ok_or(AdapterError::NotBootstrapped)
    }

    async fn run(&self, cmd: String) -> Result<serde_json::Value, AdapterError> {
        let core = Arc::clone(&self.core);
        let response = tokio::task::spawn_blocking(move || {
            core.lock()
                .expect("SimplexCore mutex poisoned")
                .send_cmd(&cmd)
        })
        .await
        .expect("spawn_blocking task panicked")?;
        let response = response.get("result").cloned().unwrap_or(response);
        if is_error_response(&response) || response.get("error").is_some() {
            return Err(AdapterError::CommandFailed(response));
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_socks() -> std::net::SocketAddrV4 {
        "127.0.0.1:9050".parse().expect("address")
    }

    #[tokio::test]
    async fn open_rejects_a_key_containing_a_nul_byte() {
        let dir = tempfile::tempdir().expect("tempdir");
        let prefix = dir.path().join("store");
        let key = Zeroizing::new("bad\0key".to_string());

        let error = NativeSimplexAdapter::open(prefix, key)
            .await
            .expect_err("NUL byte must be rejected");
        assert!(matches!(
            error,
            AdapterError::Core(super::super::core::CoreError::InvalidKey)
        ));
    }

    // The tests below link and run the real `libsimplex.so` (see `core.rs`'s build requirement)
    // and exercise the full bootstrap/invitation/shutdown cycle through this module's command
    // vocabulary, not just `SimplexCore`'s raw FFI wrapper - `core.rs`'s own tests already cover
    // the FFI boundary in isolation.

    #[tokio::test]
    async fn bootstrap_reads_back_an_active_user() {
        let dir = tempfile::tempdir().expect("tempdir");
        let prefix = dir.path().join("store");
        let key = Zeroizing::new("correct horse battery staple".to_string());

        let (adapter, _events) = NativeSimplexAdapter::open(prefix, key)
            .await
            .expect("open the real native store");

        let error = adapter
            .create_invitation()
            .await
            .expect_err("must not be able to create an invitation before bootstrap");
        assert!(matches!(error, AdapterError::NotBootstrapped));

        adapter.bootstrap(test_socks()).await.expect("bootstrap");
        // A second bootstrap must not error or create a redundant user - `ShowActiveUser` just
        // reads the same one back again, matching the CLI adapter's own idempotency.
        adapter
            .bootstrap(test_socks())
            .await
            .expect("bootstrap is idempotent");

        adapter.shutdown().await;
    }

    #[tokio::test]
    async fn create_invitation_returns_a_real_link_after_bootstrap() {
        let dir = tempfile::tempdir().expect("tempdir");
        let prefix = dir.path().join("store");
        let key = Zeroizing::new("correct horse battery staple".to_string());

        let (adapter, _events) = NativeSimplexAdapter::open(prefix, key)
            .await
            .expect("open the real native store");
        adapter.bootstrap(test_socks()).await.expect("bootstrap");

        let invitation = adapter
            .create_invitation()
            .await
            .expect("create an invitation");
        assert!(
            !invitation.link.is_empty(),
            "a real invitation link must not be empty"
        );

        adapter.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_stops_the_event_task_and_closes_the_store() {
        let dir = tempfile::tempdir().expect("tempdir");
        let prefix = dir.path().join("store");
        let key = Zeroizing::new("correct horse battery staple".to_string());

        let (adapter, mut events) = NativeSimplexAdapter::open(prefix.clone(), key.clone())
            .await
            .expect("open the real native store");
        adapter.shutdown().await;

        // The event channel's sender is dropped once the poller task exits, so the receiver
        // observes the channel closing rather than hanging forever.
        assert!(events.recv().await.is_none());

        // The store must be genuinely closed (not merely orphaned): reopening the same prefix
        // with the same key must succeed cleanly, proving nothing still holds it open.
        let (reopened, _events) = NativeSimplexAdapter::open(prefix, key)
            .await
            .expect("reopen after shutdown");
        reopened.shutdown().await;
    }

    /// Unlike [`super::super::adapter::SimplexAdapter`] (whose `configure_network` this adapter
    /// otherwise mirrors), the native store has no launch-time `--user` creation step - a user
    /// only exists once [`NativeSimplexAdapter::bootstrap`] creates one. `configure_network`
    /// itself requires an active user (confirmed here against the real native core, not
    /// assumed) and fails with `noActiveUser` before one exists. `messaging.rs`'s
    /// [`NativeSimplexAdapter::bootstrap`] therefore ensures the user exists first, then
    /// configures the network, and only then sends `/_start`.
    #[tokio::test]
    async fn configure_network_before_bootstrap_fails_with_no_active_user() {
        let dir = tempfile::tempdir().expect("tempdir");
        let prefix = dir.path().join("store");
        let key = Zeroizing::new("correct horse battery staple".to_string());

        let (adapter, _events) = NativeSimplexAdapter::open(prefix, key)
            .await
            .expect("open the real native store");

        let addr: std::net::SocketAddrV4 = "127.0.0.1:9050".parse().unwrap();
        let error = adapter
            .configure_network(addr)
            .await
            .expect_err("configure_network before any user exists must fail");
        let AdapterError::CommandFailed(response) = error else {
            panic!("expected CommandFailed, got {error:?}");
        };
        assert_eq!(
            response["error"]["errorType"]["type"].as_str(),
            Some("noActiveUser")
        );

        adapter.shutdown().await;
    }

    #[tokio::test]
    async fn configure_network_after_bootstrap_succeeds() {
        let dir = tempfile::tempdir().expect("tempdir");
        let prefix = dir.path().join("store");
        let key = Zeroizing::new("correct horse battery staple".to_string());

        let (adapter, _events) = NativeSimplexAdapter::open(prefix, key)
            .await
            .expect("open the real native store");
        adapter.bootstrap(test_socks()).await.expect("bootstrap");

        let addr: std::net::SocketAddrV4 = "127.0.0.1:9050".parse().unwrap();
        adapter
            .configure_network(addr)
            .await
            .expect("configure_network succeeds once a user exists");

        adapter.shutdown().await;
    }
}
