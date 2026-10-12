use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use arti_client::isolation::IsolationHelper;
use arti_client::{StreamPrefs, TorClient};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};
use tor_rtcompat::PreferredRuntime;
use tor_socksproto::{
    Buffer, Handshake, NextStep, PreciseReads, SocksAddr, SocksAuth, SocksCmd, SocksProxyHandshake,
    SocksStatus,
};

use crate::lifecycle::TransportLifecycle;
use crate::{TransportError, ready_client};

/// A loopback-only SOCKS5 bridge into a ready [`crate::TorTransport`].
///
/// Dropping or explicitly shutting down this handle - or the owning [`crate::TorTransport`]
/// calling [`crate::TorTransport::stop`] - stops the listener and cancels every connection it
/// accepted, including one currently mid-transfer. That cancellation is cooperative (a shared
/// `watch` signal raced against `copy_bidirectional`), not a hard socket-level kill, but it
/// closes both sides of the proxied connection as soon as the in-flight copy notices the
/// signal, without waiting for the remote peer. The bound address is safe to pass to a local
/// subprocess; the listener never binds a non-loopback interface.
///
/// # Circuit isolation (`docs/security-remediation-plan.md` Phase R4)
///
/// Each proxied connection is isolated from every other by the SOCKS5 username/password the
/// connecting client presented in its handshake: same credentials may share a circuit, different
/// credentials (or no credentials vs. any credentials) never do - see [`ConnectionIsolation`].
/// This is per-*SOCKS-connection* isolation only. It does **not** isolate: different requests
/// multiplexed over one already-open SOCKS connection (isolation is decided once, at `connect`
/// time, from that connection's handshake); anything about `TorTransport::connect`'s direct
/// (non-SOCKS) path, which does not go through this module and currently uses the transport's
/// shared default isolation; or two connections that happen to present the same credentials
/// (e.g. two callers that both connect with `SocksAuth::NoAuth` share one isolation group with
/// each other). Whether a given caller (e.g. SimpleX) actually presents distinct per-connection
/// credentials is that caller's choice, not something this bridge can enforce from its side.
pub struct TorSocksProxy {
    address: SocketAddr,
    task: JoinHandle<()>,
    shutdown_tx: watch::Sender<bool>,
}

impl std::fmt::Debug for TorSocksProxy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TorSocksProxy")
            .field("address", &self.address)
            .field("running", &!self.task.is_finished())
            .finish()
    }
}

impl TorSocksProxy {
    pub(crate) async fn start(
        lifecycle: Arc<Mutex<TransportLifecycle>>,
        client: Arc<Mutex<Option<Arc<TorClient<PreferredRuntime>>>>>,
        transport_shutdown: watch::Receiver<bool>,
    ) -> Result<Self, TransportError> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(TransportError::SocksBind)?;
        let address = listener
            .local_addr()
            .map_err(TransportError::SocksAddress)?;

        let (shutdown_tx, proxy_shutdown) = watch::channel(false);

        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            let mut proxy_shutdown = proxy_shutdown;
            let mut transport_shutdown = transport_shutdown;

            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((socket, _peer)) = accepted else { break; };
                        let lifecycle = Arc::clone(&lifecycle);
                        let client = Arc::clone(&client);
                        let conn_proxy_shutdown = proxy_shutdown.clone();
                        let conn_transport_shutdown = transport_shutdown.clone();
                        connections.spawn(async move {
                            let mut conn_proxy_shutdown = conn_proxy_shutdown;
                            let mut conn_transport_shutdown = conn_transport_shutdown;
                            // A shutdown signal wins against *every* stage of a connection - the
                            // SOCKS handshake, the Tor connect, and the transfer. Dropping the
                            // `serve` future closes the local socket and any Tor stream it holds.
                            // Racing only the transfer (as an earlier version did) let a client
                            // that connected and then sent nothing block `shutdown` forever.
                            tokio::select! {
                                _ = serve(socket, &lifecycle, &client) => {}
                                () = wait_for_shutdown(&mut conn_proxy_shutdown) => {}
                                () = wait_for_shutdown(&mut conn_transport_shutdown) => {}
                            }
                        });
                    }
                    _ = wait_for_shutdown(&mut proxy_shutdown) => break,
                    _ = wait_for_shutdown(&mut transport_shutdown) => break,
                }
            }

            // Stop accepting new connections, then wait for every in-flight connection to
            // observe the same shutdown signal and exit before this task itself finishes -
            // this is what makes `shutdown`/`stop` awaitable rather than fire-and-forget.
            while connections.join_next().await.is_some() {}
        });

        Ok(Self {
            address,
            task,
            shutdown_tx,
        })
    }

    /// The IPv4 loopback address on which this proxy is listening.
    #[must_use]
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Stop accepting connections, cancel every connection currently being proxied, and wait
    /// for the listener and all forwarding tasks to actually terminate before returning.
    pub async fn shutdown(mut self) {
        let _ = self.shutdown_tx.send(true);
        let _ = (&mut self.task).await;
    }
}

impl Drop for TorSocksProxy {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        self.task.abort();
    }
}

/// How long a local client has to complete the SOCKS5 handshake.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Resolves once `rx` carries (or ever changes to) `true`. Checks the current value first so a
/// receiver subscribed after the flip does not miss it by waiting on `changed()` alone.
async fn wait_for_shutdown(rx: &mut watch::Receiver<bool>) {
    if *rx.borrow() {
        return;
    }
    while rx.changed().await.is_ok() {
        if *rx.borrow() {
            return;
        }
    }
}

/// Isolates proxied streams by the SOCKS5 username/password the connecting client presented,
/// matching upstream SimpleX's own `SocksIsolateByAuth` expectation (see
/// `docs/security-remediation-plan.md` Phase R4): two streams that authenticated with the same
/// credentials may share a circuit, two that authenticated differently (or one that sent no
/// auth at all vs one that did) never will. `tor-socksproto`'s server-side handshake already
/// accepts a USERNAME/PASSWORD SOCKS5 auth method from the client, so a caller like SimpleX that
/// generates a fresh random username/password per connection gets a fresh circuit per
/// connection "for free" - this type is what turns that already-accepted auth into an actual
/// `arti_client::StreamPrefs` isolation instead of silently discarding it and pooling every
/// proxied stream onto the transport's shared default isolation.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ConnectionIsolation(SocksAuth);

impl IsolationHelper for ConnectionIsolation {
    fn compatible_same_type(&self, other: &Self) -> bool {
        self == other
    }

    fn join_same_type(&self, other: &Self) -> Option<Self> {
        (self == other).then(|| self.clone())
    }
}

async fn serve(
    mut socket: TcpStream,
    lifecycle: &Mutex<TransportLifecycle>,
    client: &Mutex<Option<Arc<TorClient<PreferredRuntime>>>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Local clients get a bounded time to finish the SOCKS handshake, so a silent connection
    // cannot hold a task (and its socket) open indefinitely.
    let request = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_request(&mut socket)).await??;

    if request.command() != SocksCmd::CONNECT {
        socket
            .write_all(&request.reply(SocksStatus::COMMAND_NOT_SUPPORTED, None)?)
            .await?;
        return Ok(());
    }

    let SocksAddr::Hostname(hostname) = request.addr() else {
        socket
            .write_all(&request.reply(SocksStatus::ADDRTYPE_NOT_SUPPORTED, None)?)
            .await?;
        return Ok(());
    };

    let tor_client = match ready_client(lifecycle, client) {
        Ok(client) => client,
        Err(_) => {
            socket
                .write_all(&request.reply(SocksStatus::NOT_ALLOWED, None)?)
                .await?;
            return Ok(());
        }
    };

    let mut prefs = StreamPrefs::new();
    prefs.set_isolation(ConnectionIsolation(request.auth().clone()));

    let mut stream = match tor_client
        .connect_with_prefs((hostname.as_ref().to_owned(), request.port()), &prefs)
        .await
    {
        Ok(stream) => stream,
        Err(_) => {
            socket
                .write_all(&request.reply(SocksStatus::HOST_UNREACHABLE, None)?)
                .await?;
            return Ok(());
        }
    };

    socket
        .write_all(&request.reply(SocksStatus::SUCCEEDED, None)?)
        .await?;

    // Shutdown is raced by the caller around this whole function, so dropping this future
    // mid-transfer closes both `socket` and `stream`.
    tokio::io::copy_bidirectional(&mut socket, &mut stream).await?;
    Ok(())
}

async fn read_request(
    socket: &mut TcpStream,
) -> Result<tor_socksproto::SocksRequest, tor_socksproto::Error> {
    let mut handshake = SocksProxyHandshake::new();
    let mut buffer = Buffer::<PreciseReads>::new_precise();

    loop {
        match handshake.step(&mut buffer)? {
            NextStep::Send(reply) => socket
                .write_all(&reply)
                .await
                .map_err(|_| tor_socksproto::Error::UnexpectedEof)?,
            NextStep::Recv(mut recv) => {
                let received = socket
                    .read(recv.buf())
                    .await
                    .map_err(|_| tor_socksproto::Error::UnexpectedEof)?;
                recv.note_received(received)?;
            }
            NextStep::Finished(request) => return request.into_output().map_err(Into::into),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use arti_client::isolation::Isolation;

    use super::*;

    async fn proxy_without_tor() -> (TorSocksProxy, watch::Sender<bool>) {
        let (transport_tx, transport_rx) = watch::channel(false);
        let proxy = TorSocksProxy::start(
            Arc::new(Mutex::new(TransportLifecycle::new())),
            Arc::new(Mutex::new(None)),
            transport_rx,
        )
        .await
        .expect("bind loopback listener");
        (proxy, transport_tx)
    }

    #[tokio::test]
    async fn shutdown_completes_while_a_client_is_stalled_mid_handshake() {
        let (proxy, _transport) = proxy_without_tor().await;
        // Connects and sends nothing; a second client sends only a partial greeting.
        let _silent = TcpStream::connect(proxy.address()).await.expect("connect");
        let mut partial = TcpStream::connect(proxy.address()).await.expect("connect");
        partial.write_all(&[5]).await.expect("partial greeting");
        tokio::time::sleep(Duration::from_millis(50)).await;

        tokio::time::timeout(Duration::from_secs(5), proxy.shutdown())
            .await
            .expect("shutdown must not wait on a client that never finishes its handshake");
    }

    #[tokio::test]
    async fn transport_stop_releases_a_stalled_client_too() {
        let (proxy, transport) = proxy_without_tor().await;
        let mut silent = TcpStream::connect(proxy.address()).await.expect("connect");
        tokio::time::sleep(Duration::from_millis(50)).await;

        transport.send(true).expect("signal transport stop");
        let mut buf = [0_u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(5), silent.read(&mut buf))
            .await
            .expect("the proxy must close the stalled connection");
        assert!(
            matches!(read, Ok(0) | Err(_)),
            "connection must be closed, got {read:?}"
        );
        tokio::time::timeout(Duration::from_secs(5), proxy.shutdown())
            .await
            .expect("shutdown after transport stop");
    }

    #[tokio::test]
    async fn socks_listener_refuses_after_stop() {
        let (proxy, transport) = proxy_without_tor().await;
        let address = proxy.address();
        transport.send(true).expect("signal transport stop");
        tokio::time::timeout(Duration::from_secs(5), proxy.shutdown())
            .await
            .expect("shutdown after stop");
        assert!(
            TcpStream::connect(address).await.is_err(),
            "the listener must be closed once the transport stops"
        );
    }

    #[test]
    fn same_socks_auth_is_compatible_isolation() {
        let a = ConnectionIsolation(SocksAuth::Username(b"tok".to_vec(), b"tok".to_vec()));
        let b = ConnectionIsolation(SocksAuth::Username(b"tok".to_vec(), b"tok".to_vec()));
        assert!(Isolation::compatible(&a, &b));
    }

    #[test]
    fn distinct_socks_auth_is_incompatible_isolation() {
        let a = ConnectionIsolation(SocksAuth::Username(b"one".to_vec(), b"one".to_vec()));
        let b = ConnectionIsolation(SocksAuth::Username(b"two".to_vec(), b"two".to_vec()));
        assert!(!Isolation::compatible(&a, &b));
    }

    #[test]
    fn no_auth_is_incompatible_with_any_authenticated_connection() {
        let unauthenticated = ConnectionIsolation(SocksAuth::NoAuth);
        let authenticated = ConnectionIsolation(SocksAuth::Username(b"x".to_vec(), b"x".to_vec()));
        assert!(!Isolation::compatible(&unauthenticated, &authenticated));
    }
}
