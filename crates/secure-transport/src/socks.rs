use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use arti_client::TorClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};
use tor_rtcompat::PreferredRuntime;
use tor_socksproto::{
    Buffer, Handshake, NextStep, PreciseReads, SocksAddr, SocksCmd, SocksProxyHandshake,
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
                            let _ = serve(
                                socket,
                                &lifecycle,
                                &client,
                                &mut conn_proxy_shutdown,
                                &mut conn_transport_shutdown,
                            )
                            .await;
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

async fn serve(
    mut socket: TcpStream,
    lifecycle: &Mutex<TransportLifecycle>,
    client: &Mutex<Option<Arc<TorClient<PreferredRuntime>>>>,
    proxy_shutdown: &mut watch::Receiver<bool>,
    transport_shutdown: &mut watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let request = read_request(&mut socket).await?;

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

    let mut stream = match tor_client
        .connect((hostname.as_ref().to_owned(), request.port()))
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

    // A shutdown signal wins the race against an in-progress transfer: dropping the
    // `copy_bidirectional` future here drops and closes both `socket` and `stream`, so neither
    // side of an already-proxied connection survives past `stop`/`shutdown`.
    tokio::select! {
        result = tokio::io::copy_bidirectional(&mut socket, &mut stream) => { result?; }
        () = wait_for_shutdown(proxy_shutdown) => {}
        () = wait_for_shutdown(transport_shutdown) => {}
    }
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
