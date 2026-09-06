use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use arti_client::TorClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
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
/// Dropping or explicitly shutting down this handle aborts the listener and every connection
/// it accepted. The bound address is safe to pass to a local subprocess; the listener never
/// binds a non-loopback interface.
pub struct TorSocksProxy {
    address: SocketAddr,
    task: JoinHandle<()>,
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
    ) -> Result<Self, TransportError> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(TransportError::SocksBind)?;
        let address = listener
            .local_addr()
            .map_err(TransportError::SocksAddress)?;

        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            while let Ok((socket, _peer)) = listener.accept().await {
                let lifecycle = Arc::clone(&lifecycle);
                let client = Arc::clone(&client);
                connections.spawn(async move {
                    let _ = serve(socket, &lifecycle, &client).await;
                });
            }
        });

        Ok(Self { address, task })
    }

    /// The IPv4 loopback address on which this proxy is listening.
    #[must_use]
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Stop accepting connections and abort every connection currently being proxied.
    pub async fn shutdown(mut self) {
        self.task.abort();
        let _ = (&mut self.task).await;
    }
}

impl Drop for TorSocksProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(
    mut socket: TcpStream,
    lifecycle: &Mutex<TransportLifecycle>,
    client: &Mutex<Option<Arc<TorClient<PreferredRuntime>>>>,
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
