//! Process supervision and WebSocket transport for a `simplex-chat -p <port>` subprocess.
//!
//! # What has and has not been exercised
//!
//! This module has **not** been run against a real `simplex-chat` binary: building the
//! Haskell `simplex-chat` CLI is impractical in this development environment (no Haskell
//! toolchain, and building GHC/cabal dependencies from scratch is a multi-hour undertaking even
//! with network access), so there is nothing to actually launch and connect to here. It
//! compiles and implements the documented `{corrId, cmd}` / `{corrId, resp}` WebSocket protocol
//! (see [`crate::simplex::protocol`] and `simplex-chat`'s own `bots/README.md`) faithfully, but
//! the process-spawn-then-connect sequence, real command/response round trips, and the event
//! stream have never actually run. This is the same category of gap as `secure-transport`'s
//! unexercised live Tor bootstrap - type-correct and protocol-correct as far as this
//! environment allows, not yet empirically run. See `docs/implementation-plan.md` Phase 3.

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use thiserror::Error;
use tokio::process::{Child, Command};
use tokio::sync::{Mutex as AsyncMutex, mpsc};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

use super::protocol::{CommandEnvelope, CorrelationTable, IncomingEnvelope};

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("failed to spawn the simplex-chat process: {0}")]
    Spawn(#[source] std::io::Error),
    #[error(
        "failed to connect to the simplex-chat WebSocket server after {attempts} attempts: {source}"
    )]
    Connect {
        attempts: u32,
        #[source]
        source: tokio_tungstenite::tungstenite::Error,
    },
    #[error("command timed out waiting for a response")]
    Timeout,
    #[error("the connection to simplex-chat was closed")]
    ConnectionClosed,
    #[error("failed to send a command: {0}")]
    Send(#[source] tokio_tungstenite::tungstenite::Error),
    #[error("failed to serialise a command: {0}")]
    Malformed(#[source] serde_json::Error),
}

type WsStream = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// How long to wait for a command's response before giving up. `simplex-chat` documents some
/// commands as "network usage: interactive" (may involve a relay round trip) versus
/// "background" (local only); this is a single conservative timeout for both rather than a
/// per-command budget, since there is no live process here to calibrate a tighter value
/// against.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// How many times to retry connecting to the WebSocket port after spawning the process, and
/// how long to wait between attempts, while the CLI finishes starting up and binds the port.
const CONNECT_RETRY_ATTEMPTS: u32 = 20;
const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(250);

/// A running `simplex-chat -p <port>` subprocess and its WebSocket connection.
pub struct SimplexClient {
    child: Child,
    write: AsyncMutex<futures_util::stream::SplitSink<WsStream, Message>>,
    correlations: Arc<CorrelationTable>,
    /// Set once the background read task exits, so `send_command` can fail fast with
    /// [`ClientError::ConnectionClosed`] instead of hanging on a `corrId` that will never
    /// receive a response.
    reader_task: tokio::task::JoinHandle<()>,
}

/// Chat events pushed by `simplex-chat` that do not correlate to a command this client sent -
/// see [`super::protocol::CorrelationTable::route`]. Each item is the raw `resp` JSON object;
/// this crate does not yet parse specific event shapes (`NewChatItems`, `ContactConnected`,
/// etc.) into typed values - see the module-level gap note.
pub type EventReceiver = mpsc::UnboundedReceiver<serde_json::Value>;

impl SimplexClient {
    /// Launch `simplex-chat -p <port> --database-file <database_path>` and connect to its
    /// WebSocket server, retrying the connection while the process finishes starting up.
    pub async fn launch(
        binary_path: &PathBuf,
        port: u16,
        database_path: &PathBuf,
    ) -> Result<(Self, EventReceiver), ClientError> {
        let child = Command::new(binary_path)
            .arg("-p")
            .arg(port.to_string())
            .arg("--database-file")
            .arg(database_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(ClientError::Spawn)?;

        let url = format!("ws://127.0.0.1:{port}");
        let mut last_error = None;
        let mut stream = None;
        for _ in 0..CONNECT_RETRY_ATTEMPTS {
            match connect_async(&url).await {
                Ok((ws, _response)) => {
                    stream = Some(ws);
                    break;
                }
                Err(error) => {
                    last_error = Some(error);
                    tokio::time::sleep(CONNECT_RETRY_DELAY).await;
                }
            }
        }

        let Some(stream) = stream else {
            let mut child = child;
            let _ = child.kill().await;
            return Err(ClientError::Connect {
                attempts: CONNECT_RETRY_ATTEMPTS,
                source: last_error.expect("loop only exits without a stream if an error occurred"),
            });
        };

        let (write, mut read) = stream.split();
        let correlations = Arc::new(CorrelationTable::new());
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        let reader_correlations = Arc::clone(&correlations);
        let reader_task = tokio::spawn(async move {
            while let Some(message) = read.next().await {
                let Ok(message) = message else {
                    break;
                };
                // A non-text frame (ping/pong/binary/close) or a text frame that isn't a valid
                // IncomingEnvelope is skipped rather than treated as fatal: this loop has no
                // per-frame error channel back to a caller (it is a detached background task,
                // not something a single `send_command` call is waiting on), and killing the
                // whole connection over one unexpected frame would be worse than ignoring it.
                let Message::Text(text) = message else {
                    continue;
                };
                let Ok(envelope) = serde_json::from_str::<IncomingEnvelope>(&text) else {
                    continue;
                };
                if let Some(event) = reader_correlations.route(envelope) {
                    // The only failure mode is "no receiver left", meaning the client has
                    // already been dropped; nothing to do but stop forwarding.
                    if event_tx.send(event).is_err() {
                        break;
                    }
                }
            }
        });

        Ok((
            Self {
                child,
                write: AsyncMutex::new(write),
                correlations,
                reader_task,
            },
            event_rx,
        ))
    }

    /// Send a raw command string and wait for its correlated response, or
    /// [`ClientError::Timeout`]/[`ClientError::ConnectionClosed`] if none arrives.
    pub async fn send_command(&self, cmd: String) -> Result<serde_json::Value, ClientError> {
        if self.reader_task.is_finished() {
            return Err(ClientError::ConnectionClosed);
        }

        let (corr_id, rx) = self.correlations.register();
        let envelope = CommandEnvelope { corr_id, cmd };
        let json = serde_json::to_string(&envelope).map_err(ClientError::Malformed)?;

        self.write
            .lock()
            .await
            .send(Message::Text(json.into()))
            .await
            .map_err(ClientError::Send)?;

        match timeout(COMMAND_TIMEOUT, rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => Err(ClientError::ConnectionClosed),
            Err(_) => Err(ClientError::Timeout),
        }
    }

    /// Stop the subprocess. Aborts the background reader task first so it cannot observe (and
    /// misinterpret) the connection tearing down, then kills the child process - `kill_on_drop`
    /// on the underlying [`Command`] means this would also happen on drop, but doing it
    /// explicitly lets a caller await completion rather than leaving it to happen
    /// asynchronously at an unspecified time.
    pub async fn shutdown(mut self) {
        self.reader_task.abort();
        let _ = self.child.kill().await;
    }
}
