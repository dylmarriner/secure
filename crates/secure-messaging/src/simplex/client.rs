//! Process supervision and WebSocket transport for a `simplex-chat -p <port>` subprocess.
//!
//! # What has been verified against a real binary
//!
//! This module has been run against the real `simplex-chat` v7.0.0.12 CLI (prebuilt
//! `ubuntu-24_04-x86_64` release binary) and a real spawn-connect-command-response cycle
//! succeeded. That run found two real bugs that no amount of type-checking against the
//! documented API could have caught, because both were about the CLI's actual command-line
//! interface, not its WebSocket protocol:
//!
//! - `--database-file <path>` is not a real flag. The real flag is `-d`/`--database <path>`, a
//!   path *prefix* (the CLI creates `<prefix>_chat.db`/`<prefix>_agent.db` etc. under it), not
//!   a single file path;
//! - the database is encrypted with `-k`/`--key <KEY>` (`Simplex.Chat.Options.Sqlite.chatDbOptsP`
//!   upstream - confirmed against that source, not guessed), which this crate always supplies:
//!   an unencrypted `simplex-chat` database would put message/session state on disk in plaintext,
//!   which is exactly the "no application-controlled plaintext persistence" invariant the rest of
//!   this workspace (`secure-storage`'s SQLCipher vault) is built around. There is no environment
//!   variable or key-file alternative upstream, only this CLI flag, so the key is visible in this
//!   process's argv (e.g. via `/proc/<pid>/cmdline`) to anything else able to read it - the same
//!   exposure any CLI tool taking a secret as an argument has; there is no more private way to
//!   hand this specific upstream binary a key;
//! - the SOCKS proxy is `--socks-proxy <ipv4:port>` (`Simplex.Chat.Options.chatOptsP` upstream),
//!   which this crate always supplies pointed at the caller's Tor SOCKS bridge
//!   (`secure_transport::TorTransport::start_socks_proxy`) rather than making it optional: an
//!   optional proxy is a clearnet-fallback footgun, and this crate's only job per
//!   `docs/security-architecture.md` is Tor-only transport;
//! - the WebSocket server does **not** start listening until first-run profile setup
//!   completes. With `stdin` closed (as this crate deliberately does - see [`SimplexClient::launch`]
//!   docs above the `Command` construction), an instance with no existing profile exits
//!   immediately (`hGetLine: end of file`) without ever binding the port, unless
//!   `--user-display-name` is supplied on the command line to skip the interactive prompt.
//!
//! With both fixed, a live run confirmed the exact request/response cycle this crate
//! implements: `/_start` → `chatRunning`, `/_create user <json>` → `activeUser` (creating a
//! *second* user distinct from the one `--user-display-name` created at spawn - which is why
//! [`super::adapter::SimplexAdapter::bootstrap`] uses `/user` (`ShowActiveUser`) instead, to
//! read back the CLI-created user rather than create a redundant one), and
//! `/_connect <userId>` → a real `invitation` response with a genuine `simplex:` URI in
//! `connLinkInvitation.connFullLink`, exactly the field
//! [`super::adapter`]'s response parsing already expected.
//!
//! Not yet run this way: a second instance actually accepting an invitation from the first and
//! a real end-to-end message round trip. See `docs/implementation-plan.md` Phase 3.
//!
//! # This is the CLI integration harness, not the production secret-delivery path
//!
//! `docs/security-remediation-plan.md` Phase R3 requires that no production launch path place
//! the SimpleX database key in this process's argv. The upstream `simplex-chat` CLI has no other
//! way to take that key - see the `-k`/`--key` note above - so this module's [`SimplexClient`]
//! is explicitly retained as an integration-test/dev-only adapter, kept because it is a real,
//! working, independently useful compatibility harness against the actual upstream binary, not
//! because it is an acceptable production boundary. The production path is
//! [`super::core::SimplexCore`] (behind the `simplex-native` cargo feature), which links
//! upstream's native core and calls its in-memory key API (`chat_migrate_init_key`) instead of
//! spawning this CLI - see that module for the build recipe and what has been verified against
//! the real library. Do not wire this module into a production launch path.

use std::net::SocketAddr;
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
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async_with_config};
use zeroize::Zeroizing;

use super::protocol::{
    CommandEnvelope, CorrelationTable, IncomingEnvelope, PendingGuard, RegisterError,
};

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("database encryption key must not be empty")]
    EmptyDatabaseKey,
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
    #[error("too many commands are already awaiting a response")]
    Busy,
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
/// how long to wait between attempts, while the CLI finishes starting up, creates its profile
/// and database, and binds the port. A live run observed the port opening in roughly 3-5
/// seconds on an otherwise-idle machine; this budget (up to 60 * 250ms = 15s) leaves real
/// margin above that for a slower disk/first-run database migration rather than cutting it
/// close to what was merely observed once.
const CONNECT_RETRY_ATTEMPTS: u32 = 60;
const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(250);

/// Largest WebSocket message/frame accepted from `simplex-chat`
/// (`docs/security-remediation-plan.md` Phase R7). Chat events are JSON metadata - file
/// contents never travel over this API - so even a large `newChatItems` batch is far below
/// this; tungstenite's own defaults (64MiB/16MiB) would let one event force a large allocation.
/// An oversized message is a protocol error that closes the connection and releases every
/// waiter, rather than being buffered.
pub(crate) const MAX_WS_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

/// How many parsed-but-unconsumed chat events may queue before the producer waits. Bounded so a
/// flood of events from the core cannot grow memory without limit; when full, the reader stops
/// pulling from the socket, which pushes back on the sender instead.
pub(crate) const EVENT_CHANNEL_CAPACITY: usize = 1024;

/// Chat events pushed by `simplex-chat` that do not correlate to a command this client sent -
/// see [`super::protocol::CorrelationTable::route`]. Each item is the raw `resp` JSON object;
/// parse it with [`crate::parse_chat_event`].
pub type EventReceiver = mpsc::Receiver<serde_json::Value>;

fn websocket_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_WS_MESSAGE_BYTES))
        .max_frame_size(Some(MAX_WS_MESSAGE_BYTES))
}

/// The WebSocket half of a [`SimplexClient`]: request/response correlation, bounded event
/// forwarding and teardown. Separate from process supervision so it can be exercised against a
/// local fake server in tests without a real `simplex-chat` binary.
struct Connection {
    write: AsyncMutex<futures_util::stream::SplitSink<WsStream, Message>>,
    correlations: Arc<CorrelationTable>,
    reader_task: tokio::task::JoinHandle<()>,
}

impl Connection {
    async fn connect(
        url: &str,
    ) -> Result<(Self, EventReceiver), tokio_tungstenite::tungstenite::Error> {
        let (stream, _response) =
            connect_async_with_config(url, Some(websocket_config()), false).await?;
        let (write, mut read) = stream.split();
        let correlations = Arc::new(CorrelationTable::new());
        let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);

        let reader_correlations = Arc::clone(&correlations);
        let reader_task = tokio::spawn(async move {
            while let Some(message) = read.next().await {
                // Any read error - including an over-limit message - ends the connection.
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
                    if event_tx.send(event).await.is_err() {
                        break;
                    }
                }
            }
            // No response can arrive any more: wake every waiter now rather than leaving each
            // to run out its full timeout.
            reader_correlations.close();
        });

        Ok((
            Self {
                write: AsyncMutex::new(write),
                correlations,
                reader_task,
            },
            event_rx,
        ))
    }

    async fn send_command(
        &self,
        cmd: String,
        wait: Duration,
    ) -> Result<serde_json::Value, ClientError> {
        let (corr_id, rx) = self.correlations.register().map_err(|error| match error {
            RegisterError::TooManyInFlight => ClientError::Busy,
            RegisterError::Closed => ClientError::ConnectionClosed,
        })?;
        // Removes the entry however this call ends: timeout, send error, or the caller dropping
        // this future mid-await.
        let _pending = PendingGuard::new(&self.correlations, corr_id.clone());
        let envelope = CommandEnvelope { corr_id, cmd };
        let json = serde_json::to_string(&envelope).map_err(ClientError::Malformed)?;

        self.write
            .lock()
            .await
            .send(Message::Text(json.into()))
            .await
            .map_err(ClientError::Send)?;

        match timeout(wait, rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => Err(ClientError::ConnectionClosed),
            Err(_) => Err(ClientError::Timeout),
        }
    }

    /// Stop reading and release every outstanding waiter with
    /// [`ClientError::ConnectionClosed`].
    fn close(&self) {
        self.reader_task.abort();
        self.correlations.close();
    }
}

/// A running `simplex-chat -p <port>` subprocess and its WebSocket connection.
pub struct SimplexClient {
    child: Child,
    connection: Connection,
}

impl SimplexClient {
    /// Launch
    /// `simplex-chat -d <database_path> -k <database_key> -p <port> --socks-proxy <socks_proxy>
    /// -y --user-display-name <display_name>` and connect to its WebSocket server, retrying the
    /// connection while the process finishes starting up.
    ///
    /// `database_key` and `socks_proxy` are required, not optional: an empty key would leave
    /// `simplex-chat`'s own database unencrypted, and there is no clearnet-fallback mode for the
    /// SOCKS proxy - see this module's top-level docs for why each flag is what it is. `-y`
    /// (`--yes-migrate`) avoids an interactive confirmation prompt on a schema migration after a
    /// `simplex-chat` upgrade. `--user-display-name` is not optional despite looking like a
    /// convenience flag: `stdin` is closed below (`Stdio::null()`), and without an existing
    /// profile the CLI's WebSocket server never starts listening at all - it blocks on an
    /// interactive "choose your display name" prompt first. This was found by running it, not by
    /// reading the CLI's own `--help` output, which does not make that ordering obvious - see
    /// this module's top-level docs.
    ///
    /// stdout/stderr go to `Stdio::null()`: a piped stream nobody reads fills its OS buffer and
    /// then blocks the child on its next write (Phase R7), and the CLI's terminal output can echo
    /// message content, which must not be captured into this process's logs either.
    pub async fn launch(
        binary_path: &PathBuf,
        port: u16,
        database_path: &PathBuf,
        database_key: &Zeroizing<String>,
        socks_proxy: SocketAddr,
        display_name: &str,
    ) -> Result<(Self, EventReceiver), ClientError> {
        if database_key.is_empty() {
            return Err(ClientError::EmptyDatabaseKey);
        }

        let mut child = Command::new(binary_path)
            .arg("-d")
            .arg(database_path)
            .arg("-k")
            .arg(database_key.as_str())
            .arg("-p")
            .arg(port.to_string())
            .arg("--socks-proxy")
            .arg(socks_proxy.to_string())
            .arg("-y")
            .arg("--user-display-name")
            .arg(display_name)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(ClientError::Spawn)?;

        let url = format!("ws://127.0.0.1:{port}");
        let mut last_error = None;
        for _ in 0..CONNECT_RETRY_ATTEMPTS {
            match Connection::connect(&url).await {
                Ok((connection, events)) => {
                    return Ok((Self { child, connection }, events));
                }
                Err(error) => {
                    last_error = Some(error);
                    tokio::time::sleep(CONNECT_RETRY_DELAY).await;
                }
            }
        }

        let _ = child.kill().await;
        Err(ClientError::Connect {
            attempts: CONNECT_RETRY_ATTEMPTS,
            source: last_error.expect("loop only exits without a stream if an error occurred"),
        })
    }

    /// Send a raw command string and wait for its correlated response, or
    /// [`ClientError::Timeout`]/[`ClientError::ConnectionClosed`]/[`ClientError::Busy`].
    pub async fn send_command(&self, cmd: String) -> Result<serde_json::Value, ClientError> {
        self.connection.send_command(cmd, COMMAND_TIMEOUT).await
    }

    /// Stop the subprocess. Closes the connection first - aborting the reader task so it cannot
    /// observe (and misinterpret) the teardown, and resolving every outstanding command with
    /// [`ClientError::ConnectionClosed`] - then kills the child process. `kill_on_drop` on the
    /// underlying [`Command`] means the kill would also happen on drop, but doing it explicitly
    /// lets a caller await completion.
    pub async fn shutdown(mut self) {
        self.connection.close();
        let _ = self.child.kill().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn launch_refuses_an_empty_database_key_without_spawning_a_process() {
        // A binary path that cannot possibly exist proves this is rejected before `Command::spawn`
        // is ever reached, not merely that spawning something eventually fails.
        let binary_path = PathBuf::from("/nonexistent/simplex-chat-binary-for-this-test");
        let database_path = PathBuf::from("/tmp/does-not-matter");
        let socks_proxy: SocketAddr = "127.0.0.1:9050".parse().expect("valid socket address");

        let result = SimplexClient::launch(
            &binary_path,
            0,
            &database_path,
            &Zeroizing::new(String::new()),
            socks_proxy,
            "test",
        )
        .await;

        assert!(matches!(result, Err(ClientError::EmptyDatabaseKey)));
    }

    /// What the fake server does with each command it receives.
    #[derive(Clone, Copy)]
    enum Behaviour {
        /// Never answer.
        Silent,
        /// Reply to the first command with a message larger than [`MAX_WS_MESSAGE_BYTES`].
        Oversized,
    }

    /// A local stand-in for `simplex-chat`'s WebSocket server.
    async fn fake_server(behaviour: Behaviour) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            let mut ws = tokio_tungstenite::accept_async(socket)
                .await
                .expect("handshake");
            while let Some(Ok(message)) = ws.next().await {
                if !message.is_text() {
                    continue;
                }
                if let Behaviour::Oversized = behaviour {
                    let padding = "x".repeat(MAX_WS_MESSAGE_BYTES + 1);
                    let event = format!("{{\"resp\":{{\"type\":\"pad\",\"p\":\"{padding}\"}}}}");
                    let _ = ws.send(Message::Text(event.into())).await;
                }
            }
        });
        format!("ws://{address}")
    }

    #[tokio::test]
    async fn timed_out_requests_leave_the_correlation_table_empty() {
        let url = fake_server(Behaviour::Silent).await;
        let (connection, _events) = Connection::connect(&url).await.expect("connect");

        let result = connection
            .send_command("/_start".to_owned(), Duration::from_millis(50))
            .await;
        assert!(matches!(result, Err(ClientError::Timeout)));
        assert_eq!(connection.correlations.pending_len(), 0);
    }

    #[tokio::test]
    async fn a_cancelled_command_future_leaves_the_correlation_table_empty() {
        let url = fake_server(Behaviour::Silent).await;
        let (connection, _events) = Connection::connect(&url).await.expect("connect");

        let pending = connection.send_command("/_start".to_owned(), Duration::from_secs(30));
        // Drop the future part-way through, as a caller abandoning the request would.
        let _ = timeout(Duration::from_millis(50), pending).await;
        assert_eq!(connection.correlations.pending_len(), 0);
    }

    #[tokio::test]
    async fn oversized_websocket_event_closes_the_connection_and_releases_waiters() {
        let url = fake_server(Behaviour::Oversized).await;
        let (connection, mut events) = Connection::connect(&url).await.expect("connect");

        let result = connection
            .send_command("/_start".to_owned(), Duration::from_secs(10))
            .await;
        assert!(
            matches!(result, Err(ClientError::ConnectionClosed)),
            "expected the over-limit message to close the connection, got {result:?}"
        );
        assert!(
            events.recv().await.is_none(),
            "oversized event must not be delivered"
        );
        assert!(matches!(
            connection
                .send_command("/user".to_owned(), Duration::from_secs(1))
                .await,
            Err(ClientError::ConnectionClosed)
        ));
    }

    #[tokio::test]
    async fn teardown_releases_all_waiting_commands() {
        let url = fake_server(Behaviour::Silent).await;
        let (connection, _events) = Connection::connect(&url).await.expect("connect");
        let connection = Arc::new(connection);

        let waiters: Vec<_> = (0..3)
            .map(|_| {
                let connection = Arc::clone(&connection);
                tokio::spawn(async move {
                    connection
                        .send_command("/_start".to_owned(), Duration::from_secs(30))
                        .await
                })
            })
            .collect();
        while connection.correlations.pending_len() < 3 {
            tokio::task::yield_now().await;
        }

        connection.close();
        for waiter in waiters {
            let result = timeout(Duration::from_secs(5), waiter)
                .await
                .expect("waiter must be released promptly, not left to time out")
                .expect("task");
            assert!(matches!(result, Err(ClientError::ConnectionClosed)));
        }
        assert_eq!(connection.correlations.pending_len(), 0);
    }
}
