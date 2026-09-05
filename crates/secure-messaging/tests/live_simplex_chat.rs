//! Live verification against a real `simplex-chat` binary.
//!
//! Ignored by default - this needs an actual `simplex-chat` CLI binary, which this repository
//! does not vendor (it's a large, separately-released Haskell binary; see `docs/licensing.md`
//! for why it isn't linked as a Rust dependency at all). Run explicitly:
//!
//! ```text
//! SIMPLEX_CHAT_BIN=/path/to/simplex-chat \
//!   cargo test -p secure-messaging --test live_simplex_chat -- --ignored --nocapture
//! ```
//!
//! Without `SIMPLEX_CHAT_BIN` set, `simplex-chat` on `PATH` is tried. Prebuilt release binaries
//! for common platforms are published at
//! `https://github.com/simplex-chat/simplex-chat/releases`.
//!
//! This is the test that closed Phase 3's "has never been run against a real `simplex-chat`
//! process" gap. The first real run found two bugs neither type-checking nor the network-free
//! unit tests could have caught, because both were about the CLI's actual command-line
//! interface rather than its WebSocket protocol - see `src/simplex/client.rs`'s module docs for
//! what they were and how they were fixed.

use std::path::PathBuf;
use std::time::Duration;

use secure_messaging::SimplexAdapter;
use tokio::time::timeout;

const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

fn simplex_chat_binary() -> PathBuf {
    std::env::var_os("SIMPLEX_CHAT_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("simplex-chat"))
}

#[tokio::test]
#[ignore = "requires a real simplex-chat binary - see this file's module docs"]
async fn bootstraps_and_creates_a_real_invitation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let database_path = dir.path().join("db");

    let (adapter, _events) = timeout(
        STARTUP_TIMEOUT,
        SimplexAdapter::launch(
            simplex_chat_binary(),
            19_231,
            database_path,
            "secure-live-test",
        ),
    )
    .await
    .expect("launch must not hang")
    .expect("launch must succeed against a real simplex-chat binary");

    timeout(COMMAND_TIMEOUT, adapter.bootstrap())
        .await
        .expect("bootstrap must not hang")
        .expect("bootstrap must succeed");

    let invitation = timeout(COMMAND_TIMEOUT, adapter.create_invitation())
        .await
        .expect("create_invitation must not hang")
        .expect("create_invitation must succeed once bootstrapped");

    assert!(
        invitation.link.starts_with("simplex:"),
        "expected a simplex: URI, got: {}",
        invitation.link
    );

    adapter.shutdown().await;
}
