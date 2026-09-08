//! Live verification against the real Tor network.
//!
//! Ignored by default: `cargo test --workspace` never needs network access, matching every
//! other test in this repository. Run explicitly with:
//!
//! ```text
//! cargo test -p secure-transport --test live_bootstrap -- --ignored --nocapture
//! ```
//!
//! on a machine with real outbound network access. This is the test that actually closed the
//! "has not been run against the live Tor network" gap this crate carried since Phase 2: on
//! first attempt it caught a real bug (`rustls` 0.23+ needs an explicit `CryptoProvider`
//! installed - `tor_rtcompat`'s `rustls` feature deliberately does not select one; see
//! `ensure_crypto_provider_installed` in `src/lib.rs`) that no amount of type-checking or
//! network-free unit testing could have found.

use std::time::Duration;

use secure_transport::TorTransport;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Generous but bounded: real Tor bootstrap over a healthy network link typically completes in
/// well under a minute; this leaves headroom for a slow link without hanging a CI run forever
/// if this were ever accidentally left un-ignored.
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(180);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

#[tokio::test]
#[ignore = "requires real outbound network access to the live Tor network"]
async fn bootstraps_and_connects_over_the_real_tor_network() {
    let dir = tempfile::tempdir().expect("tempdir");
    let transport = TorTransport::new(&dir.path().join("state"), &dir.path().join("cache"))
        .expect("build transport config");

    timeout(BOOTSTRAP_TIMEOUT, transport.start())
        .await
        .expect("bootstrap must not hang")
        .expect("bootstrap must succeed against the live Tor network");

    // check.torproject.org is the Tor Project's own "am I using Tor" endpoint - a reasonable,
    // stable, on-topic destination for this specific check, not an arbitrary third party.
    let stream = transport
        .connect("check.torproject.org", 443)
        .await
        .expect("must be able to open a stream over Tor once Ready");
    drop(stream);

    let proxy = transport
        .start_socks_proxy()
        .await
        .expect("must start loopback SOCKS proxy once Tor is ready");
    let mut socket = TcpStream::connect(proxy.address())
        .await
        .expect("must connect to loopback SOCKS proxy");
    socket
        .write_all(&[5, 1, 0])
        .await
        .expect("write SOCKS greeting");
    let mut greeting = [0_u8; 2];
    socket
        .read_exact(&mut greeting)
        .await
        .expect("read SOCKS greeting response");
    assert_eq!(greeting, [5, 0]);

    let host = b"check.torproject.org";
    let mut request = vec![5, 1, 0, 3, host.len() as u8];
    request.extend_from_slice(host);
    request.extend_from_slice(&443_u16.to_be_bytes());
    socket
        .write_all(&request)
        .await
        .expect("write SOCKS request");
    let mut response = [0_u8; 10];
    timeout(CONNECT_TIMEOUT, socket.read_exact(&mut response))
        .await
        .expect("SOCKS connect must not hang")
        .expect("read SOCKS connect response");
    assert_eq!(response[0], 5);
    assert_eq!(response[1], 0, "SOCKS proxy must open the stream over Tor");

    let proxy_address = proxy.address();
    proxy.shutdown().await;

    // R2 exit criterion: a proxied stream works before stop and is unusable after stop. The
    // listener task exits on shutdown, so a fresh connection attempt to the same loopback
    // address must be refused rather than silently reused or left half-open.
    TcpStream::connect(proxy_address)
        .await
        .expect_err("SOCKS proxy must refuse new connections once shut down");

    transport.stop().expect("stop");

    transport
        .connect("check.torproject.org", 443)
        .await
        .expect_err("Tor transport must refuse new streams once stopped");
}
