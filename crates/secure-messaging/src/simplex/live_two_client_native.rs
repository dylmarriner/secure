//! Two-client native SimpleX-over-Tor proof. Run one `host` locally and one `client` on a
//! separate machine. The client receives the invitation through the operator's channel.

#![cfg(feature = "simplex-native")]

use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::time::Duration;

use secure_messaging::{ChatEvent, NativeSimplexAdapter, parse_chat_event};
use tokio::time::timeout;
use zeroize::Zeroizing;

const SOCKS: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9050);
const WAIT: Duration = Duration::from_secs(180);

fn db_prefix(role: &str) -> PathBuf {
    std::env::var_os("SECURE_LIVE_DB")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!("secure-r4-{role}-{}", std::process::id()))
        })
}

fn record_event(role: &str, raw: &serde_json::Value) {
    if let Some(path) = std::env::var_os("SECURE_LIVE_EVENT_FILE") {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("open event handoff");
        writeln!(file, "{role}: {raw}").expect("write event handoff");
    }
}

async fn open(role: &str) -> (NativeSimplexAdapter, secure_messaging::EventReceiver) {
    let (adapter, events) = NativeSimplexAdapter::open(
        db_prefix(role),
        Zeroizing::new(format!("secure-r4-{role}-key")),
    )
    .await
    .expect("native client opens");
    adapter.bootstrap().await.expect("native bootstrap");
    adapter
        .configure_network(SOCKS)
        .await
        .expect("Tor SOCKS config");
    (adapter, events)
}

#[tokio::test]
#[ignore = "requires a real native library, Tor SOCKS on 127.0.0.1:9050, and two machines"]
async fn two_fresh_clients_exchange_a_message() {
    let role = std::env::var("SECURE_LIVE_ROLE").expect("SECURE_LIVE_ROLE=host|client");
    if role == "host" {
        let (adapter, mut events) = open("host").await;
        let invitation = adapter
            .create_invitation()
            .await
            .expect("create invitation");
        println!("SECURE_R4_INVITATION={}", invitation.link);
        if let Some(path) = std::env::var_os("SECURE_LIVE_INVITATION_FILE") {
            std::fs::write(path, &invitation.link).expect("write invitation handoff");
        }
        eprintln!("waiting for the remote client to connect and send...");
        while let Ok(Some(raw)) = timeout(WAIT, events.recv()).await {
            record_event("host", &raw);
            eprintln!("SECURE_R4_HOST_EVENT={raw}");
            for event in parse_chat_event(raw) {
                if let ChatEvent::IncomingMessage(message) = event {
                    assert_eq!(message.text, "secure-r4-two-client-proof");
                    println!("SECURE_R4_RECEIVED contact_id={}", message.contact_id);
                    adapter.shutdown().await;
                    return;
                }
            }
        }
        panic!("timed out waiting for the remote message");
    }

    assert_eq!(role, "client", "role must be host or client");
    let invitation = std::env::var("SECURE_LIVE_INVITATION")
        .expect("SECURE_LIVE_INVITATION must contain the host link");
    let (adapter, mut events) = open("client").await;
    if let Some(contact_id) = adapter
        .accept_invitation_with_contact_id(&invitation)
        .await
        .expect("accept invitation")
    {
        adapter
            .send_text_message(contact_id, "secure-r4-two-client-proof")
            .await
            .expect("send message");
        println!("SECURE_R4_SENT contact_id={contact_id}");
        adapter.shutdown().await;
        return;
    }
    while let Ok(Some(raw)) = timeout(WAIT, events.recv()).await {
        record_event("client", &raw);
        eprintln!("SECURE_R4_CLIENT_EVENT={raw}");
        if raw.get("type").and_then(serde_json::Value::as_str) == Some("contactConnecting") {
            if let Some(contact_id) = raw
                .get("contact")
                .and_then(|contact| contact.get("contactId"))
                .and_then(serde_json::Value::as_i64)
            {
                adapter
                    .send_text_message(contact_id, "secure-r4-two-client-proof")
                    .await
                    .expect("send message");
                println!("SECURE_R4_SENT contact_id={contact_id}");
                adapter.shutdown().await;
                return;
            }
        }
        for event in parse_chat_event(raw) {
            if let ChatEvent::ContactConnected(contact) = event {
                adapter
                    .send_text_message(contact.contact_id, "secure-r4-two-client-proof")
                    .await
                    .expect("send message");
                println!("SECURE_R4_SENT contact_id={}", contact.contact_id);
                adapter.shutdown().await;
                return;
            }
        }
    }
    panic!("timed out waiting for contact connection");
}
