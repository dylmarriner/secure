//! The native core's startup command sequence, kept free of FFI so its ordering is unit-tested
//! in every build rather than only against the 233MB native library.
//!
//! # Why the order is a security property
//!
//! Upstream `StartChat` (`/_start`, `startChatController` in
//! `src/Simplex/Chat/Library/Commands.hs`) immediately resumes the SMP agent, subscribes every
//! existing connection to its relays, and starts the delivery/XFTP workers - using whatever
//! network config the agent holds *at that moment*. The agent's default config has no SOCKS
//! proxy, and the config is not persisted in the store, so on every launch with existing contacts
//! a `/_start` sent before `/_network` connects to relays directly, outside Tor, revealing the
//! user's IP address. `APISetNetworkConfig` only requires an active user (`withUser'`), not a
//! running chat, so the safe order is always possible:
//!
//! 1. read back the active user, creating it first on a fresh store;
//! 2. `/_network` pointing at Secure's loopback SOCKS bridge;
//! 3. `/network` read-back - abort (never start) unless it matches exactly;
//! 4. `/_start`.

use std::future::Future;
use std::net::SocketAddrV4;

use super::adapter::{AdapterError, extract_socks_proxy, extract_user_id};
use super::commands;

/// Whether a failed command's response is upstream's `noActiveUser` error.
pub(super) fn is_no_active_user(response: &serde_json::Value) -> bool {
    let error = response.get("error").or_else(|| response.get("chatError"));
    error
        .and_then(|error| error.get("errorType"))
        .and_then(|error_type| error_type.get("type"))
        .and_then(serde_json::Value::as_str)
        == Some("noActiveUser")
}

/// Point the core's network config at `socks_address` and prove it took effect.
pub(super) async fn configure_network<F, Fut>(
    socks_address: SocketAddrV4,
    run: &mut F,
) -> Result<(), AdapterError>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Result<serde_json::Value, AdapterError>>,
{
    run(commands::set_network_config(socks_address)).await?;
    let response = run(commands::get_network_config()).await?;
    let actual = extract_socks_proxy(&response);
    if actual.as_deref() != Some(commands::socks_proxy_string(socks_address).as_str()) {
        return Err(AdapterError::NetworkConfigMismatch {
            expected: socks_address,
            actual,
        });
    }
    Ok(())
}

/// Run the startup sequence described in the module docs through `run` and return the active
/// user's id. `/_start` is only ever sent after the network config has been verified.
pub(super) async fn bootstrap<F, Fut>(
    socks_address: SocketAddrV4,
    mut run: F,
) -> Result<i64, AdapterError>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Result<serde_json::Value, AdapterError>>,
{
    let user = match run(commands::show_active_user()).await {
        Ok(response) => response,
        Err(AdapterError::CommandFailed(response)) if is_no_active_user(&response) => {
            run(commands::create_native_user()).await?
        }
        Err(error) => return Err(error),
    };
    let user_id = extract_user_id(&user)?;
    configure_network(socks_address, &mut run).await?;
    run(commands::start_chat()).await?;
    Ok(user_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    const SOCKS: &str = "127.0.0.1:9150";

    type Reply = std::future::Ready<Result<serde_json::Value, AdapterError>>;
    type CommandLog = Arc<Mutex<Vec<String>>>;

    /// A fake core: records every command and answers from `respond`.
    fn fake(
        respond: impl Fn(&str) -> Result<serde_json::Value, AdapterError> + Send + Sync + 'static,
    ) -> (CommandLog, impl FnMut(String) -> Reply) {
        let log = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&log);
        let run = move |cmd: String| {
            let reply = respond(&cmd);
            sink.lock().expect("log").push(cmd);
            std::future::ready(reply)
        };
        (log, run)
    }

    fn healthy(cmd: &str) -> Result<serde_json::Value, AdapterError> {
        Ok(if cmd == "/user" || cmd.starts_with("/_create user") {
            serde_json::json!({"type": "activeUser", "user": {"userId": 7}})
        } else if cmd == "/network" {
            serde_json::json!({"type": "networkConfig", "networkConfig": {"socksProxy": SOCKS}})
        } else {
            serde_json::json!({"type": "cmdOk"})
        })
    }

    fn kind(cmd: &str) -> &str {
        cmd.split(' ').next().unwrap_or(cmd)
    }

    #[tokio::test]
    async fn network_is_configured_and_verified_before_chat_starts() {
        let (log, run) = fake(healthy);
        let user_id = bootstrap(SOCKS.parse().expect("addr"), run)
            .await
            .expect("bootstrap");
        assert_eq!(user_id, 7);
        let order: Vec<_> = log
            .lock()
            .expect("log")
            .iter()
            .map(|c| kind(c).to_owned())
            .collect();
        assert_eq!(order, ["/user", "/_network", "/network", "/_start"]);
    }

    #[tokio::test]
    async fn a_fresh_store_creates_the_user_before_configuring_network() {
        let (log, run) = fake(|cmd| {
            if cmd == "/user" {
                Err(AdapterError::CommandFailed(serde_json::json!({
                    "type": "error", "error": {"errorType": {"type": "noActiveUser"}}
                })))
            } else {
                healthy(cmd)
            }
        });
        bootstrap(SOCKS.parse().expect("addr"), run)
            .await
            .expect("bootstrap");
        let order: Vec<_> = log
            .lock()
            .expect("log")
            .iter()
            .map(|c| kind(c).to_owned())
            .collect();
        assert_eq!(
            order,
            ["/user", "/_create", "/_network", "/network", "/_start"]
        );
    }

    #[tokio::test]
    async fn chat_is_never_started_when_the_network_read_back_does_not_match() {
        let (log, run) = fake(|cmd| {
            if cmd == "/network" {
                Ok(serde_json::json!({"networkConfig": {"socksProxy": null}}))
            } else {
                healthy(cmd)
            }
        });
        let error = bootstrap(SOCKS.parse().expect("addr"), run)
            .await
            .expect_err("mismatch must fail closed");
        assert!(matches!(error, AdapterError::NetworkConfigMismatch { .. }));
        assert!(
            !log.lock().expect("log").iter().any(|c| c == "/_start"),
            "/_start must never be sent over an unverified network path"
        );
    }

    #[tokio::test]
    async fn chat_is_never_started_when_setting_the_network_config_fails() {
        let (log, run) = fake(|cmd| {
            if cmd.starts_with("/_network") {
                Err(AdapterError::CommandFailed(
                    serde_json::json!({"type": "error"}),
                ))
            } else {
                healthy(cmd)
            }
        });
        assert!(bootstrap(SOCKS.parse().expect("addr"), run).await.is_err());
        assert!(!log.lock().expect("log").iter().any(|c| c == "/_start"));
    }

    #[test]
    fn recognises_no_active_user_in_both_error_shapes() {
        assert!(is_no_active_user(&serde_json::json!({
            "type": "error", "error": {"errorType": {"type": "noActiveUser"}}
        })));
        assert!(is_no_active_user(&serde_json::json!({
            "type": "chatCmdError", "chatError": {"errorType": {"type": "noActiveUser"}}
        })));
        assert!(!is_no_active_user(&serde_json::json!({"type": "error"})));
    }
}
