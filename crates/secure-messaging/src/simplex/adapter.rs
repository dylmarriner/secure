//! [`SimplexAdapter`]: the narrow, SimpleX-specific implementation behind
//! [`crate::MessagingAdapter`]. See the module docs on [`super`] for the licensing/boundary
//! context and [`super::client`] for what has and has not actually been run.
//!
//! This is a first slice, not full Phase 3 coverage: bootstrap (start chat + create the local
//! user), creating and accepting one-time invitations, and sending plain-text messages. Not yet
//! covered, deliberately left unimplemented rather than stubbed with a fake body: delivery
//! acknowledgement, session/key rotation events, attachment transport references, and exporting
//! protocol state into the encrypted vault. Adding a method to this file for one of those is
//! the right way to close that gap when there is a real caller for it - see
//! `docs/implementation-plan.md` Phase 3.

use std::net::{SocketAddr, SocketAddrV4};
use std::path::PathBuf;

use thiserror::Error;
use tokio::sync::Mutex as AsyncMutex;
use zeroize::Zeroizing;

use super::client::{ClientError, EventReceiver, SimplexClient};
use super::commands::{self, ChatKind};

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error(transparent)]
    Client(#[from] ClientError),
    #[cfg(feature = "simplex-native")]
    #[error(transparent)]
    Core(#[from] super::core::CoreError),
    #[error("simplex-chat rejected the command: {0}")]
    CommandFailed(serde_json::Value),
    #[error("unexpected response shape from simplex-chat: {0}")]
    UnexpectedResponse(serde_json::Value),
    #[error("bootstrap must complete before this operation")]
    NotBootstrapped,
    #[error(
        "simplex-chat's effective SOCKS proxy ({actual:?}) does not match the Secure-owned \
         loopback bridge ({expected}) - refusing to allow messaging over an unverified path"
    )]
    NetworkConfigMismatch {
        expected: SocketAddrV4,
        actual: Option<String>,
    },
}

/// A one-time SimpleX invitation link, ready to hand to a contact out-of-band (QR code, copy,
/// etc.) per the security architecture's "one-time invitations" contact model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invitation {
    pub link: String,
}

pub struct SimplexAdapter {
    client: SimplexClient,
    /// Populated by [`Self::bootstrap`]. `simplex-chat`'s API is scoped per local user id, so
    /// every command after bootstrap needs it.
    user_id: AsyncMutex<Option<i64>>,
}

impl SimplexAdapter {
    /// Launch the `simplex-chat` subprocess and connect to it. `display_name` is required at
    /// launch, not deferred to [`Self::bootstrap`]: the CLI's WebSocket server does not start
    /// listening until first-run profile setup completes, and with `stdin` closed (as this
    /// crate deliberately runs it - see `simplex::client::SimplexClient::launch`) that setup
    /// can only be satisfied by `--user-display-name` at spawn time. This was confirmed by
    /// actually running it - see that module's docs for what a mismatch between this and
    /// `bootstrap` looked like in practice (a second, redundant user, not an error).
    ///
    /// `database_key` and `socks_proxy` are both mandatory, for the same reason they are
    /// mandatory on `SimplexClient::launch`: an unencrypted `simplex-chat` database or a
    /// clearnet-capable launch would violate this workspace's encrypted-storage and
    /// Tor-only-transport invariants respectively (`docs/security-architecture.md`). The caller
    /// is expected to pass the address of a running
    /// `secure_transport::TorTransport::start_socks_proxy` bridge - this crate does not depend
    /// on `secure-transport` directly so that the SimpleX/Tor boundary stays a caller-composed
    /// wire-up rather than a cross-crate dependency.
    pub async fn launch(
        binary_path: PathBuf,
        port: u16,
        database_path: PathBuf,
        database_key: Zeroizing<String>,
        socks_proxy: SocketAddr,
        display_name: &str,
    ) -> Result<(Self, EventReceiver), AdapterError> {
        let (client, events) = SimplexClient::launch(
            &binary_path,
            port,
            &database_path,
            &database_key,
            socks_proxy,
            display_name,
        )
        .await?;
        Ok((
            Self {
                client,
                user_id: AsyncMutex::new(None),
            },
            events,
        ))
    }

    /// Point simplex-chat's network config at Secure's own loopback SOCKS bridge and read it
    /// back to prove the change actually took effect, per
    /// `docs/security-remediation-plan.md` Phase R4: `APISetNetworkConfig` succeeding is not by
    /// itself proof the effective config matches what was requested, so this always follows up
    /// with `APIGetNetworkConfig` and fails closed (returns
    /// [`AdapterError::NetworkConfigMismatch`]) rather than assuming success. Callers must
    /// refuse to allow any messaging operation - not just skip this call - if this errors: the
    /// alternative is an unverified, potentially direct (non-Tor) network path.
    pub async fn configure_network(&self, socks_address: SocketAddrV4) -> Result<(), AdapterError> {
        self.run(commands::set_network_config(socks_address))
            .await?;
        let response = self.run(commands::get_network_config()).await?;
        let actual = extract_socks_proxy(&response);
        if actual.as_deref() != Some(commands::socks_proxy_string(socks_address).as_str()) {
            return Err(AdapterError::NetworkConfigMismatch {
                expected: socks_address,
                actual,
            });
        }
        Ok(())
    }

    /// Start the chat controller and read back the active user profile that
    /// [`Self::launch`]'s `display_name` already created at spawn time.
    ///
    /// This calls `ShowActiveUser` (`/user`), not `CreateActiveUser` - the two are not
    /// interchangeable here. `CreateActiveUser` was confirmed, by actually running it against a
    /// process that already had a CLI-created profile, to create a *second*, distinct user and
    /// make *that* active, rather than erroring or reusing the first. `ShowActiveUser` reads
    /// back the one user that already exists, which is what a bootstrap step should do.
    pub async fn bootstrap(&self) -> Result<(), AdapterError> {
        self.run(commands::start_chat()).await?;
        let response = self.run(commands::show_active_user()).await?;
        let user_id = extract_user_id(&response)?;
        *self.user_id.lock().await = Some(user_id);
        Ok(())
    }

    /// Create a one-time invitation link for a new contact to connect with.
    pub async fn create_invitation(&self) -> Result<Invitation, AdapterError> {
        let user_id = self.require_user_id().await?;
        let response = self.run(commands::create_invitation(user_id)).await?;
        extract_invitation_link(&response).map(|link| Invitation { link })
    }

    /// Accept an invitation (or connect to a contact address / group link) received from
    /// another party.
    pub async fn accept_invitation(&self, link: &str) -> Result<(), AdapterError> {
        let user_id = self.require_user_id().await?;
        self.run(commands::connect_via_link(user_id, link)).await?;
        Ok(())
    }

    /// Send a plain-text message to a direct chat.
    pub async fn send_text_message(&self, chat_id: i64, text: &str) -> Result<(), AdapterError> {
        self.run(commands::send_text_message(ChatKind::Direct, chat_id, text))
            .await?;
        Ok(())
    }

    /// Stop the underlying subprocess.
    pub async fn shutdown(self) {
        self.client.shutdown().await;
    }

    async fn require_user_id(&self) -> Result<i64, AdapterError> {
        self.user_id
            .lock()
            .await
            .ok_or(AdapterError::NotBootstrapped)
    }

    async fn run(&self, cmd: String) -> Result<serde_json::Value, AdapterError> {
        let response = self.client.send_command(cmd).await?;
        if is_error_response(&response) {
            return Err(AdapterError::CommandFailed(response));
        }
        Ok(response)
    }
}

pub(super) fn is_error_response(response: &serde_json::Value) -> bool {
    matches!(
        response.get("type").and_then(serde_json::Value::as_str),
        Some("chatCmdError" | "error")
    )
}

pub(super) fn extract_user_id(response: &serde_json::Value) -> Result<i64, AdapterError> {
    response
        .get("user")
        .and_then(|user| user.get("userId"))
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| AdapterError::UnexpectedResponse(response.clone()))
}

/// Reads `CRNetworkConfig`'s `networkConfig.socksProxy` field back out of an
/// `APIGetNetworkConfig` response. `None` if the field is absent/not a string, which
/// [`SimplexAdapter::configure_network`] treats the same as any other mismatch - fail closed,
/// not "assume no proxy is fine".
pub(super) fn extract_socks_proxy(response: &serde_json::Value) -> Option<String> {
    response
        .get("networkConfig")?
        .get("socksProxy")?
        .as_str()
        .map(str::to_owned)
}

pub(super) fn extract_invitation_link(
    response: &serde_json::Value,
) -> Result<String, AdapterError> {
    response
        .get("connLinkInvitation")
        .and_then(|link| link.get("connFullLink"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| AdapterError::UnexpectedResponse(response.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_a_chat_cmd_error_response() {
        let response = serde_json::json!({
            "type": "chatCmdError",
            "chatError": {"type": "error", "errorType": {"type": "noActiveUser"}}
        });
        assert!(is_error_response(&response));
    }

    #[test]
    fn recognises_a_native_core_error_response() {
        let response = serde_json::json!({
            "type": "error",
            "error": {"errorType": {"type": "noActiveUser"}}
        });
        assert!(is_error_response(&response));
    }

    #[test]
    fn does_not_treat_a_successful_response_as_an_error() {
        let response = serde_json::json!({"type": "chatStarted"});
        assert!(!is_error_response(&response));
    }

    #[test]
    fn extracts_user_id_from_an_active_user_response() {
        // Shape per bots/api/COMMANDS.md's CreateActiveUser -> ActiveUser response and
        // bots/api/TYPES.md's User record (only the field this crate actually reads is
        // populated here; the real response carries many more).
        let response = serde_json::json!({
            "type": "activeUser",
            "user": {"userId": 1, "localDisplayName": "secure-user"}
        });
        assert_eq!(extract_user_id(&response).expect("user id"), 1);
    }

    #[test]
    fn extract_user_id_rejects_a_response_missing_the_field() {
        let response = serde_json::json!({"type": "chatStarted"});
        assert!(extract_user_id(&response).is_err());
    }

    #[test]
    fn extracts_invitation_link_from_an_invitation_response() {
        // Shape per bots/api/COMMANDS.md's APIAddContact -> Invitation response and
        // bots/api/TYPES.md's CreatedConnLink record.
        let response = serde_json::json!({
            "type": "invitation",
            "user": {"userId": 1},
            "connLinkInvitation": {
                "connFullLink": "https://simplex.chat/invitation#/?v=1&smp=...",
                "connShortLink": null
            },
            "connection": {}
        });
        let invitation = extract_invitation_link(&response).expect("invitation link");
        assert_eq!(invitation, "https://simplex.chat/invitation#/?v=1&smp=...");
    }

    #[test]
    fn extract_invitation_link_rejects_a_response_missing_the_field() {
        let response = serde_json::json!({"type": "chatStarted"});
        assert!(extract_invitation_link(&response).is_err());
    }

    #[test]
    fn extracts_socks_proxy_from_a_network_config_response() {
        // Shape per `CRNetworkConfig {networkConfig :: NetworkConfig}` - see
        // `commands.rs`'s network-config section doc comment for the field-name provenance.
        let response = serde_json::json!({
            "type": "networkConfig",
            "networkConfig": {"socksProxy": "127.0.0.1:9999", "socksMode": "always"}
        });
        assert_eq!(
            extract_socks_proxy(&response).as_deref(),
            Some("127.0.0.1:9999")
        );
    }

    #[test]
    fn extract_socks_proxy_rejects_a_response_missing_the_field() {
        let response = serde_json::json!({"type": "chatStarted"});
        assert!(extract_socks_proxy(&response).is_none());
    }
}
