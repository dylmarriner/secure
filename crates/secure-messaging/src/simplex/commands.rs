//! SimpleX Chat CLI command-string construction.
//!
//! Every command string built here is checked against `simplex-chat`'s own generated API
//! reference (`bots/api/COMMANDS.md` and `bots/api/TYPES.md` in the `simplex-chat/simplex-chat`
//! repository, `stable` branch, as of 2026-09-04), not guessed. This module is pure - no I/O,
//! no process, no network - specifically so the command strings this crate actually sends can
//! be unit-tested by comparing them against the documented syntax, independent of whether a
//! real `simplex-chat` process is available to send them to.
//!
//! Optional JSON fields (e.g. `ComposedMessage.fileSource`/`quotedItemId`) are omitted rather
//! than sent as explicit `null`: `simplex-chat`'s Haskell JSON decoding for `Maybe` fields
//! generally treats a missing key as `Nothing`, and omitting is the more conservative choice
//! for a client we cannot run against here to verify either encoding works.

use std::net::SocketAddrV4;

use serde::Serialize;

/// `/_start` - start the chat controller. No parameters are interpolated into the command
/// string despite `StartChat` listing `mainApp`/`enableSndFiles` parameters in its API
/// reference entry; the documented `Syntax` block for this command is the literal string with
/// no substitution, and that literal syntax is what is trusted here.
pub fn start_chat() -> String {
    "/_start".to_owned()
}

/// `/user` - `ShowActiveUser`: read back the currently active user profile. This is what
/// `bootstrap` uses, not `CreateActiveUser` (`/_create user <json>`): the CLI process is always
/// launched with `--user-display-name` (see `simplex::client::SimplexClient::launch`), which
/// already creates a profile before the WebSocket server even starts listening.
/// `CreateActiveUser` was tried first and confirmed, by actually running it against a process
/// that already had a CLI-created profile, to create a *second*, redundant user and make *that*
/// one active - not an error, not a reuse of the first. A `create_user`/`CreateActiveUser`
/// command builder for a genuine future multi-identity flow (creating an additional profile on
/// an already-running instance, which is a real, different use case from bootstrap) can be
/// re-added from `bots/api/COMMANDS.md`'s `CreateActiveUser` entry when there is an actual
/// caller for it - removed here rather than kept unused, per the project's engineering rules.
pub fn show_active_user() -> String {
    "/user".to_owned()
}

/// `/_create user <json(newUser)>` - create the first local profile when the native core opens a
/// fresh store. The CLI adapter does not use this: its `--user-display-name` launch option
/// creates the profile before the WebSocket API is available. The native core has no equivalent
/// launch option, so its bootstrap path must create the profile after `/_start` reports
/// `noActiveUser`.
#[cfg(feature = "simplex-native")]
pub fn create_native_user() -> String {
    "/_create user {\"profile\":{\"displayName\":\"Secure\",\"fullName\":\"\"},\"pastTimestamp\":false,\"userChatRelay\":false,\"clientService\":false}".to_owned()
}

/// `/_connect <userId>` with no link argument - `APIAddContact`: create a one-time invitation
/// link. Distinguished from [`connect_via_link`] (same `/_connect` prefix) purely by the
/// presence or absence of the trailing link argument, exactly as the upstream API reference
/// documents both commands.
pub fn create_invitation(user_id: i64) -> String {
    format!("/_connect {user_id}")
}

/// Longest link [`connect_via_link`] accepts. Upstream full invitation links carry several
/// base64url-encoded keys (post-quantum included) and run to a few KiB; this leaves headroom
/// for that while refusing to forward megabytes of pasted text into the core.
pub const MAX_LINK_LEN: usize = 8 * 1024;

/// Why a contact link was refused before any command was built from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvalidLink {
    #[error("link is empty")]
    Empty,
    #[error("link is longer than {MAX_LINK_LEN} bytes")]
    TooLong,
    #[error("link must start with `simplex:` or `https://`")]
    UnsupportedScheme,
    #[error("link contains whitespace, control or non-ASCII characters")]
    ForbiddenCharacter,
}

/// Validate an untrusted contact link before it is interpolated into a command string
/// (`docs/security-remediation-plan.md` Phase R7). `APIConnect` has no structured (JSON)
/// encoding upstream - the link is a positional argument in the command text - so the only way
/// to rule out argument/command injection is to constrain the link itself: SimpleX links are
/// URL-encoded and never legitimately contain spaces, control characters (NUL/CR/LF) or
/// non-ASCII, so restricting to printable non-space ASCII leaves no separator a link could use
/// to smuggle a second argument or command. Self-hosted relays mean the `https://` host cannot
/// be pinned to `simplex.chat`.
pub fn validate_link(link: &str) -> Result<(), InvalidLink> {
    if link.is_empty() {
        return Err(InvalidLink::Empty);
    }
    if link.len() > MAX_LINK_LEN {
        return Err(InvalidLink::TooLong);
    }
    if !link.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(InvalidLink::ForbiddenCharacter);
    }
    let lower = link
        .get(..8)
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    if !(lower.starts_with("simplex:") || lower.starts_with("https://")) {
        return Err(InvalidLink::UnsupportedScheme);
    }
    Ok(())
}

/// `/_connect <userId> <preparedLink>` - `APIConnect`: connect using a prepared SimpleX link
/// (one-time invitation, contact address, or group link). The link is untrusted input and is
/// checked by [`validate_link`] first.
pub fn connect_via_link(user_id: i64, link: &str) -> Result<String, InvalidLink> {
    validate_link(link)?;
    Ok(format!("/_connect {user_id} {link}"))
}

/// Which kind of chat a `ChatRef` identifies. `ChatType` (the upstream type this mirrors) has
/// three variants (`direct`/`@`, `group`/`#`, `local`/`*`); only `Direct` is represented here
/// because group chat and the local "Saved Messages" chat have no commands implemented in this
/// crate yet. Add the other variants back when group chat support lands, rather than carrying
/// unused surface area now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatKind {
    Direct,
}

impl ChatKind {
    const fn prefix(self) -> char {
        match self {
            Self::Direct => '@',
        }
    }
}

/// `<str(chatType)><chatId>` - `ChatRef`'s command-string form.
fn chat_ref(kind: ChatKind, chat_id: i64) -> String {
    format!("{}{chat_id}", kind.prefix())
}

#[derive(Debug, Serialize)]
struct MsgContentText<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    text: &'a str,
}

#[derive(Debug, Serialize)]
struct ComposedMessage<'a> {
    #[serde(rename = "msgContent")]
    msg_content: MsgContentText<'a>,
    /// `ComposedMessage.mentions` is a required (non-`Maybe`) `{string: int64}` map; an empty
    /// object is the correct encoding of "no mentions", not an omitted field.
    mentions: serde_json::Map<String, serde_json::Value>,
}

/// `/_send <chatRef> json <json([composedMessage])>` - `APISendMessages`, restricted to a
/// single plain-text message. `live`/`ttl`/`sign` modifiers are not yet supported; add them if
/// a real need for disappearing/live messages arises.
pub fn send_text_message(kind: ChatKind, chat_id: i64, text: &str) -> String {
    let messages = [ComposedMessage {
        msg_content: MsgContentText { kind: "text", text },
        mentions: serde_json::Map::new(),
    }];
    // The types above only contain strings, a static tag and an empty map, so this cannot fail.
    let json = serde_json::to_string(&messages).expect("ComposedMessage always serialises");
    format!("/_send {} json {json}", chat_ref(kind, chat_id))
}

// # Network configuration (`docs/security-remediation-plan.md` Phase R4)
//
// Every field/tag name below is transcribed from `simplexmq` commit
// `efaad8e73436d60f5052f07dda6b71151ad5039b` (the exact commit `simplex-chat`'s
// `cabal.project` pins at `SIMPLEX_CHAT_COMMIT` in `scripts/build-simplex-native.sh`), not
// guessed:
// - `src/Simplex/Messaging/Client.hs`: `NetworkConfig`'s field names (`$(deriveJSON defaultJSON
//   ''NetworkConfig)`, so JSON keys are the Haskell field names verbatim - `defaultJSON` only
//   sets `omitNothingFields`, it does not rename anything), and the `HostMode`/`SocksMode`/
//   `TransportSessionMode`/`SMPProxyMode`/`SMPProxyFallback`/`SMPWebPortServers` enum tag
//   strings (`enumJSON $ dropPrefix "..."`: drop the constructor prefix, lowercase the first
//   remaining letter - e.g. `HMPublic` -> `public`, `SPFAllowProtected` -> `allowProtected`).
// - `src/Simplex/Messaging/Transport/KeepAlive.hs`: `KeepAliveOpts` fields/defaults.
// - `src/Simplex/Messaging/Transport/Client.hs`: `SocksProxyWithAuth`/`SocksAuth`'s
//   `StrEncoding` (`socksProxy` is a plain JSON string, not an object: `<authPrefix><host>:
//   <port>`). This module always sends an address with no auth prefix at all, which upstream's
//   own `strP` parses as `SocksIsolateByAuth` (its own default, and its own fallback when
//   neither `user:pass@` nor a bare `@` matched) - that is what makes upstream generate a fresh
//   per-connection SOCKS5 username/password itself, which is exactly the signal
//   `secure_transport::socks::TorSocksProxy`'s per-connection circuit isolation (also Phase R4)
//   keys off. Do not add an explicit `@`/`user:pass@` prefix here without re-deriving both sides
//   of that isolation contract together.
// - `apps/ios/Shared/Model/AppAPITypes.swift` confirms the `/_network`/`/network` command-string
//   wrapping (`ChatCommand.apiSetNetworkConfig`/`apiGetNetworkConfig`'s `cmdString`) and, via
//   `apps/ios/SimpleXChat/APITypes.swift`'s `NetCfg.defaults`, the numeric/enum default values
//   below - the same defaults every official client sends unless a user has changed advanced
//   settings, so this is what a from-scratch Secure profile should send too.
//
// None of this has been run against a live `simplex-chat` process from this crate yet (that
// needs the native library this environment cannot build - see `core.rs`'s module docs); it is
// checked against upstream's actual source at the pinned commit, matching this module's own
// documented policy of not guessing command syntax, but is not yet the "live two-client Tor"
// empirical proof Phase R4's exit criteria requires.

#[derive(Debug, Clone, Copy, Serialize)]
struct NetworkTimeout {
    #[serde(rename = "backgroundTimeout")]
    background_timeout: u64,
    #[serde(rename = "interactiveTimeout")]
    interactive_timeout: u64,
}

#[derive(Debug, Clone, Copy, Serialize)]
struct KeepAliveOpts {
    #[serde(rename = "keepIdle")]
    keep_idle: u32,
    #[serde(rename = "keepIntvl")]
    keep_intvl: u32,
    #[serde(rename = "keepCnt")]
    keep_cnt: u32,
}

/// `NetworkConfig` - the JSON payload of `/_network <json>` (`APISetNetworkConfig`). All fields
/// except `socksProxy`/`tcpKeepAlive` are non-`Maybe` upstream, so every one of them must be
/// present (see this section's doc comment above); values other than `socks_proxy` are fixed at
/// upstream's own documented defaults - there is no Secure-specific reason to diverge from them.
#[derive(Debug, Serialize)]
struct NetworkConfig {
    #[serde(rename = "socksProxy")]
    socks_proxy: String,
    #[serde(rename = "socksMode")]
    socks_mode: &'static str,
    #[serde(rename = "hostMode")]
    host_mode: &'static str,
    #[serde(rename = "requiredHostMode")]
    required_host_mode: bool,
    #[serde(rename = "sessionMode")]
    session_mode: &'static str,
    #[serde(rename = "smpProxyMode")]
    smp_proxy_mode: &'static str,
    #[serde(rename = "smpProxyFallback")]
    smp_proxy_fallback: &'static str,
    #[serde(rename = "smpWebPortServers")]
    smp_web_port_servers: &'static str,
    #[serde(rename = "tcpConnectTimeout")]
    tcp_connect_timeout: NetworkTimeout,
    #[serde(rename = "tcpTimeout")]
    tcp_timeout: NetworkTimeout,
    #[serde(rename = "tcpTimeoutPerKb")]
    tcp_timeout_per_kb: u64,
    #[serde(rename = "rcvConcurrency")]
    rcv_concurrency: u32,
    #[serde(rename = "tcpKeepAlive")]
    tcp_keep_alive: KeepAliveOpts,
    #[serde(rename = "smpPingInterval")]
    smp_ping_interval: u64,
    #[serde(rename = "smpPingCount")]
    smp_ping_count: u32,
    #[serde(rename = "logTLSErrors")]
    log_tls_errors: bool,
}

/// The `socksProxy` string form of `socks_address`, with no `SocksAuth` prefix - see this
/// section's module-level doc comment for why that specific absence matters. Shared with
/// [`super::adapter::SimplexAdapter::configure_network`], which must compare the exact same
/// string back against what `get_network_config`'s response reports, rather than each side
/// independently reformatting the address and risking silent drift between them.
pub(crate) fn socks_proxy_string(socks_address: SocketAddrV4) -> String {
    format!("{}:{}", socks_address.ip(), socks_address.port())
}

impl NetworkConfig {
    fn for_socks_proxy(socks_address: SocketAddrV4) -> Self {
        Self {
            socks_proxy: socks_proxy_string(socks_address),
            socks_mode: "always",
            host_mode: "public",
            required_host_mode: true,
            session_mode: "user",
            smp_proxy_mode: "always",
            smp_proxy_fallback: "allowProtected",
            smp_web_port_servers: "preset",
            tcp_connect_timeout: NetworkTimeout {
                background_timeout: 45_000_000,
                interactive_timeout: 15_000_000,
            },
            tcp_timeout: NetworkTimeout {
                background_timeout: 30_000_000,
                interactive_timeout: 10_000_000,
            },
            tcp_timeout_per_kb: 10_000,
            rcv_concurrency: 12,
            tcp_keep_alive: KeepAliveOpts {
                keep_idle: 30,
                keep_intvl: 15,
                keep_cnt: 4,
            },
            smp_ping_interval: 1_200_000_000,
            smp_ping_count: 3,
            log_tls_errors: false,
        }
    }
}

/// `/_network <json(networkConfig)>` - `APISetNetworkConfig`: route every future SMP/network
/// operation through Secure's own loopback SOCKS bridge (`secure_transport::TorSocksProxy`),
/// with no direct-connection fallback path in the config itself. Must be sent and its read-back
/// (`get_network_config`) verified before any messaging operation that could touch the network -
/// wiring that check into a runtime that owns both the SimpleX core and the transport is Phase
/// R5's job (no such runtime exists to call this from yet).
pub fn set_network_config(socks_address: SocketAddrV4) -> String {
    let config = NetworkConfig::for_socks_proxy(socks_address);
    // Every field above is a plain string/bool/int/nested-record - this cannot fail.
    let json = serde_json::to_string(&config).expect("NetworkConfig always serialises");
    format!("/_network {json}")
}

/// `/network` - `APIGetNetworkConfig`: read back the network config currently in effect, to
/// verify it is still the loopback SOCKS bridge `set_network_config` requested (fail closed if
/// it is not - see that function's doc comment).
pub fn get_network_config() -> String {
    "/network".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_chat_matches_documented_syntax() {
        assert_eq!(start_chat(), "/_start");
    }

    #[test]
    fn show_active_user_matches_documented_syntax() {
        assert_eq!(show_active_user(), "/user");
    }

    #[test]
    fn create_invitation_matches_documented_syntax() {
        assert_eq!(create_invitation(1), "/_connect 1");
    }

    #[test]
    fn connect_via_link_matches_documented_syntax() {
        assert_eq!(
            connect_via_link(1, "https://simplex.chat/invitation#/?v=1&smp=...").as_deref(),
            Ok("/_connect 1 https://simplex.chat/invitation#/?v=1&smp=...")
        );
    }

    #[test]
    fn connect_via_link_accepts_the_simplex_scheme() {
        assert!(connect_via_link(1, "simplex:/invitation#/?v=2-7&smp=smp%3A%2F%2Fabc").is_ok());
    }

    #[test]
    fn malicious_links_with_newline_or_control_characters_are_rejected_before_send() {
        for link in [
            "https://simplex.chat/invitation#x\n/_send @1 json []",
            "https://simplex.chat/invitation#x\r/_delete @1",
            "https://simplex.chat/invitation#x\0",
            "https://simplex.chat/invitation#x\t",
            "https://simplex.chat/invitation#x /_send @1 text hi",
            "https://simplex.chat/invitation#\u{2028}",
        ] {
            assert_eq!(
                connect_via_link(1, link),
                Err(InvalidLink::ForbiddenCharacter),
                "{link:?} must be rejected"
            );
        }
    }

    #[test]
    fn links_with_other_schemes_are_rejected() {
        for link in [
            "http://simplex.chat/x",
            "file:///etc/passwd",
            "/_send",
            "javascript:x",
        ] {
            assert_eq!(
                connect_via_link(1, link),
                Err(InvalidLink::UnsupportedScheme)
            );
        }
    }

    #[test]
    fn empty_and_oversized_links_are_rejected() {
        assert_eq!(connect_via_link(1, ""), Err(InvalidLink::Empty));
        let long = format!("https://{}", "a".repeat(MAX_LINK_LEN));
        assert_eq!(connect_via_link(1, &long), Err(InvalidLink::TooLong));
    }

    #[test]
    fn chat_ref_uses_documented_type_prefix() {
        assert_eq!(chat_ref(ChatKind::Direct, 5), "@5");
    }

    #[test]
    fn send_text_message_matches_documented_syntax() {
        let command = send_text_message(ChatKind::Direct, 5, "hello");
        assert_eq!(
            command,
            "/_send @5 json [{\"msgContent\":{\"type\":\"text\",\"text\":\"hello\"},\"mentions\":{}}]"
        );
    }

    #[test]
    fn send_text_message_escapes_json_special_characters_in_text() {
        let original_text = "quote \" and \\ backslash";
        let command = send_text_message(ChatKind::Direct, 1, original_text);

        // Round-trip through a JSON parser to prove the produced command's JSON payload is
        // actually valid and preserves the exact original text, rather than string-matching a
        // hand-written escape sequence that is easy to get wrong when written by hand.
        let json_part = command.strip_prefix("/_send @1 json ").expect("prefix");
        let payload: serde_json::Value =
            serde_json::from_str(json_part).expect("payload must be valid JSON");
        assert_eq!(payload[0]["msgContent"]["text"], original_text);
    }

    #[test]
    fn get_network_config_matches_documented_syntax() {
        assert_eq!(get_network_config(), "/network");
    }

    #[test]
    fn set_network_config_wraps_the_documented_prefix() {
        let address: SocketAddrV4 = "127.0.0.1:9999".parse().expect("valid address");
        let command = set_network_config(address);
        assert!(command.starts_with("/_network "));
    }

    #[test]
    fn set_network_config_socks_proxy_has_no_auth_prefix() {
        // No `@`/`user:pass@` prefix at all, so upstream's own `SocksAuth` parser falls back to
        // `SocksIsolateByAuth` - see this section's module-level doc comment for why that
        // matters for `secure-transport`'s per-connection circuit isolation.
        let address: SocketAddrV4 = "127.0.0.1:9999".parse().expect("valid address");
        let command = set_network_config(address);
        let json_part = command.strip_prefix("/_network ").expect("prefix");
        let payload: serde_json::Value =
            serde_json::from_str(json_part).expect("payload must be valid JSON");
        assert_eq!(payload["socksProxy"], "127.0.0.1:9999");
    }

    #[test]
    fn set_network_config_sends_every_required_non_maybe_field() {
        // `NetworkConfig`'s aeson instance is `deriveJSON defaultJSON` with no custom
        // partial-parse fallback, so a from-scratch profile must send every field that is not
        // `Maybe` upstream or the read-back configuration will fail to parse entirely.
        let address: SocketAddrV4 = "127.0.0.1:9999".parse().expect("valid address");
        let command = set_network_config(address);
        let json_part = command.strip_prefix("/_network ").expect("prefix");
        let payload: serde_json::Value =
            serde_json::from_str(json_part).expect("payload must be valid JSON");
        for field in [
            "socksProxy",
            "socksMode",
            "hostMode",
            "requiredHostMode",
            "sessionMode",
            "smpProxyMode",
            "smpProxyFallback",
            "smpWebPortServers",
            "tcpConnectTimeout",
            "tcpTimeout",
            "tcpTimeoutPerKb",
            "rcvConcurrency",
            "tcpKeepAlive",
            "smpPingInterval",
            "smpPingCount",
            "logTLSErrors",
        ] {
            assert!(!payload[field].is_null(), "missing required field {field}");
        }
    }
}
