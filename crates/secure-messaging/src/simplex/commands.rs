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

/// `/_connect <userId>` with no link argument - `APIAddContact`: create a one-time invitation
/// link. Distinguished from [`connect_via_link`] (same `/_connect` prefix) purely by the
/// presence or absence of the trailing link argument, exactly as the upstream API reference
/// documents both commands.
pub fn create_invitation(user_id: i64) -> String {
    format!("/_connect {user_id}")
}

/// `/_connect <userId> <preparedLink>` - `APIConnect`: connect using a prepared SimpleX link
/// (one-time invitation, contact address, or group link).
pub fn connect_via_link(user_id: i64, link: &str) -> String {
    format!("/_connect {user_id} {link}")
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
            connect_via_link(1, "https://simplex.chat/invitation#/?v=1&smp=..."),
            "/_connect 1 https://simplex.chat/invitation#/?v=1&smp=..."
        );
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
}
