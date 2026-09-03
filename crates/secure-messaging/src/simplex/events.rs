//! Parsing `simplex-chat`'s unsolicited chat events into the protocol-neutral [`ChatEvent`].
//!
//! Shapes checked against `simplex-chat/simplex-chat`'s generated `bots/api/EVENTS.md` and
//! `TYPES.md` (`stable` branch, 2026-09-04): `NewChatItems` carries an array of `AChatItem`
//! (`{chatInfo, chatItem}`); this module only recognises the specific case of a single
//! plain-text message received in a direct (not group) chat -
//! `chatInfo.type == "direct"`, `chatItem.chatDir.type == "directRcv"`,
//! `chatItem.content.type == "rcvMsgContent"`, `content.msgContent.type == "text"`. Anything
//! else inside a `newChatItems` envelope (group messages, files, reactions, sent-message
//! echoes) is silently skipped rather than misparsed, per the "message receive" adapter
//! boundary item being a first slice, not full coverage - see
//! `docs/implementation-plan.md` Phase 3.
//!
//! This module is pure (no I/O), so every case here is checked against realistic sample JSON
//! matching the documented shapes, independent of whether a live `simplex-chat` process is
//! available.

use serde_json::Value;

/// A plain-text message received in a direct chat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingMessage {
    pub contact_id: i64,
    pub text: String,
}

/// A contact has connected (accepted, or had accepted, an invitation/address connection).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactConnected {
    pub contact_id: i64,
    pub display_name: String,
}

/// A typed, protocol-neutral view of one `simplex-chat` chat event.
#[derive(Debug, Clone, PartialEq)]
pub enum ChatEvent {
    IncomingMessage(IncomingMessage),
    ContactConnected(ContactConnected),
    /// An event this crate does not yet parse into a typed form, or a `newChatItems` envelope
    /// whose type tag was recognised but carried no plain-text-in-a-direct-chat items (e.g. it
    /// was entirely group messages). The raw JSON is preserved so a caller can still act on it.
    Unrecognised(Value),
}

/// Parse one raw event value (as delivered by [`super::client::EventReceiver`]) into zero or
/// more typed [`ChatEvent`]s. Zero when a recognised envelope type carried nothing this crate
/// parses yet (e.g. only group messages inside a `newChatItems` envelope); more than one when a
/// single `newChatItems` envelope batches multiple direct-chat text messages.
pub(crate) fn parse_events(value: Value) -> Vec<ChatEvent> {
    match value.get("type").and_then(Value::as_str) {
        Some("newChatItems") => parse_new_chat_items(&value),
        Some("contactConnected") => parse_contact_connected(&value)
            .map(|contact| vec![ChatEvent::ContactConnected(contact)])
            .unwrap_or_else(|| vec![ChatEvent::Unrecognised(value)]),
        _ => vec![ChatEvent::Unrecognised(value)],
    }
}

fn parse_new_chat_items(value: &Value) -> Vec<ChatEvent> {
    let Some(items) = value.get("chatItems").and_then(Value::as_array) else {
        return vec![ChatEvent::Unrecognised(value.clone())];
    };

    items
        .iter()
        .filter_map(parse_direct_text_message)
        .map(ChatEvent::IncomingMessage)
        .collect()
}

fn parse_direct_text_message(item: &Value) -> Option<IncomingMessage> {
    let is_direct = item.get("chatInfo")?.get("type")?.as_str()? == "direct";
    if !is_direct {
        return None;
    }
    let contact_id = item
        .get("chatInfo")?
        .get("contact")?
        .get("contactId")?
        .as_i64()?;

    let chat_item = item.get("chatItem")?;
    let is_received = chat_item.get("chatDir")?.get("type")?.as_str()? == "directRcv";
    if !is_received {
        return None;
    }

    let content = chat_item.get("content")?;
    if content.get("type")?.as_str()? != "rcvMsgContent" {
        return None;
    }
    let msg_content = content.get("msgContent")?;
    if msg_content.get("type")?.as_str()? != "text" {
        return None;
    }
    let text = msg_content.get("text")?.as_str()?.to_owned();

    Some(IncomingMessage { contact_id, text })
}

fn parse_contact_connected(value: &Value) -> Option<ContactConnected> {
    let contact = value.get("contact")?;
    let contact_id = contact.get("contactId")?.as_i64()?;
    let display_name = contact.get("localDisplayName")?.as_str()?.to_owned();
    Some(ContactConnected {
        contact_id,
        display_name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_new_chat_items(chat_items: Value) -> Value {
        serde_json::json!({
            "type": "newChatItems",
            "user": {"userId": 1},
            "chatItems": chat_items
        })
    }

    fn direct_text_item(contact_id: i64, text: &str) -> Value {
        serde_json::json!({
            "chatInfo": {
                "type": "direct",
                "contact": {"contactId": contact_id, "localDisplayName": "alice"}
            },
            "chatItem": {
                "chatDir": {"type": "directRcv"},
                "meta": {},
                "content": {
                    "type": "rcvMsgContent",
                    "msgContent": {"type": "text", "text": text}
                },
                "mentions": {},
                "reactions": []
            }
        })
    }

    #[test]
    fn parses_a_single_direct_text_message() {
        let event = sample_new_chat_items(serde_json::json!([direct_text_item(5, "hello")]));
        let parsed = parse_events(event);
        assert_eq!(
            parsed,
            vec![ChatEvent::IncomingMessage(IncomingMessage {
                contact_id: 5,
                text: "hello".to_owned(),
            })]
        );
    }

    #[test]
    fn parses_multiple_batched_direct_text_messages() {
        let event = sample_new_chat_items(serde_json::json!([
            direct_text_item(5, "first"),
            direct_text_item(6, "second"),
        ]));
        let parsed = parse_events(event);
        assert_eq!(
            parsed,
            vec![
                ChatEvent::IncomingMessage(IncomingMessage {
                    contact_id: 5,
                    text: "first".to_owned(),
                }),
                ChatEvent::IncomingMessage(IncomingMessage {
                    contact_id: 6,
                    text: "second".to_owned(),
                }),
            ]
        );
    }

    #[test]
    fn ignores_a_sent_message_echo() {
        let mut item = direct_text_item(5, "outgoing");
        item["chatItem"]["chatDir"] = serde_json::json!({"type": "directSnd"});
        let event = sample_new_chat_items(serde_json::json!([item]));
        assert_eq!(parse_events(event), Vec::new());
    }

    #[test]
    fn ignores_a_group_message() {
        let mut item = direct_text_item(5, "in a group");
        item["chatInfo"] = serde_json::json!({
            "type": "group",
            "groupInfo": {"groupId": 1}
        });
        let event = sample_new_chat_items(serde_json::json!([item]));
        assert_eq!(parse_events(event), Vec::new());
    }

    #[test]
    fn ignores_non_text_content() {
        let mut item = direct_text_item(5, "n/a");
        item["chatItem"]["content"] = serde_json::json!({
            "type": "rcvMsgContent",
            "msgContent": {"type": "image", "text": "a photo", "image": "data:..."}
        });
        let event = sample_new_chat_items(serde_json::json!([item]));
        assert_eq!(parse_events(event), Vec::new());
    }

    #[test]
    fn parses_contact_connected() {
        let event = serde_json::json!({
            "type": "contactConnected",
            "user": {"userId": 1},
            "contact": {"contactId": 7, "localDisplayName": "bob"}
        });
        assert_eq!(
            parse_events(event),
            vec![ChatEvent::ContactConnected(ContactConnected {
                contact_id: 7,
                display_name: "bob".to_owned(),
            })]
        );
    }

    #[test]
    fn unrecognised_event_type_is_preserved_verbatim() {
        let event = serde_json::json!({"type": "hostDisconnected", "user": {"userId": 1}});
        assert_eq!(
            parse_events(event.clone()),
            vec![ChatEvent::Unrecognised(event)]
        );
    }

    #[test]
    fn malformed_new_chat_items_missing_the_array_is_unrecognised_not_a_panic() {
        let event = serde_json::json!({"type": "newChatItems", "user": {"userId": 1}});
        assert_eq!(
            parse_events(event.clone()),
            vec![ChatEvent::Unrecognised(event)]
        );
    }
}
