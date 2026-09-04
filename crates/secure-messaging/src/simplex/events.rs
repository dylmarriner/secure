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

/// The other party deleted their side of the connection. Per `simplex-chat`'s own
/// `contactDeletedByContact` documentation, this is peer-initiated and conversation history is
/// kept locally - it is not a local burn/destroy operation (that is Phase 5/6 territory) and
/// this crate does not react to it beyond surfacing it, since deciding what a "disconnected"
/// contact means for stored conversation state belongs to whichever later-phase crate owns the
/// vault-backed contact model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactDisconnected {
    pub contact_id: i64,
    pub display_name: String,
}

/// The delivery status of a message this client sent, per `simplex-chat`'s `CIStatus` union
/// (`bots/api/TYPES.md`). Deliberately collapses `sndWarning`'s `agentError` payload into
/// `Failed` rather than exposing it: a caller needs to know delivery did not succeed, not parse
/// SimpleX's internal agent error taxonomy through this crate's boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryStatus {
    /// `sndNew` - queued, not yet handed to the sending agent.
    Pending,
    /// `sndSent` - accepted by the relay for delivery.
    Sent,
    /// `sndRcvd` - the recipient's client has received the message.
    Received,
    /// `sndErrorAuth`, `sndError` or `sndWarning` - delivery failed or is degraded.
    Failed,
}

/// A delivery-status update for a message this client previously sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageDelivery {
    pub contact_id: i64,
    pub item_id: i64,
    pub status: DeliveryStatus,
}

/// A typed, protocol-neutral view of one `simplex-chat` chat event.
#[derive(Debug, Clone, PartialEq)]
pub enum ChatEvent {
    IncomingMessage(IncomingMessage),
    ContactConnected(ContactConnected),
    ContactDisconnected(ContactDisconnected),
    MessageDelivery(MessageDelivery),
    /// An event this crate does not yet parse into a typed form, or a `newChatItems`/
    /// `chatItemsStatusesUpdated` envelope whose type tag was recognised but carried nothing
    /// this crate parses yet (e.g. it was entirely group messages, or a status other than the
    /// sent-message statuses this crate tracks). The raw JSON is preserved so a caller can
    /// still act on it.
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
        Some("contactDeletedByContact") => parse_contact_disconnected(&value)
            .map(|contact| vec![ChatEvent::ContactDisconnected(contact)])
            .unwrap_or_else(|| vec![ChatEvent::Unrecognised(value)]),
        Some("chatItemsStatusesUpdated") => parse_statuses_updated(&value),
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

fn parse_contact_disconnected(value: &Value) -> Option<ContactDisconnected> {
    let contact = value.get("contact")?;
    let contact_id = contact.get("contactId")?.as_i64()?;
    let display_name = contact.get("localDisplayName")?.as_str()?.to_owned();
    Some(ContactDisconnected {
        contact_id,
        display_name,
    })
}

fn parse_statuses_updated(value: &Value) -> Vec<ChatEvent> {
    let Some(items) = value.get("chatItems").and_then(Value::as_array) else {
        return vec![ChatEvent::Unrecognised(value.clone())];
    };

    items
        .iter()
        .filter_map(parse_direct_sent_status)
        .map(ChatEvent::MessageDelivery)
        .collect()
}

/// Only a status update for a message *this client sent* (`directSnd`) in a direct chat is
/// meaningful as a delivery-status event - a status update on a *received* item (e.g. `rcvRead`
/// after this client reads it locally) is not something the sender's UI needs to react to, and
/// is silently skipped, matching `parse_direct_text_message`'s scoping.
fn parse_direct_sent_status(item: &Value) -> Option<MessageDelivery> {
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
    let is_sent = chat_item.get("chatDir")?.get("type")?.as_str()? == "directSnd";
    if !is_sent {
        return None;
    }

    let meta = chat_item.get("meta")?;
    let item_id = meta.get("itemId")?.as_i64()?;
    let status = match meta.get("itemStatus")?.get("type")?.as_str()? {
        "sndNew" => DeliveryStatus::Pending,
        "sndSent" => DeliveryStatus::Sent,
        "sndRcvd" => DeliveryStatus::Received,
        "sndErrorAuth" | "sndError" | "sndWarning" => DeliveryStatus::Failed,
        _ => return None,
    };

    Some(MessageDelivery {
        contact_id,
        item_id,
        status,
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
    fn parses_contact_disconnected() {
        let event = serde_json::json!({
            "type": "contactDeletedByContact",
            "user": {"userId": 1},
            "contact": {"contactId": 7, "localDisplayName": "bob"}
        });
        assert_eq!(
            parse_events(event),
            vec![ChatEvent::ContactDisconnected(ContactDisconnected {
                contact_id: 7,
                display_name: "bob".to_owned(),
            })]
        );
    }

    #[test]
    fn malformed_contact_disconnected_missing_the_contact_is_unrecognised_not_a_panic() {
        let event = serde_json::json!({"type": "contactDeletedByContact", "user": {"userId": 1}});
        assert_eq!(
            parse_events(event.clone()),
            vec![ChatEvent::Unrecognised(event)]
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

    fn sent_status_item(contact_id: i64, item_id: i64, status_type: &str) -> Value {
        serde_json::json!({
            "chatInfo": {
                "type": "direct",
                "contact": {"contactId": contact_id, "localDisplayName": "alice"}
            },
            "chatItem": {
                "chatDir": {"type": "directSnd"},
                "meta": {
                    "itemId": item_id,
                    "itemStatus": {"type": status_type}
                },
                "content": {
                    "type": "sndMsgContent",
                    "msgContent": {"type": "text", "text": "hi"}
                },
                "mentions": {},
                "reactions": []
            }
        })
    }

    fn sample_statuses_updated(chat_items: Value) -> Value {
        serde_json::json!({
            "type": "chatItemsStatusesUpdated",
            "user": {"userId": 1},
            "chatItems": chat_items
        })
    }

    #[test]
    fn parses_sent_delivered_and_failed_statuses() {
        let cases = [
            ("sndNew", DeliveryStatus::Pending),
            ("sndSent", DeliveryStatus::Sent),
            ("sndRcvd", DeliveryStatus::Received),
            ("sndErrorAuth", DeliveryStatus::Failed),
            ("sndError", DeliveryStatus::Failed),
            ("sndWarning", DeliveryStatus::Failed),
        ];
        for (status_type, expected) in cases {
            let event =
                sample_statuses_updated(serde_json::json!([sent_status_item(5, 42, status_type)]));
            assert_eq!(
                parse_events(event),
                vec![ChatEvent::MessageDelivery(MessageDelivery {
                    contact_id: 5,
                    item_id: 42,
                    status: expected,
                })],
                "status type {status_type}"
            );
        }
    }

    #[test]
    fn ignores_a_received_items_status_update() {
        let mut item = sent_status_item(5, 42, "sndSent");
        item["chatItem"]["chatDir"] = serde_json::json!({"type": "directRcv"});
        let event = sample_statuses_updated(serde_json::json!([item]));
        assert_eq!(parse_events(event), Vec::new());
    }

    #[test]
    fn ignores_a_group_status_update() {
        let mut item = sent_status_item(5, 42, "sndSent");
        item["chatInfo"] = serde_json::json!({
            "type": "group",
            "groupInfo": {"groupId": 1}
        });
        let event = sample_statuses_updated(serde_json::json!([item]));
        assert_eq!(parse_events(event), Vec::new());
    }

    #[test]
    fn unrecognised_status_type_is_skipped_not_a_panic() {
        let event = sample_statuses_updated(serde_json::json!([sent_status_item(
            5,
            42,
            "somethingFuture"
        )]));
        assert_eq!(parse_events(event), Vec::new());
    }

    #[test]
    fn malformed_statuses_updated_missing_the_array_is_unrecognised_not_a_panic() {
        let event = serde_json::json!({"type": "chatItemsStatusesUpdated", "user": {"userId": 1}});
        assert_eq!(
            parse_events(event.clone()),
            vec![ChatEvent::Unrecognised(event)]
        );
    }
}
