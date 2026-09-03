//! The `simplex-chat -p <port>` WebSocket JSON correlation protocol.
//!
//! Per `simplex-chat`'s own bot API documentation: every command sent is a JSON object
//! `{"corrId": "<unique string>", "cmd": "<command string>"}`; every reply is
//! `{"corrId": "<the same corrId>", "resp": {"type": ..., ...}}`. `simplex-chat` also pushes
//! unsolicited chat events over the same connection - those do not correlate to a command this
//! client sent, so they are told apart here purely by whether their `corrId` matches an
//! outstanding request, not by inspecting `resp.type`.
//!
//! This module is pure with respect to correlation bookkeeping (no socket, no process) so that
//! bookkeeping can be unit-tested directly: constructing envelopes and routing them through
//! [`CorrelationTable`] does not require a live `simplex-chat` connection.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

#[derive(Debug, Serialize)]
pub(crate) struct CommandEnvelope {
    #[serde(rename = "corrId")]
    pub(crate) corr_id: String,
    pub(crate) cmd: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct IncomingEnvelope {
    #[serde(rename = "corrId")]
    pub(crate) corr_id: Option<String>,
    pub(crate) resp: serde_json::Value,
}

/// Generates unique `corrId` values and matches incoming [`IncomingEnvelope`]s back to the
/// caller awaiting that command's response.
pub(crate) struct CorrelationTable {
    next_id: AtomicU64,
    pending: Mutex<HashMap<String, oneshot::Sender<serde_json::Value>>>,
}

impl CorrelationTable {
    pub(crate) fn new() -> Self {
        Self {
            next_id: AtomicU64::new(0),
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Reserve a new `corrId` and return it alongside the receiving half of the channel its
    /// eventual response will be delivered on.
    pub(crate) fn register(&self) -> (String, oneshot::Receiver<serde_json::Value>) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let corr_id = format!("secure-{id}");
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .expect("correlation table lock poisoned")
            .insert(corr_id.clone(), tx);
        (corr_id, rx)
    }

    /// Route one incoming envelope. If its `corrId` matches a still-pending request, that
    /// request's waiter is resolved and `None` is returned (the envelope has been consumed as
    /// a command response). Otherwise the envelope's response payload is returned as an
    /// unsolicited event for the caller to forward on.
    ///
    /// A response whose corresponding waiter has already been dropped (the caller stopped
    /// waiting, e.g. after a timeout) is silently discarded rather than treated as an event -
    /// re-surfacing a stale command response as if it were a fresh chat event would be
    /// actively misleading.
    pub(crate) fn route(&self, envelope: IncomingEnvelope) -> Option<serde_json::Value> {
        if let Some(corr_id) = &envelope.corr_id {
            let waiter = self
                .pending
                .lock()
                .expect("correlation table lock poisoned")
                .remove(corr_id);
            if let Some(waiter) = waiter {
                let _ = waiter.send(envelope.resp);
                return None;
            }
        }
        Some(envelope.resp)
    }
}

impl Default for CorrelationTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_registrations_get_distinct_corr_ids() {
        let table = CorrelationTable::new();
        let (first, _) = table.register();
        let (second, _) = table.register();
        assert_ne!(first, second);
    }

    #[tokio::test]
    async fn routing_a_matching_response_resolves_the_waiter_and_consumes_the_envelope() {
        let table = CorrelationTable::new();
        let (corr_id, rx) = table.register();

        let response = serde_json::json!({"type": "activeUser", "user": {"userId": 1}});
        let consumed = table.route(IncomingEnvelope {
            corr_id: Some(corr_id),
            resp: response.clone(),
        });

        assert!(
            consumed.is_none(),
            "a matched response must not also be surfaced as an event"
        );
        let delivered = rx.await.expect("waiter must receive the response");
        assert_eq!(delivered, response);
    }

    #[test]
    fn routing_an_envelope_with_no_matching_corr_id_surfaces_it_as_an_event() {
        let table = CorrelationTable::new();
        let event = serde_json::json!({"type": "newChatItems", "chatItems": []});

        let surfaced = table.route(IncomingEnvelope {
            corr_id: Some("no-such-request".to_owned()),
            resp: event.clone(),
        });
        assert_eq!(surfaced, Some(event));
    }

    #[test]
    fn routing_an_envelope_with_no_corr_id_at_all_surfaces_it_as_an_event() {
        let table = CorrelationTable::new();
        let event = serde_json::json!({"type": "contactConnected"});

        let surfaced = table.route(IncomingEnvelope {
            corr_id: None,
            resp: event.clone(),
        });
        assert_eq!(surfaced, Some(event));
    }

    #[test]
    fn a_stale_response_after_its_waiter_was_dropped_is_discarded_not_surfaced() {
        let table = CorrelationTable::new();
        let (corr_id, rx) = table.register();
        drop(rx);

        let surfaced = table.route(IncomingEnvelope {
            corr_id: Some(corr_id),
            resp: serde_json::json!({"type": "activeUser"}),
        });
        assert_eq!(
            surfaced, None,
            "a stale response must be discarded, not re-surfaced as an event"
        );
    }

    #[test]
    fn command_envelope_serialises_with_documented_field_names() {
        let envelope = CommandEnvelope {
            corr_id: "secure-0".to_owned(),
            cmd: "/_start".to_owned(),
        };
        let json = serde_json::to_value(&envelope).expect("serialises");
        assert_eq!(json["corrId"], "secure-0");
        assert_eq!(json["cmd"], "/_start");
    }
}
