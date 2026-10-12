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

/// Upper bound on commands awaiting a response at once. The desktop host issues commands one
/// user action at a time, so this is far above legitimate use; it exists so a stalled or
/// malicious peer that never answers cannot make the table grow without limit
/// (`docs/security-remediation-plan.md` Phase R7).
pub(crate) const MAX_IN_FLIGHT_COMMANDS: usize = 64;

/// Why [`CorrelationTable::register`] refused to reserve a new `corrId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RegisterError {
    /// [`MAX_IN_FLIGHT_COMMANDS`] are already waiting; the caller must back off.
    TooManyInFlight,
    /// [`CorrelationTable::close`] has run; no response can ever arrive.
    Closed,
}

struct PendingState {
    waiters: HashMap<String, oneshot::Sender<serde_json::Value>>,
    closed: bool,
}

/// Generates unique `corrId` values and matches incoming [`IncomingEnvelope`]s back to the
/// caller awaiting that command's response.
pub(crate) struct CorrelationTable {
    next_id: AtomicU64,
    pending: Mutex<PendingState>,
}

impl CorrelationTable {
    pub(crate) fn new() -> Self {
        Self {
            next_id: AtomicU64::new(0),
            pending: Mutex::new(PendingState {
                waiters: HashMap::new(),
                closed: false,
            }),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, PendingState> {
        // The critical sections below never panic, so poisoning cannot occur in practice; if
        // it somehow did, the table's contents are still structurally valid, so recover rather
        // than turning one bug into a crash on every later command.
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Reserve a new `corrId` and return it alongside the receiving half of the channel its
    /// eventual response will be delivered on. The caller must [`Self::cancel`] the id if it
    /// stops waiting before a response arrives (timeout, send failure, cancellation) - see
    /// [`PendingGuard`], which does that automatically.
    pub(crate) fn register(
        &self,
    ) -> Result<(String, oneshot::Receiver<serde_json::Value>), RegisterError> {
        let mut state = self.state();
        if state.closed {
            return Err(RegisterError::Closed);
        }
        if state.waiters.len() >= MAX_IN_FLIGHT_COMMANDS {
            return Err(RegisterError::TooManyInFlight);
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let corr_id = format!("secure-{id}");
        let (tx, rx) = oneshot::channel();
        state.waiters.insert(corr_id.clone(), tx);
        Ok((corr_id, rx))
    }

    /// Forget a pending `corrId` whose caller is no longer waiting. A response that arrives
    /// for it afterwards is treated as unsolicited by [`Self::route`]; see that method for why
    /// a stale response must not be mistaken for a fresh event, which is why `route` still
    /// recognises the `secure-` prefix this table issues.
    pub(crate) fn cancel(&self, corr_id: &str) {
        self.state().waiters.remove(corr_id);
    }

    /// Resolve every outstanding waiter with "connection closed" (by dropping its sender) and
    /// refuse all future registrations. Called when the underlying connection or core is torn
    /// down so no caller is left waiting for a response that can never arrive.
    pub(crate) fn close(&self) {
        let mut state = self.state();
        state.closed = true;
        state.waiters.clear();
    }

    #[cfg(test)]
    pub(crate) fn pending_len(&self) -> usize {
        self.state().waiters.len()
    }

    /// Route one incoming envelope. If its `corrId` matches a still-pending request, that
    /// request's waiter is resolved and `None` is returned (the envelope has been consumed as
    /// a command response). Otherwise the envelope's response payload is returned as an
    /// unsolicited event for the caller to forward on.
    ///
    /// A response carrying a `corrId` this table issued but is no longer waiting on (the caller
    /// timed out or was cancelled) is silently discarded rather than treated as an event -
    /// re-surfacing a stale command response as if it were a fresh chat event would be
    /// actively misleading.
    pub(crate) fn route(&self, envelope: IncomingEnvelope) -> Option<serde_json::Value> {
        if let Some(corr_id) = &envelope.corr_id {
            let waiter = self.state().waiters.remove(corr_id);
            if let Some(waiter) = waiter {
                let _ = waiter.send(envelope.resp);
                return None;
            }
            if self.issued(corr_id) {
                return None;
            }
        }
        Some(envelope.resp)
    }

    /// Whether `corr_id` has the exact form this table hands out and a number already issued.
    fn issued(&self, corr_id: &str) -> bool {
        corr_id
            .strip_prefix("secure-")
            .and_then(|n| n.parse::<u64>().ok())
            .is_some_and(|n| n < self.next_id.load(Ordering::Relaxed))
    }
}

/// Cancels its `corrId` in the [`CorrelationTable`] when dropped, so a caller that stops waiting
/// for any reason - timeout, send failure, or its future being dropped mid-await - can never
/// leave a permanently unanswered entry behind.
pub(crate) struct PendingGuard<'a> {
    table: &'a CorrelationTable,
    corr_id: String,
}

impl<'a> PendingGuard<'a> {
    pub(crate) fn new(table: &'a CorrelationTable, corr_id: String) -> Self {
        Self { table, corr_id }
    }
}

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        self.table.cancel(&self.corr_id);
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
        let (first, _) = table.register().expect("register");
        let (second, _) = table.register().expect("register");
        assert_ne!(first, second);
    }

    #[tokio::test]
    async fn routing_a_matching_response_resolves_the_waiter_and_consumes_the_envelope() {
        let table = CorrelationTable::new();
        let (corr_id, rx) = table.register().expect("register");

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
        let (corr_id, rx) = table.register().expect("register");
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
    #[test]
    fn cancelled_requests_leave_the_table_empty() {
        let table = CorrelationTable::new();
        let (corr_id, _rx) = table.register().expect("register");
        assert_eq!(table.pending_len(), 1);
        table.cancel(&corr_id);
        assert_eq!(table.pending_len(), 0);
    }

    #[test]
    fn pending_guard_cancels_on_drop() {
        let table = CorrelationTable::new();
        let (corr_id, _rx) = table.register().expect("register");
        drop(PendingGuard::new(&table, corr_id));
        assert_eq!(table.pending_len(), 0);
    }

    #[test]
    fn a_late_response_after_cancel_is_discarded_not_surfaced() {
        let table = CorrelationTable::new();
        let (corr_id, _rx) = table.register().expect("register");
        table.cancel(&corr_id);
        let surfaced = table.route(IncomingEnvelope {
            corr_id: Some(corr_id),
            resp: serde_json::json!({"type": "activeUser"}),
        });
        assert_eq!(surfaced, None);
    }

    #[test]
    fn maximum_in_flight_command_count_is_enforced() {
        let table = CorrelationTable::new();
        let mut receivers = Vec::new();
        for _ in 0..MAX_IN_FLIGHT_COMMANDS {
            receivers.push(table.register().expect("under the limit"));
        }
        assert_eq!(table.register().err(), Some(RegisterError::TooManyInFlight));

        let (corr_id, _) = receivers.pop().expect("one registered");
        table.cancel(&corr_id);
        assert!(table.register().is_ok(), "capacity frees up after cancel");
    }

    #[tokio::test]
    async fn close_releases_every_waiter_and_refuses_new_registrations() {
        let table = CorrelationTable::new();
        let (_, first) = table.register().expect("register");
        let (_, second) = table.register().expect("register");
        table.close();
        assert!(first.await.is_err(), "waiter must observe the close");
        assert!(second.await.is_err(), "waiter must observe the close");
        assert_eq!(table.register().err(), Some(RegisterError::Closed));
        assert_eq!(table.pending_len(), 0);
    }
}
