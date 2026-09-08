//! Messaging substrate adapter for Secure.
//!
//! This crate is the *only* place in the workspace permitted to know that the messaging
//! substrate is SimpleX - see `docs/licensing.md` for why that boundary is kept even though the
//! AGPLv3 licensing decision permits linking SimpleX's implementation code directly elsewhere
//! too. The Tauri host and UI depend only on the narrow public surface re-exported here
//! ([`SimplexAdapter`], [`Invitation`], [`AdapterError`]), never on a `simplex`-module type.
//!
//! # Scope of this first slice
//!
//! Implemented: bootstrap (start chat + create the local user), creating and accepting
//! one-time invitations, sending plain-text messages, the raw chat-event stream, and typed
//! parsing of the four events this crate currently understands - a plain-text message received
//! in a direct chat, a contact connecting, a contact disconnecting (peer-initiated), and a
//! delivery-status update for a message this client sent - via [`parse_chat_event`]. Not yet
//! implemented, per the project's "no decorative implementation" rule rather than stubbed:
//! group chat, file attachments, session/key rotation events, local (as opposed to
//! whole-subprocess) conversation disconnect, and exporting protocol state into the encrypted
//! vault (`secure-storage`). See `docs/implementation-plan.md` Phase 3 for the full
//! adapter-boundary checklist this is working through.
//!
//! # What has and has not actually been run
//!
//! [`simplex::commands`] (the exact command strings sent to `simplex-chat`) and
//! [`simplex::protocol`] (the `corrId` request/response correlation bookkeeping) are pure and
//! unit-tested against `simplex-chat`'s own documented API reference. The process spawn,
//! WebSocket connection, bootstrap and invitation path has also been run against the official
//! `simplex-chat` v7.0.0 Linux release and is preserved as an ignored live test. A two-client
//! contact/message round trip remains outstanding; see `docs/implementation-plan.md` Phase 3.
//!
//! [`SimplexAdapter::launch`] requires a database encryption key and a SOCKS proxy address,
//! checked against `simplex-chat`'s own `Simplex.Chat.Options`/`Simplex.Chat.Options.Sqlite`
//! source (`-k`/`--key`, `--socks-proxy`) rather than assumed: an empty key or a missing proxy
//! would silently reintroduce, respectively, a plaintext protocol database and a clearnet
//! fallback path - exactly what this workspace's encrypted-storage and Tor-only-transport
//! invariants exist to prevent.

mod simplex;

pub use simplex::adapter::{AdapterError, Invitation, SimplexAdapter};
pub use simplex::client::EventReceiver;
pub use simplex::events::{
    ChatEvent, ContactConnected, ContactDisconnected, DeliveryStatus, IncomingMessage,
    MessageDelivery,
};
#[cfg(feature = "simplex-native")]
pub use simplex::native_adapter::NativeSimplexAdapter;

/// Parse one raw event value received from an [`EventReceiver`] into zero or more typed
/// [`ChatEvent`]s - zero when the event's type is recognised but carried nothing this crate
/// parses yet (e.g. a batch of only group messages), more than one when a single envelope
/// batches several direct-chat text messages.
#[must_use]
pub fn parse_chat_event(value: serde_json::Value) -> Vec<ChatEvent> {
    simplex::events::parse_events(value)
}
