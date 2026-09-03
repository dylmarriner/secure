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
//! one-time invitations, sending plain-text messages, and the raw chat-event stream. Not yet
//! implemented, per the project's "no decorative implementation" rule rather than stubbed:
//! typed event parsing (events currently surface as raw `serde_json::Value`), delivery
//! acknowledgement, session/key rotation events, attachment transport references, and exporting
//! protocol state into the encrypted vault (`secure-storage`). See
//! `docs/implementation-plan.md` Phase 3 for the full adapter-boundary checklist this is
//! working through.
//!
//! # What has and has not actually been run
//!
//! [`simplex::commands`] (the exact command strings sent to `simplex-chat`) and
//! [`simplex::protocol`] (the `corrId` request/response correlation bookkeeping) are pure and
//! unit-tested against `simplex-chat`'s own documented API reference, with no process or
//! network dependency. The process-spawn-and-WebSocket-connect path in [`simplex::client`] and
//! the response-shape parsing in [`simplex::adapter`] have **not** been run against a real
//! `simplex-chat` process: building the Haskell `simplex-chat` CLI is impractical in this
//! development environment. They compile and follow the documented protocol/response shapes as
//! confirmed against `simplex-chat/simplex-chat`'s `bots/api/COMMANDS.md` and `TYPES.md`
//! (`stable` branch, 2026-09-04), not guessed - but that is not the same as having been
//! empirically run. See `docs/implementation-plan.md` Phase 3.

mod simplex;

pub use simplex::adapter::{AdapterError, Invitation, SimplexAdapter};
pub use simplex::client::EventReceiver;
