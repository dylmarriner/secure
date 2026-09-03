//! Typed insert helpers for the initial vault schema.
//!
//! This module is test-only scaffolding today: the only real caller is this crate's own
//! `no_application_controlled_plaintext_message_persistence` test. Real typed read/write APIs
//! belong to whichever later-phase crate (messaging, attachments) actually needs to persist
//! these records - adding a public CRUD surface here now, before anything consumes it, would
//! be exactly the "decorative implementation" the project's engineering rules rule out.

use std::time::{SystemTime, UNIX_EPOCH};

use rand_core::{OsRng, RngCore};

use crate::{StorageError, Vault};

/// A random 128-bit opaque identifier, lower-hex encoded.
///
/// Used instead of autoincrementing integer ids so that local record identifiers never leak
/// insertion order or row counts to anything that observes ids outside the database.
fn random_id() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    let mut out = String::with_capacity(32);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[derive(Debug, Clone)]
pub struct ConversationRecord {
    pub local_alias: String,
}

#[derive(Debug, Clone)]
pub struct MessageRecord {
    pub conversation_id: String,
    pub ciphertext: Vec<u8>,
}

pub(crate) fn insert_conversation(
    vault: &mut Vault,
    record: &ConversationRecord,
) -> Result<String, StorageError> {
    let id = random_id();
    vault.connection_mut().execute(
        "INSERT INTO conversations (id, contact_id, local_alias, created_at_unix_ms) \
         VALUES (?1, NULL, ?2, ?3);",
        rusqlite::params![id, record.local_alias, now_unix_ms()],
    )?;
    Ok(id)
}

pub(crate) fn insert_message(
    vault: &mut Vault,
    record: &MessageRecord,
) -> Result<String, StorageError> {
    let id = random_id();
    vault.connection_mut().execute(
        "INSERT INTO messages (id, conversation_id, direction, ciphertext, sent_at_unix_ms) \
         VALUES (?1, ?2, 'outgoing', ?3, ?4);",
        rusqlite::params![id, record.conversation_id, record.ciphertext, now_unix_ms()],
    )?;
    Ok(id)
}
