//! Typed insert helpers for the initial vault schema.
//!
//! The public `Vault` methods are the narrow storage boundary used by later-phase messaging
//! integration. These helpers remain private so SQL details and random-id generation do not
//! leak into callers.

use std::time::{SystemTime, UNIX_EPOCH};

use rand_core::{OsRng, RngCore};
use rusqlite::OptionalExtension;
use zeroize::Zeroizing;

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

pub(crate) fn insert_conversation(
    vault: &mut Vault,
    local_alias: &str,
) -> Result<String, StorageError> {
    let id = random_id();
    vault.connection_mut().execute(
        "INSERT INTO conversations (id, contact_id, local_alias, created_at_unix_ms) \
         VALUES (?1, NULL, ?2, ?3);",
        rusqlite::params![id, local_alias, now_unix_ms()],
    )?;
    Ok(id)
}

/// Resolve the conversation for a protocol-assigned contact id (e.g. SimpleX's own integer
/// contact id), creating the contact and its conversation on first sight. Repeat events for the
/// same `external_contact_id` reuse the existing conversation instead of creating a duplicate
/// one per event - `contacts_external_id_idx` (migration 0003) is what makes that lookup exact.
pub(crate) fn find_or_create_conversation_for_contact(
    vault: &mut Vault,
    external_contact_id: i64,
    fallback_alias: &str,
) -> Result<String, StorageError> {
    if let Some(id) = vault
        .connection_mut()
        .query_row(
            "SELECT conversations.id FROM conversations \
             JOIN contacts ON contacts.id = conversations.contact_id \
             WHERE contacts.external_id = ?1;",
            rusqlite::params![external_contact_id],
            |row| row.get(0),
        )
        .optional()?
    {
        return Ok(id);
    }

    let contact_id = random_id();
    vault.connection_mut().execute(
        "INSERT INTO contacts (id, local_alias, created_at_unix_ms, external_id) \
         VALUES (?1, ?2, ?3, ?4);",
        rusqlite::params![
            contact_id,
            fallback_alias,
            now_unix_ms(),
            external_contact_id
        ],
    )?;

    let conversation_id = random_id();
    vault.connection_mut().execute(
        "INSERT INTO conversations (id, contact_id, local_alias, created_at_unix_ms) \
         VALUES (?1, ?2, ?3, ?4);",
        rusqlite::params![conversation_id, contact_id, fallback_alias, now_unix_ms()],
    )?;
    Ok(conversation_id)
}

pub(crate) fn insert_message_with_direction(
    vault: &mut Vault,
    conversation_id: &str,
    ciphertext: &[u8],
    direction: &str,
) -> Result<String, StorageError> {
    let id = random_id();
    vault.connection_mut().execute(
        "INSERT INTO messages (id, conversation_id, direction, ciphertext, sent_at_unix_ms) \
         VALUES (?1, ?2, ?3, ?4, ?5);",
        rusqlite::params![id, conversation_id, direction, ciphertext, now_unix_ms()],
    )?;
    Ok(id)
}

pub(crate) fn insert_attachment(
    vault: &mut Vault,
    message_id: &str,
    object_name: &str,
    content_type: &str,
    expected_size_bytes: u64,
    attachment_key: &[u8; 32],
) -> Result<String, StorageError> {
    let id = random_id();
    vault.connection_mut().execute(
        "INSERT INTO attachments \
         (id, message_id, object_name, content_type, expected_size_bytes, attachment_key, \
          created_at_unix_ms) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7);",
        rusqlite::params![
            id,
            message_id,
            object_name,
            content_type,
            i64::try_from(expected_size_bytes).unwrap_or(i64::MAX),
            attachment_key.as_slice(),
            now_unix_ms()
        ],
    )?;
    Ok(id)
}

pub(crate) fn attachment(
    vault: &Vault,
    attachment_id: &str,
) -> Result<crate::StoredAttachment, StorageError> {
    let row: Option<(String, Option<String>, Zeroizing<Vec<u8>>)> = vault
        .conn
        .query_row(
            "SELECT object_name, content_type, attachment_key FROM attachments WHERE id = ?1;",
            rusqlite::params![attachment_id],
            |row| Ok((row.get(0)?, row.get(1)?, Zeroizing::new(row.get(2)?))),
        )
        .optional()?;
    let Some((object_name, content_type, key_bytes)) = row else {
        return Err(StorageError::AttachmentNotFound);
    };
    // A destroyed key is an empty blob (see `burn`); anything not exactly 32 bytes is unusable.
    let key: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| StorageError::AttachmentNotFound)?;
    Ok(crate::StoredAttachment {
        object_name,
        content_type,
        key: Zeroizing::new(key),
    })
}
