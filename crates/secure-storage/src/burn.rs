//! Phase 5 - Burn Conversation: cryptographic destruction of a single conversation.
//!
//! Implements the "required sequence" from `docs/implementation-plan.md` Phase 5, restricted to
//! what this crate alone can act on (no live protocol adapter or attachment pipeline exists yet
//! to cooperate with - see the module-level caveats below for what that means for steps 3 and
//! 8 of that sequence):
//!
//! 1. freeze new sends/receives for the target conversation - `conversations.destroyed_at_unix_ms`
//!    is set. A caller (the messaging layer, once it exists) is expected to refuse to send or
//!    accept messages for a conversation once this is non-null; this crate cannot itself
//!    enforce that against a network path it doesn't own;
//! 2. mark the destruction operation as monotonic/in-progress - a `destruction_tombstones` row,
//!    `scope = 'conversation'`;
//! 3. destroy protocol/session secrets for the target relationship where supported - this crate
//!    only knows about `protocol_adapter_state`, which it deletes for the conversation's
//!    contact. Any *in-memory* session state a live protocol adapter is holding is out of this
//!    crate's reach; the messaging crate implementing that adapter is not wired to this crate's
//!    schema yet ("protocol state export into the encrypted vault" is a still-open Phase 3 item);
//! 4. destroy local attachment keys - every attachment under the conversation's messages has its
//!    `attachment_key` overwritten with an empty blob;
//! 5. remove message/contact relationship records required by the burn scope - drafts and
//!    messages for the conversation are deleted (attachment *rows* cascade-delete with their
//!    parent message, which is safe only because step 4 already destroyed their keys first -
//!    this is "keys before files" applied to database rows, not just filesystem objects). The
//!    conversation row itself and the contact are kept, matching the schema's existing
//!    `destroyed_at_unix_ms` column design: a frozen, content-empty conversation record remains
//!    as a tombstone rather than disappearing outright;
//! 6. delete encrypted attachment ciphertext best-effort - the ciphertext lives outside this
//!    database, so step 4 records each object's opaque name in `pending_object_deletions` in the
//!    same transaction that destroys its key. The owner of the attachment directory deletes the
//!    files afterwards (`Vault::pending_object_deletions` / `acknowledge_object_deleted`), and
//!    anything a crash interrupts is still queued on the next unlock - keys before files, and
//!    files never forgotten;
//! 7. persist terminal local destruction state - the tombstone's stage reaches `Complete`;
//! 8. optionally request cooperative remote deletion - out of scope for this crate; it has no
//!    network access and no protocol adapter dependency by design (see this crate's docs).
//!
//! Every stage transition commits inside one SQL transaction together with the tombstone's
//! updated stage, so a crash between stages leaves the tombstone reflecting exactly what was
//! actually committed - re-running [`burn_conversation`] against the same conversation always
//! resumes forward from that stage, never re-does an already-committed step, and never moves
//! backward. This is the same "transaction-per-step" pattern `migrations.rs` already uses for
//! the same crash-consistency reason.

use std::time::{SystemTime, UNIX_EPOCH};

use rand_core::{OsRng, RngCore};
use rusqlite::OptionalExtension;

use crate::{StorageError, Vault};

/// Monotonic stages of a single conversation's destruction. Ordered; [`BurnStage::next`] is the
/// only way to advance, so a stage can never be skipped or reordered by a caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BurnStage {
    Requested,
    Frozen,
    ProtocolSecretsDestroyed,
    AttachmentKeysDestroyed,
    RecordsRemoved,
    Complete,
}

impl BurnStage {
    fn as_db_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Frozen => "frozen",
            Self::ProtocolSecretsDestroyed => "protocol_secrets_destroyed",
            Self::AttachmentKeysDestroyed => "attachment_keys_destroyed",
            Self::RecordsRemoved => "records_removed",
            Self::Complete => "complete",
        }
    }

    fn from_db_str(value: &str) -> Result<Self, StorageError> {
        match value {
            "requested" => Ok(Self::Requested),
            "frozen" => Ok(Self::Frozen),
            "protocol_secrets_destroyed" => Ok(Self::ProtocolSecretsDestroyed),
            "attachment_keys_destroyed" => Ok(Self::AttachmentKeysDestroyed),
            "records_removed" => Ok(Self::RecordsRemoved),
            "complete" => Ok(Self::Complete),
            other => Err(StorageError::CorruptDestructionStage {
                value: other.to_owned(),
            }),
        }
    }

    fn next(self) -> Option<Self> {
        match self {
            Self::Requested => Some(Self::Frozen),
            Self::Frozen => Some(Self::ProtocolSecretsDestroyed),
            Self::ProtocolSecretsDestroyed => Some(Self::AttachmentKeysDestroyed),
            Self::AttachmentKeysDestroyed => Some(Self::RecordsRemoved),
            Self::RecordsRemoved => Some(Self::Complete),
            Self::Complete => None,
        }
    }
}

fn random_id() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    let mut out = String::with_capacity(32);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// Drive a single conversation's destruction all the way to [`BurnStage::Complete`].
///
/// Idempotent and resumable: calling this again for a conversation that is already fully
/// destroyed is a no-op that returns `Ok(BurnStage::Complete)` without touching the database;
/// calling it again after a partial burn (e.g. the process crashed mid-way) continues from
/// exactly the stage the tombstone last recorded.
pub fn burn_conversation(
    vault: &mut Vault,
    conversation_id: &str,
) -> Result<BurnStage, StorageError> {
    let conn = vault.connection_mut();

    let conversation_exists: bool = conn
        .query_row(
            "SELECT 1 FROM conversations WHERE id = ?1;",
            rusqlite::params![conversation_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !conversation_exists {
        return Err(StorageError::ConversationNotFound);
    }

    let existing_tombstone: Option<(String, String)> = conn
        .query_row(
            "SELECT id, stage FROM destruction_tombstones \
             WHERE scope = 'conversation' AND target_id = ?1;",
            rusqlite::params![conversation_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;

    let (tombstone_id, mut stage) = match existing_tombstone {
        Some((id, stage_str)) => (id, BurnStage::from_db_str(&stage_str)?),
        None => {
            let id = random_id();
            let now = now_unix_ms();
            conn.execute(
                "INSERT INTO destruction_tombstones \
                 (id, scope, target_id, stage, created_at_unix_ms, updated_at_unix_ms) \
                 VALUES (?1, 'conversation', ?2, ?3, ?4, ?4);",
                rusqlite::params![id, conversation_id, BurnStage::Requested.as_db_str(), now],
            )?;
            (id, BurnStage::Requested)
        }
    };

    while let Some(target_stage) = stage.next() {
        let tx = conn.transaction()?;
        run_stage(&tx, conversation_id, target_stage)?;
        tx.execute(
            "UPDATE destruction_tombstones SET stage = ?1, updated_at_unix_ms = ?2 WHERE id = ?3;",
            rusqlite::params![target_stage.as_db_str(), now_unix_ms(), tombstone_id],
        )?;
        tx.commit()?;
        stage = target_stage;
    }

    Ok(stage)
}

/// Resume every conversation burn that was left incomplete (e.g. by a crash or forced
/// termination) the last time this vault was open, driving each to [`BurnStage::Complete`].
/// Intended to be called once, early, whenever the vault is opened - the same "restart resumes
/// forward" contract [`burn_conversation`] already provides for one conversation, applied to
/// every conversation with an unfinished tombstone.
pub fn resume_incomplete_conversation_burns(
    vault: &mut Vault,
) -> Result<Vec<String>, StorageError> {
    let pending: Vec<String> = {
        let conn = vault.connection_mut();
        let mut statement = conn.prepare(
            "SELECT target_id FROM destruction_tombstones \
             WHERE scope = 'conversation' AND stage != 'complete';",
        )?;
        let rows = statement.query_map([], |row| row.get::<_, Option<String>>(0))?;
        rows.filter_map(Result::ok).flatten().collect()
    };

    for conversation_id in &pending {
        burn_conversation(vault, conversation_id)?;
    }

    Ok(pending)
}

/// Perform exactly the database work for entering `target_stage`, on the assumption the
/// previous stage has already been reached (the caller drives stages strictly in order via
/// [`BurnStage::next`], so this never has to check what stage it is coming from).
fn run_stage(
    conn: &rusqlite::Connection,
    conversation_id: &str,
    target_stage: BurnStage,
) -> Result<(), StorageError> {
    match target_stage {
        BurnStage::Requested => unreachable!("Requested is the initial stage, never a target"),
        BurnStage::Frozen => {
            conn.execute(
                "UPDATE conversations SET destroyed_at_unix_ms = ?1 \
                 WHERE id = ?2 AND destroyed_at_unix_ms IS NULL;",
                rusqlite::params![now_unix_ms(), conversation_id],
            )?;
        }
        BurnStage::ProtocolSecretsDestroyed => {
            conn.execute(
                "DELETE FROM protocol_adapter_state \
                 WHERE contact_id = (SELECT contact_id FROM conversations WHERE id = ?1);",
                rusqlite::params![conversation_id],
            )?;
        }
        BurnStage::AttachmentKeysDestroyed => {
            // Queue the objects' names before their rows (the only other record of them) go in
            // the next stage. Same transaction as the key destruction, so there is no crash
            // window in which keys are gone but the ciphertext has been forgotten.
            conn.execute(
                "INSERT OR IGNORE INTO pending_object_deletions (object_name) \
                 SELECT object_name FROM attachments \
                 WHERE message_id IN (SELECT id FROM messages WHERE conversation_id = ?1);",
                rusqlite::params![conversation_id],
            )?;
            conn.execute(
                "UPDATE attachments SET attachment_key = X'' \
                 WHERE message_id IN (SELECT id FROM messages WHERE conversation_id = ?1);",
                rusqlite::params![conversation_id],
            )?;
        }
        BurnStage::RecordsRemoved => {
            conn.execute(
                "DELETE FROM drafts WHERE conversation_id = ?1;",
                rusqlite::params![conversation_id],
            )?;
            // Cascades to this conversation's attachments (ON DELETE CASCADE from
            // messages.id), whose keys were already destroyed in the previous stage.
            conn.execute(
                "DELETE FROM messages WHERE conversation_id = ?1;",
                rusqlite::params![conversation_id],
            )?;
        }
        BurnStage::Complete => {
            // The previous stage already did the real work; reaching this stage in
            // `burn_conversation`'s loop just persists the terminal marker.
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use secure_crypto::VaultKey;

    fn open_test_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.db");
        let vault_key = VaultKey::generate().expect("test randomness must be available");
        let vault = Vault::create_new(&path, &vault_key).expect("create vault");
        (dir, vault)
    }

    fn seed_conversation_with_attachment(vault: &mut Vault) -> (String, String, String) {
        let conversation_id = vault
            .insert_conversation("burn-target")
            .expect("insert conversation");
        let message_id = vault
            .insert_outgoing_message(&conversation_id, b"secret content")
            .expect("insert message");
        let attachment_id = random_id();
        vault
            .connection_mut()
            .execute(
                "INSERT INTO attachments \
                 (id, message_id, object_name, content_type, expected_size_bytes, \
                  attachment_key, created_at_unix_ms) \
                 VALUES (?1, ?2, 'obj', 'text/plain', 4, ?3, ?4);",
                rusqlite::params![
                    attachment_id,
                    message_id,
                    b"a real 32 byte attachment key!!",
                    now_unix_ms()
                ],
            )
            .expect("insert attachment");
        (conversation_id, message_id, attachment_id)
    }

    #[test]
    fn burn_reaches_complete_and_is_idempotent() {
        let (_dir, mut vault) = open_test_vault();
        let (conversation_id, ..) = seed_conversation_with_attachment(&mut vault);

        let stage = burn_conversation(&mut vault, &conversation_id).expect("first burn");
        assert_eq!(stage, BurnStage::Complete);

        // Calling it again must not error and must stay Complete - a repeated burn request is
        // idempotent, per the Phase 5 test list.
        let stage_again = burn_conversation(&mut vault, &conversation_id).expect("second burn");
        assert_eq!(stage_again, BurnStage::Complete);
    }

    #[test]
    fn burn_unknown_conversation_is_an_error_not_a_silent_no_op() {
        let (_dir, mut vault) = open_test_vault();
        let err = burn_conversation(&mut vault, "does-not-exist").expect_err("must fail");
        assert!(matches!(err, StorageError::ConversationNotFound));
    }

    #[test]
    fn burn_destroys_attachment_keys_before_removing_rows() {
        let (_dir, mut vault) = open_test_vault();
        let (conversation_id, _message_id, attachment_id) =
            seed_conversation_with_attachment(&mut vault);

        burn_conversation(&mut vault, &conversation_id).expect("burn");

        // The message (and therefore its attachment row) is gone entirely...
        let remaining_attachments: i64 = vault
            .connection()
            .query_row(
                "SELECT count(*) FROM attachments WHERE id = ?1;",
                rusqlite::params![attachment_id],
                |row| row.get(0),
            )
            .expect("query attachments");
        assert_eq!(remaining_attachments, 0);

        // ...but this proves the *ordering*, not just the end state: burning again on a
        // freshly seeded attachment must show the key was blanked in its own committed
        // transaction before the row-removal stage ran, not merely that both ended up gone
        // together. Directly re-run just the key-destruction stage against a second seed and
        // check the key value in isolation.
        let (_dir2, mut vault2) = open_test_vault();
        let (conversation_id2, _message_id2, attachment_id2) =
            seed_conversation_with_attachment(&mut vault2);
        {
            let conn = vault2.connection_mut();
            run_stage(conn, &conversation_id2, BurnStage::Frozen).expect("freeze");
            run_stage(conn, &conversation_id2, BurnStage::ProtocolSecretsDestroyed)
                .expect("destroy protocol secrets");
            run_stage(conn, &conversation_id2, BurnStage::AttachmentKeysDestroyed)
                .expect("destroy attachment keys");
        }
        let key: Vec<u8> = vault2
            .connection()
            .query_row(
                "SELECT attachment_key FROM attachments WHERE id = ?1;",
                rusqlite::params![attachment_id2],
                |row| row.get(0),
            )
            .expect("query attachment key");
        assert!(
            key.is_empty(),
            "attachment key must be destroyed before the row-removal stage runs"
        );
    }

    #[test]
    fn burn_deletes_protocol_adapter_state_for_the_contact() {
        let (_dir, mut vault) = open_test_vault();
        let contact_id = random_id();
        vault
            .connection_mut()
            .execute(
                "INSERT INTO contacts (id, local_alias, created_at_unix_ms) VALUES (?1, 'c', ?2);",
                rusqlite::params![contact_id, now_unix_ms()],
            )
            .expect("insert contact");
        vault
            .connection_mut()
            .execute(
                "INSERT INTO protocol_adapter_state (contact_id, state_blob, updated_at_unix_ms) \
                 VALUES (?1, ?2, ?3);",
                rusqlite::params![contact_id, b"session secret".to_vec(), now_unix_ms()],
            )
            .expect("insert protocol adapter state");
        let conversation_id = random_id();
        vault
            .connection_mut()
            .execute(
                "INSERT INTO conversations (id, contact_id, local_alias, created_at_unix_ms) \
                 VALUES (?1, ?2, 'c', ?3);",
                rusqlite::params![conversation_id, contact_id, now_unix_ms()],
            )
            .expect("insert conversation with contact");

        burn_conversation(&mut vault, &conversation_id).expect("burn");

        let remaining: i64 = vault
            .connection()
            .query_row(
                "SELECT count(*) FROM protocol_adapter_state WHERE contact_id = ?1;",
                rusqlite::params![contact_id],
                |row| row.get(0),
            )
            .expect("query protocol_adapter_state");
        assert_eq!(
            remaining, 0,
            "protocol/session secrets must be destroyed by the burn"
        );
    }

    #[test]
    fn burn_freezes_the_conversation_row_rather_than_deleting_it() {
        let (_dir, mut vault) = open_test_vault();
        let (conversation_id, ..) = seed_conversation_with_attachment(&mut vault);

        burn_conversation(&mut vault, &conversation_id).expect("burn");

        let destroyed_at: Option<i64> = vault
            .connection()
            .query_row(
                "SELECT destroyed_at_unix_ms FROM conversations WHERE id = ?1;",
                rusqlite::params![conversation_id],
                |row| row.get(0),
            )
            .expect("conversation row must still exist as a tombstone");
        assert!(
            destroyed_at.is_some(),
            "surviving conversation row must be marked destroyed"
        );
    }

    #[test]
    fn resuming_from_a_mid_burn_crash_continues_forward_and_completes() {
        let (_dir, mut vault) = open_test_vault();
        let (conversation_id, ..) = seed_conversation_with_attachment(&mut vault);

        // Simulate a crash after the Frozen stage committed but before anything later ran, by
        // driving only that far manually instead of calling the full burn_conversation loop.
        let tombstone_id = random_id();
        {
            let conn = vault.connection_mut();
            let tx = conn.transaction().expect("begin tx");
            run_stage(&tx, &conversation_id, BurnStage::Frozen).expect("freeze");
            tx.execute(
                "INSERT INTO destruction_tombstones \
                 (id, scope, target_id, stage, created_at_unix_ms, updated_at_unix_ms) \
                 VALUES (?1, 'conversation', ?2, 'frozen', ?3, ?3);",
                rusqlite::params![tombstone_id, conversation_id, now_unix_ms()],
            )
            .expect("insert tombstone at frozen stage");
            tx.commit().expect("commit");
        }

        // Resuming (as if the app had just restarted) must pick this exact conversation up
        // from Frozen, never redo Requested->Frozen, and must reach Complete.
        let resumed = resume_incomplete_conversation_burns(&mut vault).expect("resume");
        assert_eq!(resumed, vec![conversation_id.clone()]);

        let final_stage: String = vault
            .connection()
            .query_row(
                "SELECT stage FROM destruction_tombstones WHERE id = ?1;",
                rusqlite::params![tombstone_id],
                |row| row.get(0),
            )
            .expect("query tombstone");
        assert_eq!(final_stage, "complete");
    }

    #[test]
    fn resume_with_nothing_pending_is_a_no_op() {
        let (_dir, mut vault) = open_test_vault();
        let resumed = resume_incomplete_conversation_burns(&mut vault).expect("resume");
        assert!(resumed.is_empty());
    }

    #[test]
    fn corrupt_stage_value_is_reported_not_panicked_on() {
        let (_dir, mut vault) = open_test_vault();
        let (conversation_id, ..) = seed_conversation_with_attachment(&mut vault);
        vault
            .connection_mut()
            .execute(
                "INSERT INTO destruction_tombstones \
                 (id, scope, target_id, stage, created_at_unix_ms, updated_at_unix_ms) \
                 VALUES (?1, 'conversation', ?2, 'not-a-real-stage', ?3, ?3);",
                rusqlite::params![random_id(), conversation_id, now_unix_ms()],
            )
            .expect("insert corrupt tombstone");

        let err = burn_conversation(&mut vault, &conversation_id).expect_err("must fail");
        assert!(matches!(err, StorageError::CorruptDestructionStage { .. }));
    }
    #[test]
    fn burn_queues_attachment_objects_for_deletion_and_destroys_their_keys() {
        let (_dir, mut vault) = open_test_vault();
        let conversation_id = vault.insert_conversation("c").expect("conversation");
        let message_id = vault
            .insert_outgoing_message(&conversation_id, b"ct")
            .expect("message");
        let attachment_id = vault
            .insert_attachment(
                &message_id,
                "0123456789abcdef0123456789abcdef",
                "image/png",
                3,
                &[9_u8; 32],
            )
            .expect("attachment");
        assert_eq!(
            vault
                .attachment(&attachment_id)
                .expect("lookup")
                .key
                .as_slice(),
            &[9_u8; 32]
        );

        burn_conversation(&mut vault, &conversation_id).expect("burn");

        assert!(matches!(
            vault.attachment(&attachment_id),
            Err(StorageError::AttachmentNotFound)
        ));
        assert_eq!(
            vault.pending_object_deletions().expect("pending"),
            ["0123456789abcdef0123456789abcdef"]
        );
        vault
            .acknowledge_object_deleted("0123456789abcdef0123456789abcdef")
            .expect("ack");
        assert!(
            vault
                .pending_object_deletions()
                .expect("pending")
                .is_empty()
        );
    }

    #[test]
    fn crash_after_key_destruction_keeps_the_object_queued_for_cleanup() {
        let (_dir, mut vault) = open_test_vault();
        let conversation_id = vault.insert_conversation("c").expect("conversation");
        let message_id = vault
            .insert_outgoing_message(&conversation_id, b"ct")
            .expect("message");
        let attachment_id = vault
            .insert_attachment(
                &message_id,
                "fedcba9876543210fedcba9876543210",
                "x/y",
                1,
                &[1_u8; 32],
            )
            .expect("attachment");

        // Run exactly the key-destruction stage's transaction, as a crash right after it would
        // leave things, then check the object is not forgotten.
        {
            let conn = vault.connection_mut();
            let tx = conn.transaction().expect("tx");
            run_stage(&tx, &conversation_id, BurnStage::AttachmentKeysDestroyed).expect("stage");
            tx.commit().expect("commit");
        }
        assert!(matches!(
            vault.attachment(&attachment_id),
            Err(StorageError::AttachmentNotFound)
        ));
        assert_eq!(
            vault.pending_object_deletions().expect("pending"),
            ["fedcba9876543210fedcba9876543210"]
        );
    }
}
