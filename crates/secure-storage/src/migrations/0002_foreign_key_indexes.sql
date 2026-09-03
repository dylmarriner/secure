-- SQLite does not automatically index foreign key columns. Without these, cascading deletes
-- during Burn Conversation / Burn Identity (removing all attachments for a message, all
-- invitations that resulted in a contact, etc.) fall back to full table scans. Both indexes
-- are on columns already declared as foreign keys in the initial schema; this migration adds
-- no new columns or tables.

CREATE INDEX attachments_message_id_idx ON attachments (message_id);
CREATE INDEX invitations_resulting_contact_id_idx ON invitations (resulting_contact_id);
