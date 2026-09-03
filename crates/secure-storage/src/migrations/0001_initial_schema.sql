-- Initial encrypted vault schema (schema version 1).
--
-- The SQLite file itself is encrypted at rest by SQLCipher, so column-level values below are
-- not additionally encrypted by this crate; higher-level crates (messaging, attachments) are
-- responsible for storing already-encrypted ciphertext in the BLOB columns that carry
-- protocol or attachment content, per the "keys before files" and "no application-controlled
-- plaintext message persistence" invariants.
--
-- All identifiers are random 128-bit opaque tokens (lower-hex encoded), not sequential
-- integers, so local record identity never leaks insertion order or count to anything that
-- observes ids outside the database.

CREATE TABLE local_identity (
    id TEXT PRIMARY KEY,
    created_at_unix_ms INTEGER NOT NULL,
    display_alias TEXT,
    protocol_identity_blob BLOB
);

CREATE TABLE contacts (
    id TEXT PRIMARY KEY,
    local_alias TEXT NOT NULL,
    created_at_unix_ms INTEGER NOT NULL,
    verification_state TEXT NOT NULL DEFAULT 'unverified'
        CHECK (verification_state IN ('unverified', 'verified')),
    safety_code_fingerprint BLOB
);

CREATE TABLE invitations (
    id TEXT PRIMARY KEY,
    direction TEXT NOT NULL CHECK (direction IN ('outgoing', 'incoming')),
    state TEXT NOT NULL CHECK (state IN ('pending', 'accepted', 'expired', 'revoked')),
    created_at_unix_ms INTEGER NOT NULL,
    payload BLOB NOT NULL,
    resulting_contact_id TEXT REFERENCES contacts (id) ON DELETE SET NULL
);

CREATE TABLE protocol_adapter_state (
    contact_id TEXT PRIMARY KEY REFERENCES contacts (id) ON DELETE CASCADE,
    state_blob BLOB NOT NULL,
    updated_at_unix_ms INTEGER NOT NULL
);

CREATE TABLE conversations (
    id TEXT PRIMARY KEY,
    contact_id TEXT REFERENCES contacts (id) ON DELETE SET NULL,
    local_alias TEXT NOT NULL,
    created_at_unix_ms INTEGER NOT NULL,
    destroyed_at_unix_ms INTEGER
);

CREATE TABLE messages (
    id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL REFERENCES conversations (id) ON DELETE CASCADE,
    direction TEXT NOT NULL CHECK (direction IN ('outgoing', 'incoming')),
    ciphertext BLOB NOT NULL,
    sent_at_unix_ms INTEGER,
    received_at_unix_ms INTEGER,
    delivery_state TEXT NOT NULL DEFAULT 'pending'
        CHECK (delivery_state IN ('pending', 'sent', 'delivered', 'failed'))
);

CREATE INDEX messages_conversation_id_idx ON messages (conversation_id);

CREATE TABLE drafts (
    conversation_id TEXT PRIMARY KEY REFERENCES conversations (id) ON DELETE CASCADE,
    content BLOB NOT NULL,
    updated_at_unix_ms INTEGER NOT NULL
);

CREATE TABLE attachments (
    id TEXT PRIMARY KEY,
    message_id TEXT NOT NULL REFERENCES messages (id) ON DELETE CASCADE,
    object_name TEXT NOT NULL,
    content_type TEXT,
    expected_size_bytes INTEGER,
    attachment_key BLOB NOT NULL,
    created_at_unix_ms INTEGER NOT NULL
);

CREATE TABLE app_config (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
);

CREATE TABLE destruction_tombstones (
    id TEXT PRIMARY KEY,
    scope TEXT NOT NULL CHECK (scope IN ('conversation', 'identity')),
    target_id TEXT,
    stage TEXT NOT NULL,
    created_at_unix_ms INTEGER NOT NULL,
    updated_at_unix_ms INTEGER NOT NULL
);
