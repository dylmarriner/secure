-- Schema version 4: durable queue of encrypted attachment objects awaiting deletion.
--
-- Burn Conversation destroys attachment keys and then deletes the attachment rows, which would
-- lose the only record of which on-disk ciphertext objects belonged to the burned conversation.
-- The key-destruction stage therefore copies each object name here in the same transaction, and
-- the layer that owns the attachment directory deletes the objects afterwards and removes each
-- name once its file is gone. A crash between key destruction and object deletion leaves the
-- names here, so cleanup resumes on the next unlock (docs/security-remediation-plan.md R6).
--
-- Holds opaque random object names only: no conversation, message or content metadata.

CREATE TABLE pending_object_deletions (
    object_name TEXT PRIMARY KEY
);
