-- Schema version 3: correlate inbound protocol chat events with local contacts.
--
-- Adapters (e.g. `secure-messaging`'s SimpleX event parser) address contacts by the
-- protocol's own integer id, not this vault's random-hex contact ids. `external_id` is that
-- protocol-assigned id, kept unique per contact so a delivered event can be resolved to (or
-- used to create) exactly one local contact/conversation without guessing.

ALTER TABLE contacts ADD COLUMN external_id INTEGER;

CREATE UNIQUE INDEX contacts_external_id_idx ON contacts (external_id)
    WHERE external_id IS NOT NULL;
