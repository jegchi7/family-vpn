-- Idempotency is scoped to the owner and retained even after cancellation.
ALTER TABLE devices ADD COLUMN creation_key TEXT;
ALTER TABLE devices ADD COLUMN creation_hash BLOB CHECK(creation_hash IS NULL OR length(creation_hash)=32);
CREATE UNIQUE INDEX device_creation_owner_key ON devices(user_id,creation_key) WHERE creation_key IS NOT NULL;
CREATE INDEX device_owner_state ON devices(user_id,state);
