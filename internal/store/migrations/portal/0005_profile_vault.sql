-- Only key identifiers are persisted. Keys remain outside the state/backup root.
CREATE TABLE profile_vault_state (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 active_key_id TEXT NOT NULL CHECK(length(active_key_id)=64),
 revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>=1)
);
-- A nonce collision fails the whole transaction; it never overwrites a record.
CREATE UNIQUE INDEX profile_nonce_unique ON profiles(key_id,nonce) WHERE ciphertext IS NOT NULL;
