-- Separate administrative invalidation from successful token consumption.
ALTER TABLE one_time_tokens ADD COLUMN revoked_at TEXT;
CREATE INDEX one_time_token_status ON one_time_tokens(user_id,purpose,consumed_at,revoked_at);
