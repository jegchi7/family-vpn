ALTER TABLE intent_queue ADD COLUMN next_attempt_at INTEGER NOT NULL DEFAULT 0 CHECK(next_attempt_at>=0);
ALTER TABLE intent_queue ADD COLUMN consecutive_failures INTEGER NOT NULL DEFAULT 0 CHECK(consecutive_failures BETWEEN 0 AND 30);
ALTER TABLE intent_queue ADD COLUMN last_error_code TEXT NOT NULL DEFAULT '' CHECK(last_error_code IN ('','agent_unavailable','observation_unconfirmed'));
