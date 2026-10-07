CREATE UNIQUE INDEX one_password_per_user ON credentials(user_id) WHERE kind='password';
CREATE TABLE auth_rate_limits (
 scope_hash BLOB PRIMARY KEY CHECK(length(scope_hash)=32),
 window_start INTEGER NOT NULL, attempts INTEGER NOT NULL CHECK(attempts>=0)
);
CREATE INDEX auth_rate_expiry ON auth_rate_limits(window_start);
CREATE INDEX session_user ON sessions(user_id);
CREATE INDEX tokens_user ON one_time_tokens(user_id,purpose);
