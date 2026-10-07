CREATE TABLE admin_accounts (
 id TEXT PRIMARY KEY, login TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL,
 password_hash TEXT NOT NULL, encrypted_secret BLOB NOT NULL, key_id TEXT NOT NULL,
 last_step INTEGER NOT NULL DEFAULT -1, revision INTEGER NOT NULL DEFAULT 1,
 state TEXT NOT NULL CHECK(state IN ('pending','active','disabled')),
 enrollment_expires TEXT NOT NULL
);
CREATE TABLE admin_challenges (
 token_hash BLOB PRIMARY KEY CHECK(length(token_hash)=32),
 binding_hash BLOB NOT NULL CHECK(length(binding_hash)=32),
 user_id TEXT NOT NULL UNIQUE REFERENCES admin_accounts(id), revision INTEGER NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 5), expires_at TEXT NOT NULL
);
CREATE TABLE sessions (
 token_hash BLOB PRIMARY KEY CHECK(length(token_hash)=32), user_id TEXT NOT NULL REFERENCES admin_accounts(id),
 created_at TEXT NOT NULL,last_seen_at TEXT NOT NULL,expires_at TEXT NOT NULL,auth_time TEXT NOT NULL,revoked_at TEXT
);
CREATE TABLE auth_rate_limits(scope_hash BLOB PRIMARY KEY CHECK(length(scope_hash)=32),window_start INTEGER NOT NULL,attempts INTEGER NOT NULL);
CREATE TABLE audit_events(id TEXT PRIMARY KEY,actor TEXT NOT NULL,action TEXT NOT NULL,object_ref TEXT NOT NULL,outcome TEXT NOT NULL,time TEXT NOT NULL);
CREATE INDEX admin_session_user ON sessions(user_id);
