CREATE TABLE users (
 id TEXT PRIMARY KEY, login TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('user','admin')), state TEXT NOT NULL CHECK(state IN ('invited','active','disabled')),
 device_limit INTEGER NOT NULL DEFAULT 5 CHECK(device_limit>=0), created_at TEXT NOT NULL
);
CREATE TABLE credentials (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
 kind TEXT NOT NULL CHECK(kind IN ('password','passkey','totp')), credential_id TEXT UNIQUE,
 password_hash TEXT, public_key BLOB, encrypted_secret BLOB, key_id TEXT,
 sign_count INTEGER NOT NULL DEFAULT 0 CHECK(sign_count>=0), created_at TEXT NOT NULL
);
CREATE TABLE sessions (
 token_hash BLOB PRIMARY KEY CHECK(length(token_hash)=32), user_id TEXT NOT NULL REFERENCES users(id),
 created_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, expires_at TEXT NOT NULL, auth_time TEXT NOT NULL, revoked_at TEXT
);
CREATE TABLE one_time_tokens (
 token_hash BLOB PRIMARY KEY CHECK(length(token_hash)=32), user_id TEXT NOT NULL REFERENCES users(id),
 purpose TEXT NOT NULL CHECK(purpose IN ('invite','recovery','recovery_code')),
 expires_at TEXT NOT NULL, consumed_at TEXT
);
CREATE TABLE devices (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 64),
 os TEXT NOT NULL CHECK(os IN ('ios','android','windows','macos','linux','other')),
 selected_app TEXT NOT NULL DEFAULT '', state TEXT NOT NULL CHECK(state IN ('pending','active','partial','revoking','revoked','error')),
 generation INTEGER NOT NULL DEFAULT 1 CHECK(generation>=1), revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>=1),
 created_at TEXT NOT NULL, revoked_at TEXT
);
CREATE INDEX devices_owner ON devices(user_id,id);
CREATE TABLE profiles (
 id TEXT PRIMARY KEY, device_id TEXT NOT NULL REFERENCES devices(id),
 protocol TEXT NOT NULL CHECK(protocol IN ('awg','reality')), generation INTEGER NOT NULL CHECK(generation>=1),
 state TEXT NOT NULL CHECK(state IN ('pending','ready','revoking','revoked','error')), format TEXT NOT NULL,
 allocated_ip TEXT UNIQUE, ciphertext BLOB, nonce BLOB, key_id TEXT, installed_revision TEXT,
 UNIQUE(device_id,protocol,generation),
 CHECK((ciphertext IS NULL AND nonce IS NULL AND key_id IS NULL) OR (ciphertext IS NOT NULL AND nonce IS NOT NULL AND key_id IS NOT NULL))
);
CREATE TABLE subscription_tokens (
 id TEXT PRIMARY KEY, device_id TEXT NOT NULL REFERENCES devices(id), token_hash BLOB NOT NULL UNIQUE CHECK(length(token_hash)=32),
 format TEXT NOT NULL, expires_at TEXT, revoked_at TEXT
);
CREATE TABLE instructions (
 id TEXT PRIMARY KEY, os TEXT NOT NULL, app_id TEXT NOT NULL DEFAULT '', version_range TEXT NOT NULL DEFAULT '',
 protocol TEXT NOT NULL DEFAULT '', format TEXT NOT NULL DEFAULT '', content_version INTEGER NOT NULL CHECK(content_version>=1),
 title TEXT NOT NULL, verified_at TEXT, steps_json TEXT NOT NULL CHECK(json_valid(steps_json))
);
CREATE TABLE health_samples (
 id INTEGER PRIMARY KEY, component TEXT NOT NULL, path_id TEXT NOT NULL DEFAULT '', check_type TEXT NOT NULL DEFAULT 'demo',
 status TEXT NOT NULL CHECK(status IN ('healthy','degraded','unavailable','unknown')), reason TEXT NOT NULL,
 measured_at TEXT NOT NULL, expires_at TEXT NOT NULL, latency_ms INTEGER, reason_code TEXT NOT NULL DEFAULT ''
);
CREATE TABLE public_operations (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), target_id TEXT NOT NULL,
 state TEXT NOT NULL, result_code TEXT, measured_at TEXT NOT NULL
);
CREATE TABLE audit_events (
 id TEXT PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL, object_ref TEXT NOT NULL,
 outcome TEXT NOT NULL, request_id TEXT, operation_id TEXT, time TEXT NOT NULL
);
CREATE TABLE app_metadata (key TEXT PRIMARY KEY,value TEXT NOT NULL);
