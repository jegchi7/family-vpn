-- Metadata only. No private keys, enrollment tokens or connection passwords.
CREATE TABLE gateway_peers (
 node_id TEXT PRIMARY KEY REFERENCES nodes(id), pinned_identity TEXT NOT NULL,
 pairing_state TEXT NOT NULL CHECK(pairing_state IN ('pending','paired','revoked')),
 trust_epoch INTEGER NOT NULL CHECK(trust_epoch>=1), capabilities_json TEXT NOT NULL CHECK(json_valid(capabilities_json)),
 created_at TEXT NOT NULL, revoked_at TEXT
);
CREATE TABLE gateway_sync (
 node_id TEXT PRIMARY KEY REFERENCES gateway_peers(node_id),
 desired_revision INTEGER NOT NULL DEFAULT 0 CHECK(desired_revision>=0),
 observed_revision INTEGER NOT NULL DEFAULT 0 CHECK(observed_revision>=0),
 descriptor_hash TEXT, last_checked_at TEXT, last_error_code TEXT,
 CHECK(observed_revision<=desired_revision)
);
