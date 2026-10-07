-- Only the synthetic local stand uses these runtime tables. No VPN credentials.
CREATE TABLE intent_nodes (
 node_id TEXT PRIMARY KEY REFERENCES nodes(id), revision INTEGER NOT NULL DEFAULT 0 CHECK(revision>=0)
);
CREATE TABLE intent_queue (
 operation_id TEXT PRIMARY KEY REFERENCES operations(id), node_id TEXT NOT NULL REFERENCES intent_nodes(node_id),
 envelope_json TEXT NOT NULL CHECK(json_valid(envelope_json)), expected_sequence INTEGER NOT NULL CHECK(expected_sequence>=0),
 priority INTEGER NOT NULL CHECK(priority IN (0,1)), lease_deadline INTEGER, checkpoint TEXT NOT NULL DEFAULT 'intent' CHECK(checkpoint IN ('intent','before_apply','observed')),
 sequence INTEGER NOT NULL UNIQUE, CHECK(sequence>0)
);
CREATE INDEX intent_queue_order ON intent_queue(node_id,priority DESC,sequence);
CREATE TABLE fake_peers (
 node_id TEXT NOT NULL REFERENCES intent_nodes(node_id), profile_id TEXT NOT NULL, generation INTEGER NOT NULL,
 active INTEGER NOT NULL CHECK(active IN (0,1)), PRIMARY KEY(node_id,profile_id,generation)
);
CREATE TABLE fake_applied (
 operation_id TEXT PRIMARY KEY REFERENCES operations(id), node_id TEXT NOT NULL REFERENCES intent_nodes(node_id),
 request_hash TEXT NOT NULL, observed_revision INTEGER NOT NULL CHECK(observed_revision>=0), result_code TEXT NOT NULL CHECK(result_code IN ('applied','revoked','revision_conflict'))
);
CREATE TABLE intent_revocations (
 node_id TEXT NOT NULL REFERENCES intent_nodes(node_id), profile_id TEXT NOT NULL, generation INTEGER NOT NULL,
 PRIMARY KEY(node_id,profile_id,generation)
);
CREATE TRIGGER intent_revocations_no_delete BEFORE DELETE ON intent_revocations BEGIN SELECT RAISE(ABORT,'revocations are append-only'); END;
CREATE TRIGGER intent_revocations_no_update BEFORE UPDATE ON intent_revocations BEGIN SELECT RAISE(ABORT,'revocations are append-only'); END;
