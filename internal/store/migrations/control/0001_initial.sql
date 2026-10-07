CREATE TABLE nodes (
 id TEXT PRIMARY KEY, role TEXT NOT NULL CHECK(role IN ('ru','foreign')), endpoint_ref TEXT,
 capabilities_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(capabilities_json)), last_seen_at TEXT
);
CREATE TABLE revisions (
 id TEXT PRIMARY KEY, parent_id TEXT REFERENCES revisions(id), schema_version INTEGER NOT NULL CHECK(schema_version>=1),
 adapter_versions_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(adapter_versions_json)),
 desired_hash TEXT NOT NULL, applied_hash TEXT, state TEXT NOT NULL CHECK(state IN ('prepared','applying','applied','failed','superseded')),
 created_at TEXT NOT NULL, applied_at TEXT
);
CREATE TABLE operations (
 id TEXT PRIMARY KEY, actor_id TEXT NOT NULL, type TEXT NOT NULL, target_id TEXT NOT NULL,
 idempotency_key TEXT NOT NULL, request_hash TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('queued','running','reconciling','succeeded','failed','partial','cancelled')),
 attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0), lease_until TEXT,
 expected_revision TEXT REFERENCES revisions(id), result_code TEXT, created_at TEXT NOT NULL, finished_at TEXT,
 UNIQUE(actor_id,idempotency_key)
);
CREATE TABLE revocations (
 profile_id TEXT NOT NULL, generation INTEGER NOT NULL CHECK(generation>=1), revoked_at TEXT NOT NULL, reason TEXT NOT NULL,
 PRIMARY KEY(profile_id,generation)
);
CREATE TRIGGER revocations_no_delete BEFORE DELETE ON revocations BEGIN SELECT RAISE(ABORT,'revocations are append-only'); END;
CREATE TRIGGER revocations_no_update BEFORE UPDATE ON revocations BEGIN SELECT RAISE(ABORT,'revocations are append-only'); END;
CREATE TABLE audit_events (
 id TEXT PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL, object_ref TEXT NOT NULL,
 outcome TEXT NOT NULL, request_id TEXT, operation_id TEXT, time TEXT NOT NULL
);
CREATE TABLE app_metadata (key TEXT PRIMARY KEY,value TEXT NOT NULL);
