-- Readback metadata only: no snapshots, keys, addresses, endpoints or credential digests.
CREATE TABLE profile_observations (
 id TEXT PRIMARY KEY CHECK(length(id)=32),
 profile_id TEXT NOT NULL REFERENCES profiles(id),
 owner_id TEXT NOT NULL REFERENCES users(id),
 generation INTEGER NOT NULL CHECK(generation>0),
 device_revision INTEGER NOT NULL CHECK(device_revision>0),
 source TEXT NOT NULL CHECK(source IN ('awg-runtime','awg-snapshot')),
 peer_matches INTEGER NOT NULL CHECK(peer_matches IN (0,1)),
 mismatched_fields TEXT NOT NULL CHECK(json_valid(mismatched_fields)),
 measured_at TEXT NOT NULL, expires_at TEXT NOT NULL
);
CREATE INDEX profile_observations_target ON profile_observations(profile_id,measured_at);
