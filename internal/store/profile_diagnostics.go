package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"familyvpn.local/platform/internal/clientconfig"
	"familyvpn.local/platform/internal/domain"
	"familyvpn.local/platform/internal/profileobserve"
	"time"
)

type diagnosticBinding struct {
	owner, device, profile, protocol, format, deviceState, profileState string
	generation, revision                                                int
	stored                                                              bool
}

// This projection reads only existing portal metadata. It is intentionally
// separate from the trusted CLI readiness report and has no key/core/control
// access or permission outcome. All callers use their current read snapshot.
func profileDiagnosticsTx(ctx context.Context, tx *sql.Tx, b diagnosticBinding, now time.Time) (*domain.ProfileDiagnostics, error) {
	d := &domain.ProfileDiagnostics{Connection: "unknown", Configuration: "unchecked", Source: "none", ClientVerification: "unchecked"}
	if b.stored {
		d.Configuration = "stored"
	}
	if !b.stored || b.protocol != "awg" || b.format != clientconfig.AWG31Conf {
		return d, nil
	}
	// The latest owner-bound row wins even when stale, conflicting or expired.
	// Fractional-second normalization prevents 00Z hiding the later 00.1Z.
	const sortTime = "(substr(o.measured_at,1,19)||'.'||substr(CASE WHEN substr(o.measured_at,20,1)='.' THEN substr(o.measured_at,21,length(o.measured_at)-21) ELSE '' END||'000000000',1,9)||'Z')"
	// SQLite accepts normalized calendar dates and non-canonical fractional
	// spellings that Go rejects. Rank every such row before positive history:
	// its temporal ordering cannot justify falling back to an older match.
	// Checking the first 19 characters independently avoids SQLite's fractional
	// rounding when validating the calendar and whole-second UTC spelling.
	canonicalTime := func(column string) string {
		calendar := "strftime('%Y-%m-%dT%H:%M:%S',julianday(substr(" + column + ",1,19)||'Z'))"
		return "(length(" + column + ") BETWEEN 20 AND 30 AND substr(" + column + ",-1)='Z' AND " + calendar + " IS NOT NULL AND " + calendar + "=substr(" + column + ",1,19) AND (length(" + column + ")=20 OR (length(" + column + ") BETWEEN 22 AND 30 AND substr(" + column + ",20,1)='.' AND substr(" + column + ",21,length(" + column + ")-21) NOT GLOB '*[^0-9]*' AND substr(" + column + ",-2,1)!='0')))"
	}
	invalidTime := "CASE WHEN " + canonicalTime("o.measured_at") + " AND " + canonicalTime("o.expires_at") + " THEN 0 ELSE 1 END"
	var id, source, fields, measured, expires, ownerState, ownerRole string
	var generation, revision int
	var matched bool
	err := tx.QueryRowContext(ctx, `SELECT o.id,o.source,o.generation,o.device_revision,o.peer_matches,o.mismatched_fields,o.measured_at,o.expires_at,u.state,u.role
 FROM profile_observations o JOIN users u ON u.id=o.owner_id
 JOIN profiles p ON p.id=o.profile_id JOIN devices device ON device.id=p.device_id
 WHERE o.profile_id=? AND o.owner_id=? AND device.id=? AND device.user_id=?
 ORDER BY `+invalidTime+` DESC,`+sortTime+` DESC,o.id DESC LIMIT 1`, b.profile, b.owner, b.device, b.owner).Scan(&id, &source, &generation, &revision, &matched, &fields, &measured, &expires, &ownerState, &ownerRole)
	if errors.Is(err, sql.ErrNoRows) {
		return d, nil
	}
	if err != nil {
		return nil, err
	}
	// Corrupt/unrecognized metadata cannot become a positive badge or leak raw
	// values. Do not fall back to any older matching observation.
	decodedID, err := hex.DecodeString(id)
	if err != nil || len(decodedID) != 16 || hex.EncodeToString(decodedID) != id || source != "awg-runtime" && source != "awg-snapshot" {
		return d, nil
	}
	at, err := time.Parse(time.RFC3339Nano, measured)
	if err != nil || stamp(at) != measured {
		return d, nil
	}
	until, err := time.Parse(time.RFC3339Nano, expires)
	if err != nil || stamp(until) != expires || !until.Equal(at.Add(profileobserve.TTL)) {
		return d, nil
	}
	if _, err = observationFields(fields, matched); err != nil {
		return d, nil
	}
	d.Source = "snapshot"
	if source == "awg-runtime" {
		d.Source = "native_readback"
	}
	d.CheckedAt, d.ExpiresAt = measured, expires
	switch {
	case generation != b.generation || revision != b.revision || ownerState != "active" || ownerRole != "user" || b.deviceState != "pending" || b.profileState != "pending" || now.Before(at):
		d.Configuration = "stale"
	case !now.Before(until):
		d.Configuration = "expired"
	case !matched:
		d.Configuration = "conflict"
	default:
		d.Configuration = "matched"
	}
	return d, nil
}
