package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"familyvpn.local/platform/internal/auth"
	"familyvpn.local/platform/internal/domain"
	"time"
)

func validPage(p domain.PageRequest, audit bool) bool {
	if p.Limit < 1 || p.Limit > 100 || len(p.After) > 256 {
		return false
	}
	return p.After == "" || audit || auth.ValidToken(p.After)
}
func (p *PortalStore) AdminUsers(ctx context.Context, request domain.PageRequest) (domain.Page[domain.AdminUser], error) {
	return p.adminUsersAt(ctx, request, time.Now())
}
func (p *PortalStore) adminUsersAt(ctx context.Context, request domain.PageRequest, at time.Time) (domain.Page[domain.AdminUser], error) {
	out := domain.Page[domain.AdminUser]{Items: []domain.AdminUser{}}
	if !validPage(request, false) {
		return out, auth.ErrInput
	}
	if e := p.AssertLocalAuth(ctx); e != nil {
		return out, e
	}
	now := stamp(at)
	// Revoked tokens do not represent available, expired or consumed invitations.
	// Match the time comparison used by invitation/recovery consumption.
	rows, e := p.db.QueryContext(ctx, `SELECT u.id,u.login,u.display_name,u.state,u.device_limit,
 (SELECT count(*) FROM devices d WHERE d.user_id=u.id AND d.state!='revoked'),
 CASE WHEN EXISTS(SELECT 1 FROM one_time_tokens t WHERE t.user_id=u.id AND t.purpose='invite' AND t.consumed_at IS NULL AND t.revoked_at IS NULL AND julianday(t.expires_at)>julianday(?)) THEN 'available'
 WHEN EXISTS(SELECT 1 FROM one_time_tokens t WHERE t.user_id=u.id AND t.purpose='invite' AND t.consumed_at IS NULL AND t.revoked_at IS NULL) THEN 'expired'
 WHEN EXISTS(SELECT 1 FROM one_time_tokens t WHERE t.user_id=u.id AND t.purpose='invite' AND t.consumed_at IS NOT NULL AND t.revoked_at IS NULL) THEN 'used' ELSE 'none' END,
 EXISTS(SELECT 1 FROM one_time_tokens t WHERE t.user_id=u.id AND t.purpose='recovery' AND t.consumed_at IS NULL AND t.revoked_at IS NULL AND julianday(t.expires_at)>julianday(?))
 FROM users u WHERE u.role='user' AND u.id>? ORDER BY u.id LIMIT ?`, now, now, request.After, request.Limit+1)
	if e != nil {
		return out, e
	}
	defer rows.Close()
	for rows.Next() {
		var u domain.AdminUser
		if e = rows.Scan(&u.ID, &u.Login, &u.DisplayName, &u.State, &u.DeviceLimit, &u.UsedSlots, &u.Invitation, &u.RecoveryPending); e != nil {
			return out, e
		}
		out.Items = append(out.Items, u)
	}
	if e = rows.Err(); e != nil {
		return out, e
	}
	if len(out.Items) > request.Limit {
		out.Items = out.Items[:request.Limit]
		out.NextCursor = out.Items[len(out.Items)-1].ID
	}
	return out, nil
}
func (p *PortalStore) AdminDevices(ctx context.Context, request domain.PageRequest, state string) (domain.Page[domain.AdminDevice], error) {
	out := domain.Page[domain.AdminDevice]{Items: []domain.AdminDevice{}}
	if !validPage(request, false) {
		return out, auth.ErrInput
	}
	switch state {
	case "all", "pending", "active", "partial", "revoking", "revoked", "error":
	default:
		return out, auth.ErrInput
	}
	if e := p.AssertLocalAuth(ctx); e != nil {
		return out, e
	}
	tx, e := p.db.BeginTx(ctx, nil)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	rows, e := tx.QueryContext(ctx, `SELECT d.id,d.user_id,u.login,d.name,d.os,d.state,d.revision,d.generation FROM devices d JOIN users u ON u.id=d.user_id WHERE u.role='user' AND d.id>? AND (?='all' OR d.state=?) ORDER BY d.id LIMIT ?`, request.After, state, state, request.Limit+1)
	if e != nil {
		return out, e
	}
	for rows.Next() {
		var d domain.AdminDevice
		if e = rows.Scan(&d.ID, &d.OwnerID, &d.OwnerLogin, &d.Name, &d.OS, &d.State, &d.Revision, &d.Generation); e != nil {
			rows.Close()
			return out, e
		}
		d.Profiles = []domain.AdminProfile{}
		out.Items = append(out.Items, d)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	if len(out.Items) > request.Limit {
		out.Items = out.Items[:request.Limit]
		out.NextCursor = out.Items[len(out.Items)-1].ID
	}
	for i := range out.Items {
		d := &out.Items[i]
		rows, e = tx.QueryContext(ctx, `SELECT id,protocol,state,format,ciphertext IS NOT NULL FROM profiles WHERE device_id=? AND generation=? ORDER BY protocol`, d.ID, d.Generation)
		if e != nil {
			return out, e
		}
		for rows.Next() {
			var profile domain.AdminProfile
			if e = rows.Scan(&profile.ID, &profile.Protocol, &profile.State, &profile.Format, &profile.Stored); e != nil {
				rows.Close()
				return out, e
			}
			d.Profiles = append(d.Profiles, profile)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return out, e
		}
	}
	if e = tx.Commit(); e != nil {
		return domain.Page[domain.AdminDevice]{}, e
	}
	return out, nil
}

type auditCursor struct {
	Time string `json:"time"`
	ID   string `json:"id"`
}

func validAuditTime(s string) bool {
	t, e := time.Parse(time.RFC3339Nano, s)
	return e == nil && stamp(t) == s && len(s) <= 35
}
func decodeAuditCursor(s string) (auditCursor, error) {
	var c auditCursor
	if s == "" {
		return c, nil
	}
	b, e := base64.RawURLEncoding.Strict().DecodeString(s)
	if e != nil {
		return c, auth.ErrInput
	}
	if json.Unmarshal(b, &c) != nil || !auth.ValidToken(c.ID) || !validAuditTime(c.Time) {
		return auditCursor{}, auth.ErrInput
	}
	canonical, _ := json.Marshal(c)
	if base64.RawURLEncoding.EncodeToString(canonical) != s {
		return auditCursor{}, auth.ErrInput
	}
	return c, nil
}
func safeAuditAction(s string) string {
	switch s {
	case "device.request.cancel":
		// Preserve the stored request event while exposing the existing safe API action.
		return "device.cancel"
	case "invite.create", "invite.accept", "invite.reissue", "session.login", "session.logout", "recovery.issue", "recovery.complete", "device.request", "device.rename", "device.cancel", "profile.stage", "profile-vault.initialize", "profile-vault.rotate":
		return s
	}
	return "other"
}
func (p *PortalStore) AdminAudit(ctx context.Context, request domain.PageRequest) (domain.Page[domain.AdminAuditEvent], error) {
	out := domain.Page[domain.AdminAuditEvent]{Items: []domain.AdminAuditEvent{}}
	if !validPage(request, true) {
		return out, auth.ErrInput
	}
	cursor, e := decodeAuditCursor(request.After)
	if e != nil {
		return out, e
	}
	if e = p.AssertLocalAuth(ctx); e != nil {
		return out, e
	}
	// Normalize fractional seconds before sorting: RFC3339Nano without a
	// fraction ends in Z and otherwise sorts ahead of later fractional times.
	const sortTime = "(substr(a.time,1,19)||'.'||substr(CASE WHEN substr(a.time,20,1)='.' THEN substr(a.time,21,length(a.time)-21) ELSE '' END||'000000000',1,9)||'Z')"
	cursorTime := ""
	if cursor.Time != "" {
		parsed, _ := time.Parse(time.RFC3339Nano, cursor.Time)
		cursorTime = parsed.UTC().Format("2006-01-02T15:04:05.000000000Z")
	}
	// Never select raw actor, request_id/operation_id or free-text object_ref.
	rows, e := p.db.QueryContext(ctx, `SELECT a.id,a.action,
 CASE WHEN a.actor IN('local-cli','trusted-cli') THEN 'trusted-cli' WHEN EXISTS(SELECT 1 FROM users u WHERE u.id=a.actor) THEN 'user' ELSE 'unknown' END,
 CASE WHEN a.action IN('invite.create','invite.accept','invite.reissue','session.login','session.logout','recovery.issue','recovery.complete') AND EXISTS(SELECT 1 FROM users u WHERE u.id=a.object_ref) THEN a.object_ref
 WHEN a.action IN('device.request','device.rename','device.cancel','device.request.cancel') AND EXISTS(SELECT 1 FROM devices d WHERE d.id=a.object_ref) THEN a.object_ref
 WHEN a.action='profile.stage' AND EXISTS(SELECT 1 FROM profiles p WHERE p.id=a.object_ref) THEN a.object_ref ELSE '' END,
 a.outcome,a.time FROM audit_events a
 WHERE length(a.id)=43 AND a.id NOT GLOB '*[^A-Za-z0-9_-]*' AND (?='' OR `+sortTime+`<? OR (`+sortTime+`=? AND a.id<?))
 ORDER BY `+sortTime+` DESC,a.id DESC LIMIT ?`, cursorTime, cursorTime, cursorTime, cursor.ID, request.Limit+1)
	if e != nil {
		return out, e
	}
	defer rows.Close()
	for rows.Next() {
		var a domain.AdminAuditEvent
		if e = rows.Scan(&a.ID, &a.Action, &a.ActorKind, &a.ObjectID, &a.Outcome, &a.Time); e != nil {
			return out, e
		}
		if !validAuditTime(a.Time) || !auth.ValidToken(a.ID) {
			return out, auth.ErrInput
		}
		a.Action = safeAuditAction(a.Action)
		if !auth.ValidToken(a.ObjectID) {
			a.ObjectID = ""
		}
		switch a.Outcome {
		case "success", "succeeded":
			a.Outcome = "success"
		case "failed", "denied":
			a.Outcome = "failed"
		default:
			a.Outcome = "unknown"
		}
		out.Items = append(out.Items, a)
	}
	if e = rows.Err(); e != nil {
		return out, e
	}
	if len(out.Items) > request.Limit {
		out.Items = out.Items[:request.Limit]
		last := out.Items[len(out.Items)-1]
		b, _ := json.Marshal(auditCursor{last.Time, last.ID})
		out.NextCursor = base64.RawURLEncoding.EncodeToString(b)
	}
	return out, nil
}
