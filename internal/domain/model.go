package domain

import "time"

type Profile struct {
	ID          string              `json:"id"`
	Protocol    string              `json:"protocol"`
	State       string              `json:"state"`
	Format      string              `json:"format"`
	Diagnostics *ProfileDiagnostics `json:"diagnostics,omitempty"`
}

// ProfileDiagnostics is a read-only display projection. A configuration match
// never attests a current VPN session, client acceptance or profile readiness.
type ProfileDiagnostics struct {
	Connection         string `json:"connection"`
	Configuration      string `json:"configuration"`
	Source             string `json:"source"`
	CheckedAt          string `json:"checkedAt,omitempty"`
	ExpiresAt          string `json:"expiresAt,omitempty"`
	ClientVerification string `json:"clientVerification"`
}
type Device struct {
	ID       string    `json:"id"`
	OwnerID  string    `json:"-"`
	Name     string    `json:"name"`
	OS       string    `json:"os"`
	State    string    `json:"state"`
	Profiles []Profile `json:"profiles"`
	Revision int       `json:"revision"`
}
type Health struct {
	Component  string    `json:"component"`
	Status     string    `json:"status"`
	Reason     string    `json:"reason"`
	MeasuredAt time.Time `json:"measured_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func (h Health) At(now time.Time) Health {
	if !now.Before(h.ExpiresAt) {
		h.Status = "unknown"
		h.Reason = "Данные устарели; новое измерение не получено"
	}
	return h
}

type Instruction struct {
	ID                string   `json:"id"`
	OS                string   `json:"os"`
	Title             string   `json:"title"`
	Verified          bool     `json:"verified"`
	Steps             []string `json:"steps"`
	Kind              string   `json:"kind,omitempty"`
	ContentVersion    int      `json:"content_version,omitempty"`
	VerifiedAt        string   `json:"verified_at,omitempty"`
	VerificationScope string   `json:"verification_scope,omitempty"`
	AppID             string   `json:"app_id,omitempty"`
	AppVersion        string   `json:"app_version,omitempty"`
	Protocol          string   `json:"protocol,omitempty"`
	Format            string   `json:"format,omitempty"`
	OfflineAvailable  bool     `json:"offline_available"`
}
