package domain

type PageRequest struct {
	Limit int
	After string
}
type Page[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"next_cursor"`
}
type AdminUser struct {
	ID              string `json:"id"`
	Login           string `json:"login"`
	DisplayName     string `json:"display_name"`
	State           string `json:"state"`
	DeviceLimit     int    `json:"device_limit"`
	UsedSlots       int    `json:"used_slots"`
	Invitation      string `json:"invitation"`
	RecoveryPending bool   `json:"recovery_pending"`
}
type AdminProfile struct {
	ID          string              `json:"id"`
	Protocol    string              `json:"protocol"`
	State       string              `json:"state"`
	Format      string              `json:"format"`
	Stored      bool                `json:"stored"`
	Diagnostics *ProfileDiagnostics `json:"diagnostics,omitempty"`
}
type AdminDevice struct {
	ID         string         `json:"id"`
	OwnerID    string         `json:"owner_id"`
	OwnerLogin string         `json:"owner_login"`
	Name       string         `json:"name"`
	OS         string         `json:"os"`
	State      string         `json:"state"`
	Revision   int            `json:"revision"`
	Generation int            `json:"generation"`
	Profiles   []AdminProfile `json:"profiles"`
}
type AdminAuditEvent struct {
	ID        string `json:"id"`
	Action    string `json:"action"`
	ActorKind string `json:"actor_kind"`
	ObjectID  string `json:"object_id"`
	Outcome   string `json:"outcome"`
	Time      string `json:"time"`
}
