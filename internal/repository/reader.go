package repository

import (
	"context"
	"familyvpn.local/platform/internal/domain"
)

// Reader is a portal-safe boundary. It cannot execute control commands or read keys.
type Reader interface {
	DevicesForOwner(context.Context, string) ([]domain.Device, error)
	ProfileForOwner(context.Context, string, string) (domain.Profile, bool, error)
	HealthSamples(context.Context) ([]domain.Health, error)
	Instructions(context.Context) ([]domain.Instruction, error)
	DeviceCount(context.Context) (int, error)
	Ping(context.Context) error
	Backend() string
}

// DeviceWriter is local user intent only: no keys, IP allocation or agent commands.
type DeviceWriter interface {
	DeviceQuota(context.Context, string) (domain.DeviceQuota, error)
	RequestDevice(context.Context, string, domain.DeviceRequest) (domain.Device, error)
	RenameDevice(context.Context, string, string, string, int) (domain.Device, error)
	CancelDeviceRequest(context.Context, string, string, int) (domain.Device, error)
}

// AdminReader is wired only to authenticated management HTTP. No credential,
// ciphertext, key, token, server snapshot or network mutation methods.
type AdminReader interface {
	AdminUsers(context.Context, domain.PageRequest) (domain.Page[domain.AdminUser], error)
	AdminDevices(context.Context, domain.PageRequest, string) (domain.Page[domain.AdminDevice], error)
	AdminAudit(context.Context, domain.PageRequest) (domain.Page[domain.AdminAuditEvent], error)
}
