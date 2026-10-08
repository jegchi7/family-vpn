package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/clientconfig"
	"familyvpn.local/platform/internal/domain"
	"familyvpn.local/platform/internal/profileobserve"
	"familyvpn.local/platform/internal/profilevault"
	"strings"
	"testing"
)

func awgSessionTarget() profileobserve.Target {
	return profileobserve.Target{Interface: "inventory_awg", Endpoint: "edge.example.invalid:443", ToolSHA256: strings.Repeat("a", 64), BootID: "11111111-2222-3333-4444-555555555555", NetNSDevice: 4, NetNSInode: 12345}
}

func awgSessionStoreFixture(t *testing.T) (*PortalStore, *profilevault.Vault, profilevault.Context, []byte, string) {
	t.Helper()
	p, s, _, path := authStore(t)
	u, _ := enroll(t, s, "alice")
	v := profileTestKey(t)
	if e := p.InitializeProfileVault(ctx, v); e != nil {
		t.Fatal(e)
	}
	d, e := p.RequestDevice(ctx, u.ID, deviceInput())
	if e != nil {
		t.Fatal(e)
	}
	c := awgImportContext(u.ID, d)
	client := awgImportPayload(t)
	if _, e = p.ImportClientProfile(ctx, v, c, 1, client, true); e != nil {
		t.Fatal(e)
	}
	return p, v, c, client, path
}

type awgSessionDBState struct {
	audit, observations, revision, generation int
	device, profile, format, keyID            string
	installed                                 sql.NullString
	ciphertext, nonce                         [32]byte
}

func awgSessionState(t *testing.T, p *PortalStore, id string) awgSessionDBState {
	t.Helper()
	var state awgSessionDBState
	if e := p.db.QueryRow("SELECT count(*) FROM audit_events").Scan(&state.audit); e != nil {
		t.Fatal(e)
	}
	if e := p.db.QueryRow("SELECT count(*) FROM profile_observations").Scan(&state.observations); e != nil {
		t.Fatal(e)
	}
	var cipher, nonce []byte
	if e := p.db.QueryRow(`SELECT d.revision,d.generation,d.state,p.state,p.format,p.installed_revision,p.key_id,p.ciphertext,p.nonce FROM profiles p JOIN devices d ON d.id=p.device_id WHERE p.id=?`, id).Scan(&state.revision, &state.generation, &state.device, &state.profile, &state.format, &state.installed, &state.keyID, &cipher, &nonce); e != nil {
		t.Fatal(e)
	}
	state.ciphertext = sha256.Sum256(cipher)
	state.nonce = sha256.Sum256(nonce)
	clear(cipher)
	clear(nonce)
	return state
}

func TestPendingAWGSessionRejectsZeroResultReadOnly(t *testing.T) {
	p, v, c, _, path := awgSessionStoreFixture(t)
	ro, e := OpenPortal(ctx, path, true)
	if e != nil {
		t.Fatal(e)
	}
	defer ro.Close()
	before := awgSessionState(t, p, c.ProfileID)
	summary, e := ro.CheckPendingAWGSession(ctx, v, c, 2, awgSessionTarget(), profileobserve.SessionResult{})
	if !errors.Is(e, profileobserve.ErrStale) || summary.Ready || summary.ClientsVerified || summary.CoreIdentityVerified || summary.RevisionVerified || summary.DNSRoutingVerified {
		t.Fatal("zero session result acquired authority")
	}
	if after := awgSessionState(t, p, c.ProfileID); before != after {
		t.Fatal("session diagnostics mutated state, ciphertext or audit/ledger")
	}
	if _, e = p.ReadReadyProfileSecret(ctx, v, c.OwnerID, c.ProfileID); !errors.Is(e, domain.ErrDeviceState) {
		t.Fatal("zero session result allowed download")
	}
	var restored profileobserve.SessionResult
	if e = json.Unmarshal([]byte(`{"source":"awg-session-runtime","ready":true,"clients_verified":true}`), &restored); e == nil {
		t.Fatal("JSON restored session authority")
	}
	if _, e = ro.CheckPendingAWGSession(ctx, v, c, 2, awgSessionTarget(), restored); !errors.Is(e, profileobserve.ErrStale) {
		t.Fatal("JSON produced an accepted session result")
	}
}

func TestPendingAWGSessionRechecksCurrentStorageGuards(t *testing.T) {
	for _, kind := range []string{"foreign_owner", "foreign_device", "foreign_profile", "revision", "generation", "current_generation", "disabled", "device_revoked", "profile_revoked", "installed_empty", "installed", "corrupt", "invalid_format", "key", "rotation", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			p, v, c, client, path := awgSessionStoreFixture(t)
			binding, key, revision := c, v, 2
			want := ErrConflict
			var e error
			switch kind {
			case "foreign_owner":
				binding.OwnerID = "foreign"
				want = ErrNotFound
			case "foreign_device":
				binding.DeviceID = "foreign"
				want = ErrNotFound
			case "foreign_profile":
				binding.ProfileID = "foreign"
				want = ErrNotFound
			case "revision":
				_, e = p.RenameDevice(ctx, c.OwnerID, c.DeviceID, "Renamed", 2)
			case "generation":
				binding.Generation++
				want = ErrNotFound
			case "current_generation":
				_, e = p.db.Exec("UPDATE devices SET generation=generation+1 WHERE id=?", c.DeviceID)
			case "disabled":
				_, e = p.db.Exec("UPDATE users SET state='disabled' WHERE id=?", c.OwnerID)
				want = ErrNotFound
			case "device_revoked":
				_, e = p.db.Exec("UPDATE devices SET state='revoked' WHERE id=?", c.DeviceID)
				want = domain.ErrDeviceState
			case "profile_revoked":
				_, e = p.db.Exec("UPDATE profiles SET state='revoked' WHERE id=?", c.ProfileID)
				want = domain.ErrDeviceState
			case "installed_empty":
				_, e = p.db.Exec("UPDATE profiles SET installed_revision='' WHERE id=?", c.ProfileID)
				want = domain.ErrDeviceState
			case "installed":
				_, e = p.db.Exec("UPDATE profiles SET installed_revision='unexpected' WHERE id=?", c.ProfileID)
				want = domain.ErrDeviceState
			case "corrupt":
				_, e = p.db.Exec("UPDATE profiles SET ciphertext=zeroblob(length(ciphertext)) WHERE id=?", c.ProfileID)
				want = profilevault.ErrEnvelope
			case "invalid_format":
				changed := append(append([]byte{}, client...), []byte("\nUnknown = rejected\n")...)
				replaceReadinessSecret(t, p, v, c, changed)
				clear(changed)
				want = clientconfig.ErrInvalid
			case "key":
				key = profileTestKey(t)
				want = profilevault.ErrKey
			case "rotation":
				_, e = p.RotateProfileVault(ctx, v, profileTestKey(t))
				want = profilevault.ErrKey
			case "duplicate":
				d, err := p.RequestDevice(ctx, c.OwnerID, deviceInput())
				if err != nil {
					t.Fatal(err)
				}
				_, e = p.StageProfileSecret(ctx, v, awgImportContext(c.OwnerID, d), 1, client)
				want = ErrClientCredentialConflict
			}
			if e != nil {
				t.Fatal("test storage change failed", e)
			}
			ro, e := OpenPortal(ctx, path, true)
			if e != nil {
				t.Fatal(e)
			}
			defer ro.Close()
			before := awgSessionState(t, p, c.ProfileID)
			summary, e := ro.CheckPendingAWGSession(ctx, key, binding, revision, awgSessionTarget(), profileobserve.SessionResult{})
			if !errors.Is(e, want) || summary.Ready || summary.ClientsVerified {
				t.Fatal("session diagnostics skipped a current storage guard", e)
			}
			if after := awgSessionState(t, p, c.ProfileID); before != after {
				t.Fatal("rejected session diagnostics changed stored state")
			}
		})
	}
}

func TestPendingAWGSessionInvalidBindingAndTargetBeforeDB(t *testing.T) {
	var p *PortalStore
	c := profilevault.Context{OwnerID: "owner", DeviceID: "device", ProfileID: "profile", Generation: 1, Protocol: "awg", Format: clientconfig.AWG31Conf}
	for _, bad := range []profilevault.Context{{}, {OwnerID: "owner", DeviceID: "device", ProfileID: "profile", Generation: 1, Protocol: "reality", Format: clientconfig.VLESSRealityURI}} {
		if _, e := p.CheckPendingAWGSession(ctx, nil, bad, 2, awgSessionTarget(), profileobserve.SessionResult{}); !errors.Is(e, profilevault.ErrInput) {
			t.Fatal("malformed binding accessed DB")
		}
	}
	if _, e := p.CheckPendingAWGSession(ctx, nil, c, 0, awgSessionTarget(), profileobserve.SessionResult{}); !errors.Is(e, profilevault.ErrInput) {
		t.Fatal("malformed revision accessed DB")
	}
	if _, e := p.CheckPendingAWGSession(ctx, nil, c, 2, profileobserve.Target{}, profileobserve.SessionResult{}); !errors.Is(e, profileobserve.ErrTarget) {
		t.Fatal("missing independent runtime target accessed DB")
	}
}
