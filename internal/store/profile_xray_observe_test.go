package store

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/domain"
	"familyvpn.local/platform/internal/runtimeenv"
	"familyvpn.local/platform/internal/xrayobserve"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func vlessAliasPayload(t *testing.T, data []byte) []byte {
	t.Helper()
	u, _ := url.Parse(string(bytes.TrimSpace(data)))
	id := u.User.Username()
	b, _ := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
	defer clear(b)
	b[6] ^= 1
	h := hex.EncodeToString(b)
	alias := h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
	out := bytes.Replace(data, []byte(id), []byte(alias), 1)
	t.Cleanup(func() { clear(out) })
	return out
}
func TestXrayUsersReadOnlyRecheckAndPendingGate(t *testing.T) {
	p, s, _, path := authStore(t)
	u, _ := enroll(t, s, "alice")
	v := profileTestKey(t)
	p.InitializeProfileVault(ctx, v)
	d, _ := p.RequestDevice(ctx, u.ID, deviceInput())
	c := importContext(u.ID, d)
	data := importPayload(t)
	if _, e := p.ImportClientProfile(ctx, v, c, 1, data, true); e != nil {
		t.Fatal(e)
	}
	ro, e := OpenPortal(ctx, path, true)
	if e != nil {
		t.Fatal(e)
	}
	defer ro.Close()
	plain, e := ro.LoadPendingXrayUsersObservation(ctx, v, c, 2)
	if e != nil || !bytes.Equal(plain, data) {
		t.Fatal("readonly exact bytes", e)
	}
	clear(plain)
	uri, _ := url.Parse(string(bytes.TrimSpace(data)))
	response, _ := json.Marshal(map[string]any{"users": []any{map[string]any{"email": "test@example.invalid", "account": map[string]any{"_TypedMessage_": "xray.proxy.vless.Account", "id": uri.User.Username(), "flow": "xtls-rprx-vision"}}}})
	defer clear(response)
	r, e := xrayobserve.Snapshot(c, 2, data, response)
	if e != nil {
		t.Fatal(e)
	}
	var before int
	p.db.QueryRow("SELECT count(*) FROM audit_events").Scan(&before)
	summary, e := ro.RecheckXrayUsersObservation(ctx, v, c, 2, xrayobserve.Target{}, r)
	if e != nil || !summary.UserMatches || summary.RuntimeReadback || summary.InventoryBound || summary.ExecutionScopeBound || summary.Ready || summary.RevisionVerified || summary.CoreIdentityVerified || summary.TransportVerified || summary.ClientsVerified {
		t.Fatal("partial published", e)
	}
	if _, e = ro.RecheckXrayUsersObservation(ctx, v, c, 2, xrayobserve.Target{}, xrayobserve.Result{}); !errors.Is(e, xrayobserve.ErrStale) {
		t.Fatal("empty result", e)
	}
	for _, target := range []xrayobserve.Target{
		{Scope: runtimeenv.Scope{BootID: "11111111-1111-1111-1111-111111111111"}},
		{Scope: runtimeenv.Scope{NetNSDevice: 4}},
		{Scope: runtimeenv.Scope{NetNSInode: 12345}},
		{Server: "127.0.0.1:10085", Tag: "inventory", ToolSHA256: strings.Repeat("a", 64), InventorySHA256: strings.Repeat("c", 64), Scope: runtimeenv.Scope{BootID: "11111111-1111-1111-1111-111111111111", NetNSDevice: 4, NetNSInode: 12345}},
	} {
		if _, e = ro.RecheckXrayUsersObservation(ctx, v, c, 2, target, r); !errors.Is(e, xrayobserve.ErrStale) {
			t.Fatal("snapshot relabelled as runtime execution scope", e)
		}
	}
	var after, revision int
	var state string
	var installed *string
	p.db.QueryRow("SELECT count(*) FROM audit_events").Scan(&after)
	p.db.QueryRow("SELECT d.revision,p.state,p.installed_revision FROM profiles p JOIN devices d ON d.id=p.device_id WHERE p.id=?", c.ProfileID).Scan(&revision, &state, &installed)
	if before != after || revision != 2 || state != "pending" || installed != nil {
		t.Fatal("read-only observer mutated state")
	}
	if _, e = p.ReadReadyProfileSecret(ctx, v, u.ID, c.ProfileID); !errors.Is(e, domain.ErrDeviceState) {
		t.Fatal("partial allowed download", e)
	}
	wrong := c
	wrong.OwnerID = "foreign"
	if _, e = ro.LoadPendingXrayUsersObservation(ctx, v, wrong, 2); !errors.Is(e, ErrNotFound) {
		t.Fatal("foreign target", e)
	}
	if _, e = p.RenameDevice(ctx, u.ID, d.ID, "Renamed", 2); e != nil {
		t.Fatal(e)
	}
	if _, e = ro.RecheckXrayUsersObservation(ctx, v, c, 2, xrayobserve.Target{}, r); !errors.Is(e, ErrConflict) {
		t.Fatal("stale current revision", e)
	}
	if _, e = ro.RecheckXrayUsersObservation(ctx, v, c, 3, xrayobserve.Target{}, r); !errors.Is(e, xrayobserve.ErrStale) {
		t.Fatal("observation rebound", e)
	}
	p.db.Exec("UPDATE profiles SET installed_revision='unexpected' WHERE id=?", c.ProfileID)
	if _, e = ro.LoadPendingXrayUsersObservation(ctx, v, c, 3); !errors.Is(e, domain.ErrDeviceState) {
		t.Fatal("installed pending profile observed", e)
	}
}
func TestVLESSWireAliasRaceAcrossDBHandles(t *testing.T) {
	p, s, _, path := authStore(t)
	u, _ := enroll(t, s, "alice")
	v := profileTestKey(t)
	p.InitializeProfileVault(ctx, v)
	a, _ := p.RequestDevice(ctx, u.ID, deviceInput())
	b, _ := p.RequestDevice(ctx, u.ID, deviceInput())
	second, e := OpenExistingPortal(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer second.Close()
	data := importPayload(t)
	alias := vlessAliasPayload(t, data)
	start := make(chan struct{})
	out := make(chan error, 2)
	var wg sync.WaitGroup
	for i, c := range []domain.Device{a, b} {
		writer := p
		payload := data
		if i == 1 {
			writer = second
			payload = alias
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, e := writer.ImportClientProfile(ctx, v, importContext(u.ID, c), 1, payload, true)
			out <- e
		}()
	}
	close(start)
	wg.Wait()
	close(out)
	success, conflict := 0, 0
	for e := range out {
		if e == nil {
			success++
		} else if errors.Is(e, ErrClientCredentialConflict) {
			conflict++
		} else {
			t.Fatal("unexpected alias race", e)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatal("wire alias assigned twice")
	}
	newKey := profileTestKey(t)
	if _, e = p.RotateProfileVault(ctx, v, newKey); e != nil {
		t.Fatal(e)
	}
	// Either winning export remains exact; rotation must retain alias exclusion.
	decrypted := 0
	for _, d := range []domain.Device{a, b} {
		c := importContext(u.ID, d)
		plain, e := p.LoadPendingXrayUsersObservation(ctx, newKey, c, 2)
		if e == nil {
			decrypted++
			if !bytes.Equal(plain, data) && !bytes.Equal(plain, alias) {
				t.Fatal("export bytes changed")
			}
			clear(plain)
		} else {
			if !errors.Is(e, ErrConflict) && !errors.Is(e, ErrNotFound) {
				t.Fatal("rotated current profile unavailable", e)
			}
			if _, e = p.ImportClientProfile(ctx, newKey, c, 1, data, false); !errors.Is(e, ErrClientCredentialConflict) {
				t.Fatal("rotation lost alias exclusion", e)
			}
		}
	}
	if decrypted != 1 {
		t.Fatal("winning exact export lost")
	}
}
