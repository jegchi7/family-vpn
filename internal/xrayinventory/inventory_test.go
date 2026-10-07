package xrayinventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/runtimeenv"
	"strings"
	"testing"
)

func fixture(t interface {
	Helper()
	Fatal(...any)
}) ([]byte, string, Expected) {
	t.Helper()
	e := Expected{Server: "127.0.0.1:10085", Tag: "clients", ToolSHA256: strings.Repeat("a", 64), Scope: runtimeenv.Scope{BootID: "11111111-2222-3333-4444-555555555555", NetNSDevice: 4, NetNSInode: 12345}}
	b, err := json.Marshal(map[string]any{"schema_version": 1, "boot_id": e.Scope.BootID, "netns_device": e.Scope.NetNSDevice, "netns_inode": e.Scope.NetNSInode, "kernel_release": "test-local.1", "xray": []any{map[string]any{"api_server": e.Server, "inbound_tag": e.Tag, "tool_sha256": e.ToolSHA256, "tool_version": "test-cli.1", "core_sha256": strings.Repeat("b", 64), "core_version": "test-core.1", "config_sha256": strings.Repeat("c", 64)}}})
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return b, hex.EncodeToString(h[:]), e
}

func TestClosedInventoryAndExactByteTargetBinding(t *testing.T) {
	b, pin, e := fixture(t)
	i, err := parse(b)
	if err != nil || i.check(pin, e) != nil {
		t.Fatal("valid expectations rejected", err)
	}
	for _, field := range []string{"server", "tag", "tool", "boot", "device", "inode"} {
		wrong := e
		switch field {
		case "server":
			wrong.Server = "[::1]:10085"
		case "tag":
			wrong.Tag = "other"
		case "tool":
			wrong.ToolSHA256 = strings.Repeat("b", 64)
		case "boot":
			wrong.Scope.BootID = "22222222-2222-3333-4444-555555555555"
		case "device":
			wrong.Scope.NetNSDevice++
		case "inode":
			wrong.Scope.NetNSInode++
		}
		if !errors.Is(i.check(pin, wrong), ErrInventory) {
			t.Fatal("target rebound", field)
		}
	}
	for _, wrong := range []string{"", strings.Repeat("A", 64), strings.Repeat("d", 64)} {
		if !errors.Is(i.check(wrong, e), ErrInventory) {
			t.Fatal("pin bypass")
		}
	}
	changed, err := parse(append(bytes.Clone(b), '\n'))
	if err != nil || !errors.Is(changed.check(pin, e), ErrInventory) {
		t.Fatal("exact bytes not pinned", err)
	}
}

func TestRejectAmbiguousIncompleteAndUnsupportedInventory(t *testing.T) {
	b, _, _ := fixture(t)
	bad := [][]byte{nil, []byte(`null`), []byte(`{}`), append(bytes.Clone(b), []byte(` {}`)...), bytes.Repeat([]byte(" "), MaxSize+1), bytes.Replace(b, []byte(`"schema_version":1`), []byte(`"schema_version":2`), 1), bytes.Replace(b, []byte(`"schema_version":1`), []byte(`"schema_version":1.0`), 1), bytes.Replace(b, []byte(`"schema_version":1`), []byte(`"schema_version":1,"Schema_Version":1`), 1), bytes.Replace(b, []byte(`"kernel_release":`), []byte(`"unknown":"private-value","kernel_release":`), 1), bytes.Replace(b, []byte(`"inbound_tag":`), []byte(`"inbound_tag":"duplicate","inbound_tag":`), 1), bytes.Replace(b, []byte(`"boot_id":`), []byte(`"Boot_ID":`), 1), bytes.Replace(b, []byte(`"netns_inode":12345`), []byte(`"netns_inode":0`), 1), bytes.Replace(b, []byte(`"netns_device":4`), []byte(`"netns_device":4.0`), 1), bytes.Replace(b, []byte(`"netns_device":4`), []byte(`"netns_device":18446744073709551616`), 1), bytes.Replace(b, []byte(`127.0.0.1:10085`), []byte(`remote.example.invalid:443`), 1), bytes.Replace(b, []byte(`test-core.1`), []byte(`test core`), 1), bytes.Replace(b, []byte(`"tool_sha256":`), []byte(`"token":"private-value","tool_sha256":`), 1), bytes.Replace(b, []byte(`"core_version":"test-core.1"`), []byte(`"core_version":null`), 1)}
	for _, v := range bad {
		if _, err := parse(v); !errors.Is(err, ErrInventory) || strings.Contains(err.Error(), "private-value") {
			t.Fatal("ambiguous inventory accepted/raw error", err)
		}
	}
	var m map[string]any
	json.Unmarshal(b, &m)
	for _, field := range []string{"schema_version", "boot_id", "netns_device", "netns_inode", "kernel_release", "xray"} {
		var copy map[string]any
		json.Unmarshal(b, &copy)
		delete(copy, field)
		v, _ := json.Marshal(copy)
		if _, err := parse(v); !errors.Is(err, ErrInventory) {
			t.Fatal("missing field", field)
		}
	}
	entry := m["xray"].([]any)[0].(map[string]any)
	for _, field := range []string{"api_server", "inbound_tag", "tool_sha256", "tool_version", "core_sha256", "core_version", "config_sha256"} {
		var copy map[string]any
		json.Unmarshal(b, &copy)
		delete(copy["xray"].([]any)[0].(map[string]any), field)
		v, _ := json.Marshal(copy)
		if _, err := parse(v); !errors.Is(err, ErrInventory) {
			t.Fatal("missing target field", field)
		}
	}
	m["xray"] = []any{entry, entry}
	v, _ := json.Marshal(m)
	if _, err := parse(v); !errors.Is(err, ErrInventory) {
		t.Fatal("duplicate target accepted")
	}
	other := map[string]any{}
	for k, v := range entry {
		other[k] = v
	}
	other["inbound_tag"] = "other"
	other["core_sha256"] = strings.Repeat("d", 64)
	m["xray"] = []any{entry, other}
	v, _ = json.Marshal(m)
	if _, err := parse(v); !errors.Is(err, ErrInventory) {
		t.Fatal("same API inconsistent core accepted")
	}
	other["core_sha256"] = entry["core_sha256"]
	v, _ = json.Marshal(m)
	if _, err := parse(v); err != nil {
		t.Fatal("separate tags rejected", err)
	}
	entries := make([]any, MaxTargets+1)
	for n := range entries {
		copy := map[string]any{}
		for k, v := range entry {
			copy[k] = v
		}
		copy["inbound_tag"] = strings.Repeat("x", n+1)
		entries[n] = copy
	}
	m["xray"] = entries
	v, _ = json.Marshal(m)
	if _, err := parse(v); !errors.Is(err, ErrInventory) {
		t.Fatal("target count unbounded")
	}
}

func FuzzInventory(f *testing.F) {
	seed, _, _ := fixture(f)
	f.Add(seed)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"schema_version":1}`))
	f.Add([]byte(`{"xray":null}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		i, e := parse(b)
		if e == nil {
			if len(i.targets) < 1 || len(i.targets) > MaxTargets || !i.scope.Valid() || !version(i.kernel) {
				t.Fatal("accepted invalid inventory")
			}
			for _, v := range i.targets {
				if !ValidTarget(v.server, v.tag, v.tool) || !ValidPin(v.core) || !ValidPin(v.config) {
					t.Fatal("accepted invalid target")
				}
			}
		}
	})
}
