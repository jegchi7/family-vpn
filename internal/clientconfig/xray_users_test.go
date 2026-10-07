package clientconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func userResponse(t testing.TB, ids ...string) []byte {
	t.Helper()
	users := []any{}
	for _, id := range ids {
		users = append(users, map[string]any{"email": "test@example.invalid", "account": map[string]any{"_TypedMessage_": "xray.proxy.vless.Account", "id": id, "flow": "xtls-rprx-vision"}})
	}
	b, e := json.Marshal(map[string]any{"users": users})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { clear(b) })
	return b
}
func aliasID(id string) string {
	b, _ := uuidBytes(id)
	defer clear(b)
	b[6] ^= 1
	h := fmt.Sprintf("%x", b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
func TestXrayUsersPartialComparisonAliasesAndOrdering(t *testing.T) {
	client := sampleURI(t)
	defer clear(client)
	u, _ := url.Parse(string(client))
	id := u.User.Username()
	other := sampleURI(t)
	defer clear(other)
	v, _ := url.Parse(string(other))
	otherID := v.User.Username()
	a, e := CheckXrayUsers(client, userResponse(t, id, otherID))
	if e != nil || !a.Summary().UserMatches {
		t.Fatal("match", e)
	}
	b, e := CheckXrayUsers(client, userResponse(t, strings.ToUpper(otherID), strings.ToUpper(id)))
	if e != nil || !SameXrayUsers(a, b) {
		t.Fatal("map order or UUID case became drift", e)
	}
	for _, tc := range []struct {
		response []byte
		field    string
	}{{userResponse(t), "credential_unobserved"}, {userResponse(t, aliasID(id)), "credential_alias"}, {bytes.Replace(userResponse(t, id), []byte("xtls-rprx-vision"), []byte(""), 1), "flow"}} {
		r, e := CheckXrayUsers(client, tc.response)
		if e != nil || r.Summary().UserMatches || strings.Join(r.Summary().MismatchedFields, ",") != tc.field {
			t.Fatal("partial comparison hid mismatch", e)
		}
	}
	for _, data := range [][]byte{userResponse(t, id, id), userResponse(t, id, aliasID(id))} {
		if _, e = CheckXrayUsers(client, data); !errors.Is(e, ErrXrayUsers) {
			t.Fatal("duplicate wire identity", e)
		}
	}
	encoded, _ := json.Marshal(a)
	for _, out := range []string{string(encoded), fmt.Sprintf("%#v", a), fmt.Sprint(a)} {
		for _, bad := range []string{id, otherID, "test@example.invalid", "digest", "vless://"} {
			if strings.Contains(out, bad) {
				t.Fatal("readback leaked material")
			}
		}
	}
	fields := a.Summary()
	fields.UserMatches = false
	if !a.Summary().UserMatches {
		t.Fatal("mutable comparison")
	}
}
func TestXrayUsersRejectsAmbiguousOrUnsupportedJSON(t *testing.T) {
	client := sampleURI(t)
	defer clear(client)
	u, _ := url.Parse(string(client))
	response := userResponse(t, u.User.Username())
	bad := [][]byte{nil, []byte(`{}`), []byte(`{"users":null}`), []byte(`{"users":[],"Users":[]}`), []byte(`{"users":[]} {}`), []byte(`{"users":[null]}`), []byte(`{"users":[],"token":"hidden"}`), bytes.Repeat([]byte(" "), 65537), bytes.Replace(response, []byte(`"account":`), []byte(`"level":null,"account":`), 1), bytes.Replace(response, []byte(`"account":`), []byte(`"level":4294967296,"account":`), 1), bytes.Replace(response, []byte("xray.proxy.vless.Account"), []byte("xray.proxy.vmess.Account"), 1), bytes.Replace(response, []byte(`"flow":`), []byte(`"reverse":{},"flow":`), 1), bytes.Replace(response, []byte(`"flow":`), []byte(`"encryption":"unsupported","flow":`), 1), bytes.Replace(response, []byte(`"flow":`), []byte(`"id":"duplicate","flow":`), 1)}
	ids := make([]string, 257)
	for i := range ids {
		ids[i] = u.User.Username()
	}
	bad = append(bad, userResponse(t, ids...))
	for i, data := range bad {
		if _, e := CheckXrayUsers(client, data); !errors.Is(e, ErrXrayUsers) {
			t.Fatal("unsupported readback accepted", i, e)
		}
	}
}
func TestVLESSWireAliasesReservedWithoutChangingExport(t *testing.T) {
	client, in, id := snapshotPair(t)
	alias := aliasID(id)
	changed := bytes.Replace(client, []byte(id), []byte(alias), 1)
	defer clear(changed)
	a, e := Validate(VLESSRealityURI, client)
	if e != nil {
		t.Fatal(e)
	}
	b, e := Validate(VLESSRealityURI, changed)
	if e != nil || !SameCredential(a, b) {
		t.Fatal("wire alias not reserved", e)
	}
	peer := in["settings"].(map[string]any)["clients"].([]any)[0].(map[string]any)
	peer["id"] = alias
	response, pin := encodedSnapshot(t, in)
	fields, e := CheckXraySnapshot(VLESSRealityURI, client, response, "clients", "edge.example.invalid:443", pin)
	if e != nil || strings.Join(fields, ",") != "credential" {
		t.Fatal("alias became exact config match", e)
	}
	in["settings"].(map[string]any)["clients"] = []any{map[string]any{"id": id, "flow": "xtls-rprx-vision"}, peer}
	response, pin = encodedSnapshot(t, in)
	if _, e = CheckXraySnapshot(VLESSRealityURI, client, response, "clients", "edge.example.invalid:443", pin); !errors.Is(e, ErrSnapshot) {
		t.Fatal("snapshot wire aliases ambiguous", e)
	}
}
func FuzzXrayUsersNeverMutatesOrLeaks(f *testing.F) {
	client := sampleURI(f)
	defer clear(client)
	u, _ := url.Parse(string(client))
	f.Add(userResponse(f, u.User.Username()))
	f.Add([]byte(`{"users":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		before := bytes.Clone(data)
		_, e := CheckXrayUsers(client, data)
		if !bytes.Equal(before, data) {
			t.Fatal("mutated input")
		}
		if e != nil && !errors.Is(e, ErrXrayUsers) {
			t.Fatal("unsafe error", e)
		}
	})
}
