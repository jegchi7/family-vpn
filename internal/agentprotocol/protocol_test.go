package agentprotocol

import (
	"strings"
	"testing"
)

func TestStrictIntent(t *testing.T) {
	good := `{"schema_version":1,"operation_id":"op-a","type":"EnsureDeviceProfiles","target_id":"profile-a","expected_revision":0,"payload":{"generation":1}}`
	if _, e := Decode(strings.NewReader(good)); e != nil {
		t.Fatal(e)
	}
	cases := []string{
		strings.Replace(good, `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1),
		strings.Replace(good, `"schema_version"`, `"Schema_version"`, 1),
		strings.Replace(good, `"generation":1`, `"generation":1,"generation":2`, 1),
		strings.Replace(good, `"generation":1`, `"generation":1,"command":"whoami"`, 1),
		strings.Replace(good, `"generation":1`, `"generation":null`, 1),
		strings.Replace(good, `"payload":`, `"path":"/tmp/x","payload":`, 1),
		strings.Replace(good, `"payload":`, `"service":"arbitrary","payload":`, 1),
		strings.Replace(good, `"payload":`, `"config":{},"payload":`, 1),
		strings.Replace(good, `"payload":`, `"endpoint":"https://example.invalid","payload":`, 1),
		strings.Replace(good, `"schema_version":1`, `"schema_version":2`, 1),
		strings.Replace(good, `EnsureDeviceProfiles`, `ApplyRevision`, 1),
		strings.Replace(good, `"generation":1`, `"generation":1.5`, 1),
		strings.Replace(good, `"target_id":"profile-a"`, `"target_id":"../x"`, 1),
		strings.Replace(good, `"expected_revision":0`, `"expected_revision":-1`, 1),
		good + `{}`, good + strings.Repeat(" ", MaxBody), `null`,
	}
	for i, b := range cases {
		if _, e := Decode(strings.NewReader(b)); e == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}
