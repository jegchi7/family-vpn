package netstand

import (
	"bytes"
	"strings"
	"testing"
)

func syntheticJournal(t *testing.T, steps int, final string) []byte {
	t.Helper()
	binding := strings.Repeat("a", 64)
	state := journalState{}
	var out []byte
	for n := 0; n <= steps; n++ {
		r, e := nextRecord(state, binding, n, "progress")
		if e != nil {
			t.Fatal(e)
		}
		b, _ := journalBytes(r)
		out = append(out, b...)
		state = recordState(r)
	}
	if final != "" {
		r, e := nextRecord(state, binding, steps, final)
		if e != nil {
			t.Fatal(e)
		}
		b, _ := journalBytes(r)
		out = append(out, b...)
	}
	return out
}
func TestJournalIsCrashFenceAndNeverReplayAuthority(t *testing.T) {
	for _, final := range []string{"", "complete", "failed"} {
		b := syntheticJournal(t, 64, final)
		s, e := validateJournalBytes(b)
		if e != nil || s.completed != 64 || s.binding != strings.Repeat("a", 64) {
			t.Fatal("valid bounded journal rejected")
		}
		if final != "" {
			if _, e := nextRecord(s, s.binding, s.completed+1, "progress"); e == nil {
				t.Fatal("terminal journal resumed")
			}
		}
	}
	data := syntheticJournal(t, 2, "complete")
	for _, changed := range [][]byte{data[:len(data)-1], append(data, data...), bytes.Replace(data, []byte(`"completed":1`), []byte(`"completed":2`), 1), bytes.Replace(data, []byte(`"sequence":1`), []byte(`"sequence":0`), 1), bytes.Replace(data, []byte(`"state":"complete"`), []byte(`"state":"ready"`), 1), bytes.Replace(data, []byte(`"format":1`), []byte(`"format":1,"format":1`), 1), bytes.Replace(data, []byte(`"format":1`), []byte(`"format":1,"unknown":false`), 1), append(data, []byte("\n")...), []byte(strings.Repeat("x", journalLimit+1))} {
		if _, e := validateJournalBytes(changed); e == nil {
			t.Fatal("ambiguous or resumptive journal accepted")
		}
	}
	state := journalState{binding: strings.Repeat("a", 64), state: "progress", sequence: 0, completed: 0}
	if _, e := nextRecord(state, strings.Repeat("b", 64), 1, "progress"); e == nil {
		t.Fatal("different manifest journal accepted")
	}
	if _, e := nextRecord(state, state.binding, 0, "complete"); e != nil {
		t.Fatal("bounded terminal fence rejected")
	}
}
