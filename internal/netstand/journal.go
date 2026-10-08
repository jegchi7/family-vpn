package netstand

import (
	"bytes"
	"encoding/json"
	"io"
)

const journalName = "apply.json"
const journalLimit = 32 << 10

// This private journal is a crash/retry fence, never firewall evidence or a
// permission to activate a link, launch a core, or make a profile ready.
type journalRecord struct {
	Format    int    `json:"format"`
	Binding   string `json:"manifest_sha256"`
	Sequence  int    `json:"sequence"`
	Completed int    `json:"completed"`
	State     string `json:"state"`
}
type journalState struct {
	binding             string
	sequence, completed int
	state               string
}

func nextRecord(previous journalState, binding string, completed int, state string) (journalRecord, error) {
	if !digestValid(binding) || completed < 0 || completed > 64 || (state != "progress" && state != "complete" && state != "failed") {
		return journalRecord{}, ErrRecovery
	}
	if previous.binding == "" {
		if completed != 0 || state != "progress" {
			return journalRecord{}, ErrRecovery
		}
		return journalRecord{1, binding, 0, 0, "progress"}, nil
	}
	if previous.binding != binding || previous.state != "progress" || previous.sequence >= 65 {
		return journalRecord{}, ErrRecovery
	}
	if state == "progress" {
		if completed != previous.completed+1 {
			return journalRecord{}, ErrRecovery
		}
	} else if completed != previous.completed {
		return journalRecord{}, ErrRecovery
	}
	return journalRecord{1, binding, previous.sequence + 1, completed, state}, nil
}
func recordState(r journalRecord) journalState {
	return journalState{r.Binding, r.Sequence, r.Completed, r.State}
}
func journalBytes(r journalRecord) ([]byte, error) {
	b, e := json.Marshal(r)
	if e != nil {
		return nil, ErrRecovery
	}
	return append(b, '\n'), nil
}
func validateJournalBytes(data []byte) (journalState, error) {
	if len(data) == 0 || len(data) > journalLimit || data[len(data)-1] != '\n' {
		return journalState{}, ErrRecovery
	}
	lines := bytes.Split(data, []byte{'\n'})
	if len(lines) < 2 || len(lines) > 67 {
		return journalState{}, ErrRecovery
	}
	current := journalState{}
	for _, line := range lines[:len(lines)-1] {
		if len(line) == 0 || len(line) > 512 {
			return journalState{}, ErrRecovery
		}
		var r journalRecord
		d := json.NewDecoder(bytes.NewReader(line))
		d.DisallowUnknownFields()
		if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF || r.Format != 1 {
			return journalState{}, ErrRecovery
		}
		canonical, e := journalBytes(r)
		if e != nil || !bytes.Equal(canonical[:len(canonical)-1], line) {
			return journalState{}, ErrRecovery
		}
		expected, e := nextRecord(current, r.Binding, r.Completed, r.State)
		if e != nil || expected != r {
			return journalState{}, ErrRecovery
		}
		current = recordState(r)
	}
	return current, nil
}
