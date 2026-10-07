package runtimeenv

import (
	"strings"
	"testing"
)

func TestIndependentScopeCannotDefaultOrNormalize(t *testing.T) {
	good := Scope{"abcdefab-2222-3333-4444-555555555555", 4, 12345}
	if !good.Valid() {
		t.Fatal("valid scope")
	}
	for _, s := range []Scope{{}, {good.BootID, 0, 12345}, {good.BootID, 4, 0}, {strings.ToUpper(good.BootID), 4, 12345}, {"00000000-0000-0000-0000-000000000000", 4, 12345}, {good.BootID + "\n", 4, 12345}, {"abcdefab2222-3333-4444-555555555555", 4, 12345}} {
		if s.Valid() {
			t.Fatal("invalid scope accepted")
		}
	}
}
