//go:build linux

package profileobserve

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestAWGSessionNativeCommandVocabularyIsClosed(t *testing.T) {
	for _, view := range []string{"", "setconf", "addconf", "syncconf", "dump", "all", "show", "interfaces", "transfer extra", "latest-handshakes\n"} {
		data, e := readNativeCommand(context.Background(), "inventory_awg", strings.Repeat("a", 64), view)
		if !errors.Is(e, ErrRuntime) || len(data) != 0 {
			t.Fatal("unapproved command reached the native tool")
		}
	}
}
