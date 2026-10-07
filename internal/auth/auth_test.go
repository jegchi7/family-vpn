package auth

import (
	"strings"
	"testing"
)

func TestPasswordHashAndBoundedParser(t *testing.T) {
	password := RandomToken()
	a, e := HashPassword(password)
	if e != nil {
		t.Fatal(e)
	}
	b, e := HashPassword(password)
	if e != nil {
		t.Fatal(e)
	}
	if a == b || strings.Contains(a, password) || !VerifyPassword(password, a) || VerifyPassword(RandomToken(), a) {
		t.Fatal("password hash failure")
	}
	for _, s := range []string{"", strings.Replace(a, "m=19456", "m=999999999", 1), a + "$extra", strings.Replace(a, "v=19", "v=20", 1)} {
		if VerifyPassword(password, s) {
			t.Fatal("invalid encoding accepted")
		}
	}
	if ValidPassword("short") || ValidPassword(strings.Repeat("a", 1025)) {
		t.Fatal("password bounds")
	}
	raw := RandomToken()
	if !ValidToken(raw) || ValidToken(raw+"=") || CSRF(raw) == raw || !Equal(CSRF(raw), CSRF(raw)) {
		t.Fatal("token boundary failure")
	}
}
