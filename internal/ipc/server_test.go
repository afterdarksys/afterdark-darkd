package ipc

import (
	"testing"
)

func TestGenerateSecureToken_IsRandom(t *testing.T) {
	t1 := generateSecureToken(32)
	t2 := generateSecureToken(32)
	if t1 == t2 {
		t.Error("two tokens should not be identical")
	}
	if len(t1) != 32 {
		t.Errorf("expected length 32, got %d", len(t1))
	}
}

func TestGenerateSecureToken_Length(t *testing.T) {
	for _, n := range []int{16, 32, 64} {
		tok := generateSecureToken(n)
		if len(tok) != n {
			t.Errorf("length %d: got %d", n, len(tok))
		}
	}
}
