package ipc

import (
	"strings"
	"testing"
)

const tokenCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func TestGenerateSecureToken_IsRandom(t *testing.T) {
	t1, err := generateSecureToken(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t2, err := generateSecureToken(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if t1 == t2 {
		t.Error("two tokens should not be identical")
	}
	if len(t1) != 32 {
		t.Errorf("expected length 32, got %d", len(t1))
	}
	// Verify all chars are from the charset
	for _, c := range t1 {
		if !strings.ContainsRune(tokenCharset, c) {
			t.Errorf("unexpected character %q not in charset", c)
		}
	}
}

func TestGenerateSecureToken_Length(t *testing.T) {
	for _, n := range []int{16, 32, 64} {
		tok, err := generateSecureToken(n)
		if err != nil {
			t.Fatalf("length %d: unexpected error: %v", n, err)
		}
		if len(tok) != n {
			t.Errorf("length %d: got %d", n, len(tok))
		}
	}
}

func TestGenerateSecureToken_ZeroLength(t *testing.T) {
	tok, err := generateSecureToken(0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "" {
		t.Errorf("expected empty string for length 0, got %q", tok)
	}
}
