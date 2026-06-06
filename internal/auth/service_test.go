package auth

import (
	"testing"
)

func TestHashToken_NotPlaintext(t *testing.T) {
	token := "mysecrettoken"
	hashed := hashToken(token)
	if hashed == token {
		t.Error("hashToken must not return the plaintext token")
	}
}

func TestHashToken_Deterministic(t *testing.T) {
	token := "mysecrettoken"
	if hashToken(token) != hashToken(token) {
		t.Error("hashToken must be deterministic for the same input")
	}
}

func TestHashToken_DifferentInputs(t *testing.T) {
	if hashToken("a") == hashToken("b") {
		t.Error("different tokens must produce different hashes")
	}
}

func TestHashToken_KnownValue(t *testing.T) {
	// SHA-256("test") = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
	got := hashToken("test")
	want := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	if got != want {
		t.Errorf("hashToken(\"test\") = %q, want %q", got, want)
	}
}
