package ipc

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/metadata"
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

func TestValidateAuth_RejectsNoMetadata(t *testing.T) {
	s := &Server{config: &Config{RequireAuth: true}, authToken: "correcttoken"}
	err := s.validateAuth(context.Background())
	if err == nil {
		t.Error("expected error with no metadata in context")
	}
}

func TestValidateAuth_RejectsNoAuthHeader(t *testing.T) {
	s := &Server{config: &Config{RequireAuth: true}, authToken: "correcttoken"}
	md := metadata.New(map[string]string{"other": "value"})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	err := s.validateAuth(ctx)
	if err == nil {
		t.Error("expected error with no authorization header")
	}
}

func TestValidateAuth_RejectsBadToken(t *testing.T) {
	s := &Server{config: &Config{RequireAuth: true}, authToken: "correcttoken"}
	md := metadata.Pairs("authorization", "Bearer wrongtoken")
	ctx := metadata.NewIncomingContext(context.Background(), md)
	err := s.validateAuth(ctx)
	if err == nil {
		t.Error("expected error with wrong token")
	}
}

func TestValidateAuth_AcceptsCorrectToken(t *testing.T) {
	s := &Server{config: &Config{RequireAuth: true}, authToken: "correcttoken"}
	md := metadata.Pairs("authorization", "Bearer correcttoken")
	ctx := metadata.NewIncomingContext(context.Background(), md)
	if err := s.validateAuth(ctx); err != nil {
		t.Errorf("expected no error with correct token, got: %v", err)
	}
}

func TestValidateAuth_SkipsWhenAuthDisabled(t *testing.T) {
	s := &Server{config: &Config{RequireAuth: false}, authToken: ""}
	err := s.validateAuth(context.Background())
	if err != nil {
		t.Errorf("expected no error when auth disabled, got: %v", err)
	}
}
