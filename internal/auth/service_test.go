package auth

import (
	"context"
	"strings"
	"testing"
	"time"
)

// mockUserRepo is a minimal in-memory UserRepository for testing.
type mockUserRepo struct {
	users []*User
}

func (m *mockUserRepo) Create(_ context.Context, user *User) error { return nil }
func (m *mockUserRepo) GetByID(_ context.Context, id string) (*User, error) {
	for _, u := range m.users {
		if u.ID == id {
			return u, nil
		}
	}
	return nil, ErrNotFound
}
func (m *mockUserRepo) GetByEmail(_ context.Context, _ string, email string) (*User, error) {
	for _, u := range m.users {
		if strings.EqualFold(u.Email, email) {
			return u, nil
		}
	}
	return nil, ErrNotFound
}
func (m *mockUserRepo) Update(_ context.Context, _ *User) error              { return nil }
func (m *mockUserRepo) Delete(_ context.Context, _ string) error             { return nil }
func (m *mockUserRepo) List(_ context.Context, _ string, _ *UserFilter) ([]*User, error) {
	return m.users, nil
}
func (m *mockUserRepo) UpdateLastLogin(_ context.Context, _ string) error      { return nil }
func (m *mockUserRepo) IncrementFailedLogins(_ context.Context, _ string) error { return nil }
func (m *mockUserRepo) ResetFailedLogins(_ context.Context, _ string) error    { return nil }
func (m *mockUserRepo) LockUser(_ context.Context, _ string, _ time.Time) error { return nil }
func (m *mockUserRepo) UnlockUser(_ context.Context, _ string) error           { return nil }

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

func TestFindUserByEmail_ReturnsUser(t *testing.T) {
	svc := &AuthService{users: &mockUserRepo{
		users: []*User{{ID: "u1", Email: "test@example.com", TenantID: "t1"}},
	}}
	user, err := svc.findUserByEmail(context.Background(), "test@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.ID != "u1" {
		t.Errorf("expected u1, got %s", user.ID)
	}
}

func TestFindUserByEmail_NormalizesEmail(t *testing.T) {
	svc := &AuthService{users: &mockUserRepo{
		users: []*User{{ID: "u1", Email: "test@example.com"}},
	}}
	user, err := svc.findUserByEmail(context.Background(), "  TEST@EXAMPLE.COM  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.ID != "u1" {
		t.Errorf("expected u1, got %s", user.ID)
	}
}

func TestFindUserByEmail_NotFound(t *testing.T) {
	svc := &AuthService{users: &mockUserRepo{users: []*User{}}}
	_, err := svc.findUserByEmail(context.Background(), "nobody@example.com")
	if err == nil {
		t.Error("expected error for unknown email")
	}
}
