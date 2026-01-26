package auth

import (
	"errors"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrPasswordTooShort    = errors.New("password must be at least 12 characters")
	ErrPasswordNoUppercase = errors.New("password must contain at least one uppercase letter")
	ErrPasswordNoLowercase = errors.New("password must contain at least one lowercase letter")
	ErrPasswordNoDigit     = errors.New("password must contain at least one digit")
	ErrPasswordNoSpecial   = errors.New("password must contain at least one special character")
	ErrPasswordMismatch    = errors.New("password does not match")
)

// PasswordConfig holds password policy configuration
type PasswordConfig struct {
	MinLength       int
	RequireUpper    bool
	RequireLower    bool
	RequireDigit    bool
	RequireSpecial  bool
	BcryptCost      int
}

// DefaultPasswordConfig returns sensible password policy defaults
func DefaultPasswordConfig() *PasswordConfig {
	return &PasswordConfig{
		MinLength:      12,
		RequireUpper:   true,
		RequireLower:   true,
		RequireDigit:   true,
		RequireSpecial: true,
		BcryptCost:     bcrypt.DefaultCost,
	}
}

// PasswordService handles password operations
type PasswordService struct {
	config *PasswordConfig
}

// NewPasswordService creates a new password service
func NewPasswordService(config *PasswordConfig) *PasswordService {
	if config == nil {
		config = DefaultPasswordConfig()
	}
	return &PasswordService{config: config}
}

// HashPassword creates a bcrypt hash of the password
func (s *PasswordService) HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.config.BcryptCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// VerifyPassword checks if the password matches the hash
func (s *PasswordService) VerifyPassword(password, hash string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return ErrPasswordMismatch
		}
		return err
	}
	return nil
}

// ValidatePassword checks if a password meets policy requirements
func (s *PasswordService) ValidatePassword(password string) error {
	if len(password) < s.config.MinLength {
		return ErrPasswordTooShort
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasDigit   bool
		hasSpecial bool
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if s.config.RequireUpper && !hasUpper {
		return ErrPasswordNoUppercase
	}
	if s.config.RequireLower && !hasLower {
		return ErrPasswordNoLowercase
	}
	if s.config.RequireDigit && !hasDigit {
		return ErrPasswordNoDigit
	}
	if s.config.RequireSpecial && !hasSpecial {
		return ErrPasswordNoSpecial
	}

	return nil
}

// ValidateAndHash validates the password and returns its hash
func (s *PasswordService) ValidateAndHash(password string) (string, error) {
	if err := s.ValidatePassword(password); err != nil {
		return "", err
	}
	return s.HashPassword(password)
}

// NeedsRehash checks if a password hash needs to be updated
// (e.g., if bcrypt cost has changed)
func (s *PasswordService) NeedsRehash(hash string) bool {
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		return true
	}
	return cost != s.config.BcryptCost
}
