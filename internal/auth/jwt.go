package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidToken     = errors.New("invalid token")
	ErrExpiredToken     = errors.New("token has expired")
	ErrInvalidClaims    = errors.New("invalid token claims")
	ErrTokenNotYetValid = errors.New("token not yet valid")
)

// JWTConfig holds JWT configuration
type JWTConfig struct {
	Secret          []byte
	AccessExpiry    time.Duration
	RefreshExpiry   time.Duration
	AgentExpiry     time.Duration
	Issuer          string
	AllowedAudience []string
}

// DefaultJWTConfig returns sensible defaults
func DefaultJWTConfig(secret []byte) *JWTConfig {
	return &JWTConfig{
		Secret:        secret,
		AccessExpiry:  15 * time.Minute,
		RefreshExpiry: 7 * 24 * time.Hour,
		AgentExpiry:   30 * 24 * time.Hour,
		Issuer:        "afterdark",
		AllowedAudience: []string{"afterdark-api"},
	}
}

// JWTService handles JWT operations
type JWTService struct {
	config *JWTConfig
}

// NewJWTService creates a new JWT service
func NewJWTService(config *JWTConfig) *JWTService {
	return &JWTService{config: config}
}

// GenerateAccessToken creates a new access token for a user
func (s *JWTService) GenerateAccessToken(user *User, roles []string, permissions []string, siteIDs []string) (string, error) {
	now := time.Now()
	claims := &JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.config.Issuer,
			Subject:   user.ID,
			Audience:  s.config.AllowedAudience,
			ExpiresAt: jwt.NewNumericDate(now.Add(s.config.AccessExpiry)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        generateTokenID(),
		},
		UserID:      user.ID,
		TenantID:    user.TenantID,
		Email:       user.Email,
		Roles:       roles,
		Permissions: permissions,
		SiteIDs:     siteIDs,
		TokenType:   TokenTypeAccess,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.config.Secret)
}

// GenerateRefreshToken creates a new refresh token
func (s *JWTService) GenerateRefreshToken(user *User) (string, error) {
	now := time.Now()
	claims := &JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.config.Issuer,
			Subject:   user.ID,
			Audience:  s.config.AllowedAudience,
			ExpiresAt: jwt.NewNumericDate(now.Add(s.config.RefreshExpiry)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        generateTokenID(),
		},
		UserID:    user.ID,
		TenantID:  user.TenantID,
		TokenType: TokenTypeRefresh,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.config.Secret)
}

// GenerateAgentToken creates a token for an endpoint agent
func (s *JWTService) GenerateAgentToken(tenantID, siteID, agentID string) (string, error) {
	now := time.Now()
	claims := &JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.config.Issuer,
			Subject:   agentID,
			Audience:  []string{"afterdark-agent"},
			ExpiresAt: jwt.NewNumericDate(now.Add(s.config.AgentExpiry)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        generateTokenID(),
		},
		TenantID:  tenantID,
		SiteIDs:   []string{siteID},
		TokenType: TokenTypeAgent,
		Permissions: []string{
			"agents:write:own",
			"events:write:own",
			"telemetry:write:own",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.config.Secret)
}

// ValidateToken parses and validates a JWT token
func (s *JWTService) ValidateToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.config.Secret, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		if errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, ErrTokenNotYetValid
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidClaims
	}

	// Validate issuer
	if claims.Issuer != s.config.Issuer {
		return nil, fmt.Errorf("%w: invalid issuer", ErrInvalidClaims)
	}

	return claims, nil
}

// RefreshAccessToken generates a new access token from a valid refresh token
func (s *JWTService) RefreshAccessToken(refreshToken string, user *User, roles []string, permissions []string, siteIDs []string) (string, error) {
	claims, err := s.ValidateToken(refreshToken)
	if err != nil {
		return "", err
	}

	if claims.TokenType != TokenTypeRefresh {
		return "", fmt.Errorf("%w: not a refresh token", ErrInvalidToken)
	}

	if claims.UserID != user.ID {
		return "", fmt.Errorf("%w: user mismatch", ErrInvalidToken)
	}

	return s.GenerateAccessToken(user, roles, permissions, siteIDs)
}

// GetTokenExpiry returns when a token expires
func (s *JWTService) GetTokenExpiry(tokenString string) (time.Time, error) {
	claims, err := s.ValidateToken(tokenString)
	if err != nil && !errors.Is(err, ErrExpiredToken) {
		return time.Time{}, err
	}

	if claims != nil && claims.ExpiresAt != nil {
		return claims.ExpiresAt.Time, nil
	}

	return time.Time{}, ErrInvalidClaims
}

// generateTokenID creates a unique token identifier
func generateTokenID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// GenerateAPIKey generates a random API key
func GenerateAPIKey() (key string, prefix string, err error) {
	// Generate 32 bytes of random data
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	key = "ads_" + base64.RawURLEncoding.EncodeToString(b)
	prefix = key[:12] // "ads_" + first 8 chars

	return key, prefix, nil
}

// GenerateSecureToken generates a random token of specified length
func GenerateSecureToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
