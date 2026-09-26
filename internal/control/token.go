// Package control verifies signed stop and upgrade tokens and opens the
// maintenance window during which the Endpoint Security self-protection lets
// the agent be stopped.
//
// Threats: a local root process, or anyone who can reach the IPC socket, must
// not be able to stop or unload darkd without an operator-signed token. A token
// is accepted only when it is at most MaxTokenSize bytes, its Ed25519 signature
// over the domain-separated canonical payload verifies against a key in the
// root-owned, non-group/world-writable key file, its system_id is this
// endpoint's, its lifetime is at most MaxTokenLifetime, it is not expired, its
// issued_at is at most MaxClockSkew in the future, and its nonce has not been
// used (nonces persist across restarts). Any error denies and leaves the window
// closed. The raw token and nonce are never logged or journaled; only the key
// fingerprint and a SHA-256 of the nonce are.
//
// Not covered: a stolen signing key or an unexpired stolen token (it is single
// use, but the first presenter wins); root rewriting the key file or rolling the
// wall clock back past a pruned nonce's not_after; any process stopping darkd
// while a window is open (the window is not bound to the presenting peer);
// unloading the Endpoint Security extension or rebooting.
package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const (
	// TokenVersion is the only payload version accepted.
	TokenVersion = 1
	// MaxTokenSize bounds the encoded token before any parsing.
	MaxTokenSize = 4096
	// MaxTokenLifetime bounds not_after - issued_at.
	MaxTokenLifetime = 15 * time.Minute
	// MaxClockSkew bounds how far issued_at may be ahead of this clock.
	MaxClockSkew = 5 * time.Minute
	// MinNonceSize and MaxNonceSize bound the decoded nonce.
	MinNonceSize = 16
	MaxNonceSize = 64
	// DefaultNonceSize is what SignToken generates.
	DefaultNonceSize = 32

	ActionStop    = "stop"
	ActionUpgrade = "upgrade"

	tokenPrefix = "darkdctl1"
	// signingContext separates these signatures from any other use of the key.
	signingContext = "afterdark-darkd/control/v1\x00"
)

var (
	ErrTokenTooLarge  = errors.New("control token exceeds 4096 bytes")
	ErrMalformed      = errors.New("control token is malformed")
	ErrBadSignature   = errors.New("control token signature does not verify against any configured key")
	ErrNotCanonical   = errors.New("control token payload is not canonical")
	ErrBadVersion     = errors.New("control token version is not supported")
	ErrBadAction      = errors.New("control token action must be stop or upgrade")
	ErrWrongSystem    = errors.New("control token was issued for a different system")
	ErrBadNonce       = errors.New("control token nonce must be 16 to 64 bytes")
	ErrExpired        = errors.New("control token has expired")
	ErrLifetime       = errors.New("control token lifetime exceeds 15 minutes or is not positive")
	ErrFutureIssuedAt = errors.New("control token issued_at is more than 5 minutes in the future")
)

// Claims is the signed payload. Field order is the canonical encoding order;
// a payload is accepted only if re-encoding it reproduces the signed bytes.
type Claims struct {
	Version  int    `json:"version"`
	Action   string `json:"action"`
	SystemID string `json:"system_id"`
	Nonce    string `json:"nonce"`
	IssuedAt int64  `json:"issued_at"`
	NotAfter int64  `json:"not_after"`
}

// NewClaims builds claims with a fresh CSPRNG nonce.
func NewClaims(action, systemID string, issuedAt time.Time, ttl time.Duration) (Claims, error) {
	if action != ActionStop && action != ActionUpgrade {
		return Claims{}, ErrBadAction
	}
	if strings.TrimSpace(systemID) == "" {
		return Claims{}, errors.New("system id is required")
	}
	if ttl <= 0 || ttl > MaxTokenLifetime {
		return Claims{}, ErrLifetime
	}
	nonce := make([]byte, DefaultNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return Claims{}, fmt.Errorf("crypto/rand read failed: %w", err)
	}
	return Claims{
		Version:  TokenVersion,
		Action:   action,
		SystemID: systemID,
		Nonce:    base64.RawURLEncoding.EncodeToString(nonce),
		IssuedAt: issuedAt.Unix(),
		NotAfter: issuedAt.Add(ttl).Unix(),
	}, nil
}

// SignToken encodes and signs claims: darkdctl1.<payload>.<signature>, both
// parts unpadded base64url.
func SignToken(priv ed25519.PrivateKey, claims Claims) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", errors.New("invalid Ed25519 private key")
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, signedMessage(payload))
	token := tokenPrefix + "." + base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig)
	if len(token) > MaxTokenSize {
		return "", ErrTokenTooLarge
	}
	return token, nil
}

func signedMessage(payload []byte) []byte {
	msg := make([]byte, 0, len(signingContext)+len(payload))
	msg = append(msg, signingContext...)
	return append(msg, payload...)
}

// verified is a token whose signature and claims passed every check.
type verified struct {
	Claims    Claims
	Key       ed25519.PublicKey
	NonceHash string
}

// verifyToken performs every stateless check. It has no side effects.
func verifyToken(raw []byte, keys []ed25519.PublicKey, systemID string, now time.Time) (verified, error) {
	if len(raw) > MaxTokenSize {
		return verified{}, ErrTokenTooLarge
	}
	if len(keys) == 0 {
		return verified{}, ErrNoKeys
	}
	parts := strings.Split(string(bytes.TrimSpace(raw)), ".")
	if len(parts) != 3 || parts[0] != tokenPrefix {
		return verified{}, ErrMalformed
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || len(payload) == 0 {
		return verified{}, ErrMalformed
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return verified{}, ErrMalformed
	}
	msg := signedMessage(payload)
	var key ed25519.PublicKey
	for _, candidate := range keys {
		if len(candidate) == ed25519.PublicKeySize && ed25519.Verify(candidate, msg, sig) {
			key = candidate
			break
		}
	}
	if key == nil {
		return verified{}, ErrBadSignature
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return verified{}, ErrMalformed
	}
	canonical, err := json.Marshal(claims)
	if err != nil || !bytes.Equal(canonical, payload) {
		return verified{}, ErrNotCanonical
	}
	if claims.Version != TokenVersion {
		return verified{}, ErrBadVersion
	}
	if claims.Action != ActionStop && claims.Action != ActionUpgrade {
		return verified{}, ErrBadAction
	}
	if systemID == "" || subtle.ConstantTimeCompare([]byte(claims.SystemID), []byte(systemID)) != 1 {
		return verified{}, ErrWrongSystem
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(claims.Nonce)
	if err != nil || len(nonce) < MinNonceSize || len(nonce) > MaxNonceSize {
		return verified{}, ErrBadNonce
	}
	lifetime := claims.NotAfter - claims.IssuedAt
	if lifetime <= 0 || lifetime > int64(MaxTokenLifetime/time.Second) {
		return verified{}, ErrLifetime
	}
	if claims.IssuedAt > now.Add(MaxClockSkew).Unix() {
		return verified{}, ErrFutureIssuedAt
	}
	if now.Unix() > claims.NotAfter {
		return verified{}, ErrExpired
	}
	sum := sha256.Sum256(nonce)
	return verified{Claims: claims, Key: key, NonceHash: hex.EncodeToString(sum[:])}, nil
}

// Fingerprint identifies a public key in logs and the journal.
func Fingerprint(key ed25519.PublicKey) string {
	sum := sha256.Sum256(key)
	return "SHA256:" + hex.EncodeToString(sum[:])
}

// ReadToken reads a token from path, or from stdin when path is "-". More than
// MaxTokenSize bytes is an error; nothing beyond that is read.
func ReadToken(path string, stdin io.Reader) ([]byte, error) {
	var r io.Reader
	switch path {
	case "":
		return nil, errors.New("a control token file (or - for stdin) is required")
	case "-":
		r = stdin
	default:
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open control token: %w", err)
		}
		defer f.Close()
		r = f
	}
	data, err := io.ReadAll(io.LimitReader(r, MaxTokenSize+1))
	if err != nil {
		return nil, fmt.Errorf("read control token: %w", err)
	}
	if len(data) > MaxTokenSize {
		return nil, ErrTokenTooLarge
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("control token is empty")
	}
	return data, nil
}
