package control

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	// DefaultKeysFile holds the trusted stop public keys when the config does
	// not name one. A missing file means no stop is possible.
	DefaultKeysFile = "/etc/afterdark/control-stop-keys.pub"

	maxKeysFileSize = 16 * 1024
	maxKeys         = 16

	PrivateKeyFile = "darkd-control.key"
	PublicKeyFile  = "darkd-control.pub"
)

// ErrNoKeys means no trusted stop key is configured, so stop is impossible.
var ErrNoKeys = errors.New("no control stop public key is configured; darkd cannot be stopped or upgraded until an operator installs one (control.stop_public_keys_file)")

// LoadPublicKeys reads one base64 Ed25519 public key per line. Blank lines and
// lines starting with # are ignored. The file and its directory must be owned
// by owner and not writable by group or others; anything else is rejected.
func LoadPublicKeys(path string, owner uint32) ([]ed25519.PublicKey, error) {
	if path == "" {
		return nil, ErrNoKeys
	}
	if err := checkTrustedPath(filepath.Dir(path), owner, true); err != nil {
		return nil, err
	}
	f, err := openNoFollow(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s does not exist", ErrNoKeys, path)
		}
		return nil, fmt.Errorf("open control key file: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat control key file: %w", err)
	}
	if err := checkTrustedInfo(path, info, owner, false); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxKeysFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read control key file: %w", err)
	}
	if len(data) > maxKeysFileSize {
		return nil, fmt.Errorf("control key file exceeds %d bytes", maxKeysFileSize)
	}
	var keys []ed25519.PublicKey
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(text)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("control key file line %d is not a base64 Ed25519 public key", line)
		}
		if len(keys) == maxKeys {
			return nil, fmt.Errorf("control key file holds more than %d keys", maxKeys)
		}
		keys = append(keys, ed25519.PublicKey(raw))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read control key file: %w", err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: %s holds no keys", ErrNoKeys, path)
	}
	return keys, nil
}

func checkTrustedPath(path string, owner uint32, dir bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("control key path unavailable: %w", err)
	}
	return checkTrustedInfo(path, info, owner, dir)
}

func checkTrustedInfo(path string, info os.FileInfo, owner uint32, dir bool) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("control key path %s is a symlink", path)
	}
	if dir && !info.IsDir() {
		return fmt.Errorf("control key directory %s is not a directory", path)
	}
	if !dir && !info.Mode().IsRegular() {
		return fmt.Errorf("control key file %s is not a regular file", path)
	}
	if info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("control key path %s is writable by group or others", path)
	}
	uid, ok := fileOwner(info)
	if !ok {
		return fmt.Errorf("control key path %s: ownership cannot be verified on this platform", path)
	}
	if uid != owner {
		return fmt.Errorf("control key path %s is owned by uid %d, want %d", path, uid, owner)
	}
	return nil
}

// GenerateKeyPair writes a new private key (0600) and public key (0644) into
// dir. Existing files are never overwritten.
func GenerateKeyPair(dir string) (privPath, pubPath string, pub ed25519.PublicKey, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", nil, fmt.Errorf("generate Ed25519 key: %w", err)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", "", nil, err
	}
	privPath = filepath.Join(dir, PrivateKeyFile)
	pubPath = filepath.Join(dir, PublicKeyFile)
	if err := writeNew(privPath, base64.StdEncoding.EncodeToString(priv.Seed())+"\n", 0600); err != nil {
		return "", "", nil, err
	}
	if err := writeNew(pubPath, base64.StdEncoding.EncodeToString(pub)+"\n", 0644); err != nil {
		return "", "", nil, err
	}
	return privPath, pubPath, pub, nil
}

func writeNew(path, content string, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// LoadPrivateKey reads a key written by GenerateKeyPair. It refuses a key
// file readable or writable by group or others.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	f, err := openNoFollow(path)
	if err != nil {
		return nil, fmt.Errorf("open private key: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("private key is not a regular file")
	}
	if privateKeyModeCheck && info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("private key %s must not be accessible by group or others (mode %04o)", path, info.Mode().Perm())
	}
	data, err := io.ReadAll(io.LimitReader(f, 1024))
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("private key file is not a base64 Ed25519 seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
